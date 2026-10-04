//! Node protection config, schema 1. Owner-set only: the central copy arrives in the node policy's
//! `protection` section, the local copy is `protection.json` in the agent's config directory, and the two
//! are unioned so that the stricter setting always wins. There is no field that could name a protected
//! process as the target of an action (S16 made structural).

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::OnceLock;

use fancy_regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::json::{bool_of, f64_of, get, int_of, is_null, is_object, num, obj, str_of, strings};
use crate::model::GroupSample;

/// A config the agent refuses (the message names the rule and the problem).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

fn err<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(msg.into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionMode {
    FleetFirst,
    #[default]
    Moderate,
    StrictYield,
}

impl ProtectionMode {
    pub const ALL: [ProtectionMode; 3] = [Self::FleetFirst, Self::Moderate, Self::StrictYield];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FleetFirst => "fleet_first",
            Self::Moderate => "moderate",
            Self::StrictYield => "strict_yield",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.as_str() == s)
    }

    /// Strictness order used by the union: the stricter mode wins.
    fn rank(self) -> u8 {
        match self {
            Self::FleetFirst => 0,
            Self::Moderate => 1,
            Self::StrictYield => 2,
        }
    }
}

impl fmt::Display for ProtectionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionScope {
    All,
    Cpu,
    Gpu,
    Io,
}

impl ProtectionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
            Self::Io => "io",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::All, Self::Cpu, Self::Gpu, Self::Io]
            .into_iter()
            .find(|x| x.as_str() == s)
    }
}

/// `{"scope": ...}` actions: an object without a known scope means `all`; anything else is absent.
fn scope_action(v: Option<&Value>) -> Option<ProtectionScope> {
    let v = v?;
    str_of(get(Some(v), "scope"))
        .and_then(ProtectionScope::parse)
        .or(if v.is_object() {
            Some(ProtectionScope::All)
        } else {
            None
        })
}

/// Present and not null (`lower_fleet` carries no settings the agent reads).
fn present(v: Option<&Value>) -> bool {
    v.is_some() && !is_null(v)
}

#[derive(Debug, Clone, PartialEq)]
pub struct MemoryFloors {
    /// Calibrated on 6,946 recorded samples (2026-09-28..30): the design's 20/10 % stopped admission on a
    /// 64 GB Mac in 34 % of samples without any memory pressure, so the defaults are 12 % soft and 8 % hard.
    pub soft_free_pct: f64,
    pub hard_free_pct: f64,
    pub swap_growth_soft_mb_min: f64,
    pub swap_growth_hard_mb_min: f64,
    pub min_reclaim_gb: f64,
}

impl Default for MemoryFloors {
    fn default() -> Self {
        Self {
            soft_free_pct: 12.0,
            hard_free_pct: 8.0,
            swap_growth_soft_mb_min: 256.0,
            swap_growth_hard_mb_min: 1024.0,
            min_reclaim_gb: 2.0,
        }
    }
}

impl MemoryFloors {
    pub fn from_json(j: Option<&Value>) -> Self {
        let mut m = Self::default();
        if !is_object(j) {
            return m;
        }
        if let Some(v) = f64_of(get(j, "soft_free_pct")) {
            m.soft_free_pct = v;
        }
        if let Some(v) = f64_of(get(j, "hard_free_pct")) {
            m.hard_free_pct = v;
        }
        if let Some(v) = f64_of(get(j, "swap_growth_soft_mb_min")) {
            m.swap_growth_soft_mb_min = v;
        }
        if let Some(v) = f64_of(get(j, "swap_growth_hard_mb_min")) {
            m.swap_growth_hard_mb_min = v;
        }
        if let Some(v) = f64_of(get(j, "min_reclaim_gb")) {
            m.min_reclaim_gb = v;
        }
        m
    }

    /// Stricter on every field: higher free-% floors, lower swap-growth thresholds, larger reclaim.
    pub fn union(&self, o: &MemoryFloors) -> MemoryFloors {
        MemoryFloors {
            soft_free_pct: self.soft_free_pct.max(o.soft_free_pct),
            hard_free_pct: self.hard_free_pct.max(o.hard_free_pct),
            swap_growth_soft_mb_min: self.swap_growth_soft_mb_min.min(o.swap_growth_soft_mb_min),
            swap_growth_hard_mb_min: self.swap_growth_hard_mb_min.min(o.swap_growth_hard_mb_min),
            min_reclaim_gb: self.min_reclaim_gb.max(o.min_reclaim_gb),
        }
    }

    pub fn to_json(&self) -> Value {
        Value::Object(obj([
            ("soft_free_pct", num(self.soft_free_pct)),
            ("hard_free_pct", num(self.hard_free_pct)),
            ("swap_growth_soft_mb_min", num(self.swap_growth_soft_mb_min)),
            ("swap_growth_hard_mb_min", num(self.swap_growth_hard_mb_min)),
            ("min_reclaim_gb", num(self.min_reclaim_gb)),
        ]))
    }
}

/// The match keys of a rule; every given key must hold. An empty string or list counts as absent, as in the
/// console's preview matcher (`protection_match.py`) and the coordinator's schema.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessMatch {
    pub requirement: Option<String>,
    pub team_id: Option<String>,
    pub identifier: Option<String>,
    pub bundle_ids: Vec<String>,
    pub path_prefix: Option<String>,
    pub path_contains: Option<String>,
    pub argv_regex: Option<String>,
    pub name: Option<String>,
}

fn nonempty(v: Option<&Value>) -> Option<String> {
    str_of(v).filter(|s| !s.is_empty()).map(str::to_string)
}

impl ProcessMatch {
    /// Parse without validation (the match-vector tests and the preview use this).
    pub fn from_json_unchecked(json: &Value) -> Self {
        let j = Some(json);
        let bundle_ids = match get(j, "bundle_id") {
            Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect(),
            _ => vec![],
        };
        ProcessMatch {
            requirement: nonempty(get(j, "requirement")),
            team_id: nonempty(get(j, "team_id")),
            identifier: nonempty(get(j, "identifier")),
            bundle_ids,
            path_prefix: nonempty(get(j, "path_prefix")),
            path_contains: nonempty(get(j, "path_contains")),
            argv_regex: nonempty(get(j, "argv_regex")),
            name: nonempty(get(j, "name")),
        }
    }

    pub fn from_json(json: &Value) -> Result<Self, ConfigError> {
        let m = Self::from_json_unchecked(json);
        if let Some(r) = &m.argv_regex {
            if Regex::new(r).is_err() {
                return err(format!("match.argv_regex does not compile: {r}"));
            }
        }
        if m.is_empty() {
            return err("match needs at least one key");
        }
        Ok(m)
    }

    pub fn is_empty(&self) -> bool {
        self.requirement.is_none()
            && self.team_id.is_none()
            && self.identifier.is_none()
            && self.bundle_ids.is_empty()
            && self.path_prefix.is_none()
            && self.path_contains.is_none()
            && self.argv_regex.is_none()
            && self.name.is_none()
    }

    /// Whether matching needs the (lazily resolved, more expensive) code-signing identity or argv.
    pub fn needs_signing(&self) -> bool {
        self.requirement.is_some() || self.team_id.is_some() || self.identifier.is_some()
    }

    pub fn needs_argv(&self) -> bool {
        self.argv_regex.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TreeScope {
    #[default]
    SelfOnly,
    Descendants,
    SameTeam,
}

impl TreeScope {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "self" => Some(Self::SelfOnly),
            "descendants" => Some(Self::Descendants),
            "same_team" => Some(Self::SameTeam),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfOnly => "self",
            Self::Descendants => "descendants",
            Self::SameTeam => "same_team",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActiveWhen {
    /// "present": any matched process is running.
    pub present: bool,
    pub cpu_cores_gt: Option<f64>,
    pub footprint_gb_gt: Option<f64>,
    /// true: the frontmost app is one of the group's processes; false: the group runs but is not in front.
    /// An unknown frontmost app satisfies either.
    pub frontmost: Option<bool>,
    /// `gpu_active = { min_busy = x }`: the group's processes kept the GPU busy for at least this share of the
    /// last sample interval (GPU busy seconds per second, summed over the group and the GPU's engines). Usage
    /// that cannot be read satisfies it.
    pub gpu_min_busy: Option<f64>,
    pub for_s: Option<f64>,
}

/// `gpu_active = {}` holds at 5 % GPU busy.
pub const DEFAULT_GPU_MIN_BUSY: f64 = 0.05;

impl Default for ActiveWhen {
    fn default() -> Self {
        Self {
            present: true,
            cpu_cores_gt: None,
            footprint_gb_gt: None,
            frontmost: None,
            gpu_min_busy: None,
            for_s: None,
        }
    }
}

/// `active_when.gpu_active`: absent, or a table whose `min_busy` is in (0, 1].
fn gpu_min_busy(id: &str, v: Option<&Value>) -> Result<Option<f64>, ConfigError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(g @ Value::Object(_)) => {
            let m = match get(Some(g), "min_busy") {
                None => DEFAULT_GPU_MIN_BUSY,
                Some(x) => match x.as_f64() {
                    Some(m) if m > 0.0 && m <= 1.0 => m,
                    _ => {
                        return err(format!(
                            "rule {id}: active_when.gpu_active.min_busy must be a number in (0, 1]"
                        ))
                    }
                },
            };
            Ok(Some(m))
        }
        Some(_) => err(format!(
            "rule {id}: active_when.gpu_active must be a table such as {{ min_busy = 0.05 }}"
        )),
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CapFleet {
    pub slots: Option<i64>,
    pub cpu_cores: Option<f64>,
    pub threads: Option<i64>,
    pub staging_mbps: Option<f64>,
    pub gpu_jobs: Option<i64>,
    /// While the rule is active, only jobs that reserve these pools may start, up to the given tokens.
    pub pools: BTreeMap<String, i64>,
}

impl CapFleet {
    fn from_json(c: Option<&Value>, with_pools: bool) -> Self {
        let mut cf = CapFleet {
            slots: int_of(get(c, "slots")),
            cpu_cores: f64_of(get(c, "cpu_cores")),
            threads: int_of(get(c, "threads")),
            staging_mbps: f64_of(get(c, "staging_mbps")),
            gpu_jobs: int_of(get(c, "gpu_jobs")),
            pools: BTreeMap::new(),
        };
        if with_pools {
            if let Some(p) = get(c, "pools").and_then(|p| p.as_object()) {
                for (k, v) in p {
                    if let Some(n) = int_of(Some(v)) {
                        cf.pools.insert(k.clone(), n.max(0));
                    }
                }
            }
        }
        cf
    }
}

/// A measured metric of the protected group kept within a target (the feedback loop).
#[derive(Debug, Clone, PartialEq)]
pub struct ProtectSpec {
    pub metric: String,
    /// Absolute ceiling on the metric (cpu_stall, pageins_rate, gpu_share), or
    pub max: Option<f64>,
    /// a relative slowdown against the paused-fleet baseline (progress_rate, ipc_ratio).
    pub max_slowdown: Option<f64>,
    pub window_s: f64,
    /// The owner's progress source (`jsonl`, `log_regex` + `path`, or `exec`).
    pub source_json: Option<Value>,
}

impl ProtectSpec {
    pub fn new(metric: &str, max: Option<f64>, max_slowdown: Option<f64>) -> Self {
        Self {
            metric: metric.to_string(),
            max,
            max_slowdown,
            window_s: 20.0,
            source_json: None,
        }
    }
}

/// Extra actions while an owner-supplied source says a phase is on (e.g. no staging during an upload).
#[derive(Debug, Clone, PartialEq)]
pub struct DuringSpec {
    pub source_json: Value,
    pub cap_fleet: Option<CapFleet>,
    pub pause_fleet: Option<ProtectionScope>,
    pub lower_fleet: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProtectionRule {
    pub id: String,
    pub match_: ProcessMatch,
    pub tree: TreeScope,
    pub active_when: ActiveWhen,
    pub ignore: bool,
    pub reserve_cpu: Option<ReserveExpr>,
    pub reserve_mem_gb: Option<ReserveExpr>,
    pub cap_fleet: Option<CapFleet>,
    pub lower_fleet: bool,
    pub pause_fleet: Option<ProtectionScope>,
    pub evict: Option<ProtectionScope>,
    pub protect: Option<ProtectSpec>,
    pub during: Vec<DuringSpec>,
    pub enter_for_s: Option<f64>,
    pub exit_after_s: Option<f64>,
}

impl ProtectionRule {
    /// A rule with no actions (callers set the ones they need).
    pub fn new(id: &str, match_: ProcessMatch) -> Self {
        Self {
            id: id.to_string(),
            match_,
            tree: TreeScope::SelfOnly,
            active_when: ActiveWhen::default(),
            ignore: false,
            reserve_cpu: None,
            reserve_mem_gb: None,
            cap_fleet: None,
            lower_fleet: false,
            pause_fleet: None,
            evict: None,
            protect: None,
            during: vec![],
            enter_for_s: None,
            exit_after_s: None,
        }
    }

    pub fn protect_metric(&self) -> Option<&str> {
        self.protect.as_ref().map(|p| p.metric.as_str())
    }

    pub fn from_json(json: &Value) -> Result<Self, ConfigError> {
        let j = Some(json);
        let id = match str_of(get(j, "id")) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return err("rule without an id"),
        };
        let Some(m) = get(j, "match") else {
            return err(format!("rule {id}: no match"));
        };
        let mut r = ProtectionRule::new(&id, ProcessMatch::from_json(m)?);
        if let Some(t) = str_of(get(j, "tree")) {
            match TreeScope::parse(t) {
                Some(ts) => r.tree = ts,
                None => return err(format!("rule {id}: unknown tree {t}")),
            }
        }
        if let Some(aw) = get(j, "active_when") {
            if aw.as_str() == Some("present") {
                r.active_when = ActiveWhen::default();
            } else if aw.is_object() {
                let a = Some(aw);
                r.active_when = ActiveWhen {
                    present: false,
                    cpu_cores_gt: f64_of(get(a, "cpu_cores_gt")),
                    footprint_gb_gt: f64_of(get(a, "footprint_gb_gt")),
                    frontmost: bool_of(get(a, "frontmost")),
                    gpu_min_busy: gpu_min_busy(&id, get(a, "gpu_active"))?,
                    for_s: f64_of(get(a, "for_s")),
                };
                let w = &mut r.active_when;
                if w.cpu_cores_gt.is_none()
                    && w.footprint_gb_gt.is_none()
                    && w.frontmost.is_none()
                    && w.gpu_min_busy.is_none()
                {
                    w.present = true;
                }
            }
        }
        r.ignore = bool_of(get(j, "ignore")).unwrap_or(false);
        let reserve = get(j, "reserve");
        if is_object(reserve) {
            r.reserve_cpu = ReserveExpr::from_json(get(reserve, "cpu"))?;
            r.reserve_mem_gb = ReserveExpr::from_json(get(reserve, "mem_gb"))?;
        }
        let cap = get(j, "cap_fleet");
        if is_object(cap) {
            r.cap_fleet = Some(CapFleet::from_json(cap, true));
        }
        r.lower_fleet = present(get(j, "lower_fleet"));
        r.pause_fleet = scope_action(get(j, "pause_fleet"));
        r.evict = scope_action(get(j, "evict"));
        let pj = get(j, "protect");
        if is_object(pj) {
            if let Some(metric) = str_of(get(pj, "metric")) {
                let ps = ProtectSpec {
                    metric: metric.to_string(),
                    max: f64_of(get(pj, "max")),
                    max_slowdown: f64_of(get(pj, "max_slowdown")),
                    window_s: f64_of(get(pj, "window_s")).unwrap_or(20.0),
                    source_json: get(pj, "source").cloned(),
                };
                if ps.max.is_none() == ps.max_slowdown.is_none() {
                    return err(format!(
                        "rule {id}: protect needs exactly one of max / max_slowdown"
                    ));
                }
                r.protect = Some(ps);
            }
        }
        let during = get(j, "during").and_then(|d| d.as_array());
        for d in during.into_iter().flatten() {
            let ds = Some(d);
            let src = get(ds, "source");
            if !is_object(src) {
                return err(format!("rule {id}: during needs a source"));
            }
            let dc = get(ds, "cap_fleet");
            r.during.push(DuringSpec {
                source_json: src.cloned().unwrap_or(Value::Null),
                cap_fleet: is_object(dc).then(|| CapFleet::from_json(dc, false)),
                pause_fleet: scope_action(get(ds, "pause_fleet")),
                lower_fleet: present(get(ds, "lower_fleet")),
            });
        }
        r.enter_for_s = f64_of(get(j, "enter_for_s"));
        r.exit_after_s = f64_of(get(j, "exit_after_s"));
        let has_action = r.reserve_cpu.is_some()
            || r.reserve_mem_gb.is_some()
            || r.cap_fleet.is_some()
            || r.lower_fleet
            || r.pause_fleet.is_some()
            || r.evict.is_some()
            || r.protect.is_some();
        if r.ignore && has_action {
            return err(format!("rule {id}: ignore cannot be combined with actions"));
        }
        if !r.ignore && !has_action && during.is_none_or(|d| d.is_empty()) {
            return err(format!("rule {id}: needs an action or ignore"));
        }
        if r.tree == TreeScope::SameTeam
            && r.match_.team_id.is_none()
            && r.match_.requirement.is_none()
        {
            return err(format!(
                "rule {id}: tree = same_team needs a team_id or requirement matcher"
            ));
        }
        Ok(r)
    }
}

/// The bounds of `[node] max_pause_s` (spec/runner-protocol.md: a pause lasts at most 10 minutes).
pub const MAX_PAUSE_S: f64 = 600.0;
pub const MIN_PAUSE_S: f64 = 10.0;

#[derive(Debug, Clone, PartialEq)]
pub struct ProtectionConfig {
    pub mode: ProtectionMode,
    pub pause: bool,
    pub memory: MemoryFloors,
    pub enter_for_s: f64,
    pub exit_after_s: f64,
    /// Resume cooldown for rules that hold admission back: base × backoff^(earlier activations in the
    /// window), capped (by default 120, 240, ... 3840 s).
    pub cooldown_base_s: f64,
    pub cooldown_backoff: f64,
    pub cooldown_max_s: f64,
    pub cooldown_window_s: f64,
    /// GPU fleet jobs: never | when_no_gpu_protected | always.
    pub gpu_jobs: String,
    /// moderate / strict_yield only: protect the frontmost app while the user is present, and a generic owner
    /// CPU stall signal over every unmatched owner process.
    pub implicit_frontmost: bool,
    pub owner_stall_max: Option<f64>,
    /// The longest a fleet job stays paused before it is released (checkpointed first when its runner can): at most
    /// 600 s; an owner may set less (`[node] max_pause_s`, 10 to 600).
    pub max_pause_s: f64,
    pub rules: Vec<ProtectionRule>,
    /// Where each part came from ("central", "local"), for the status page.
    pub sources: Vec<String>,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            mode: ProtectionMode::Moderate,
            pause: false,
            memory: MemoryFloors::default(),
            enter_for_s: 4.0,
            exit_after_s: 60.0,
            cooldown_base_s: 120.0,
            cooldown_backoff: 2.0,
            cooldown_max_s: 3840.0,
            cooldown_window_s: 3600.0,
            gpu_jobs: "when_no_gpu_protected".to_string(),
            implicit_frontmost: true,
            owner_stall_max: Some(0.15),
            max_pause_s: MAX_PAUSE_S,
            rules: vec![],
            sources: vec![],
        }
    }
}

impl ProtectionConfig {
    pub fn new(mode: ProtectionMode, rules: Vec<ProtectionRule>) -> Self {
        Self {
            mode,
            rules,
            ..Self::default()
        }
    }

    /// Parse a schema-1 document (JSON form of the TOML: `{"schema": 1, "node": {...}, "rule": [...]}`).
    pub fn from_json(json: &Value, source: &str) -> Result<Self, ConfigError> {
        let j = Some(json);
        let mut c = Self::default();
        if let Some(s) = int_of(get(j, "schema")) {
            if s != 1 {
                return err(format!("protection schema {s} is not supported (1)"));
            }
        }
        let node = get(j, "node");
        if let Some(m) = str_of(get(node, "mode")) {
            match ProtectionMode::parse(m) {
                Some(mode) => c.mode = mode,
                None => return err(format!("unknown protection mode {m}")),
            }
        }
        c.pause = bool_of(get(node, "pause")).unwrap_or(false);
        if let Some(g) = str_of(get(node, "gpu_jobs")) {
            c.gpu_jobs = g.to_string();
        }
        let im = get(node, "implicit");
        if is_object(im) {
            c.implicit_frontmost = bool_of(get(im, "frontmost_app")).unwrap_or(true);
            if let Some(os) = get(im, "owner_stall") {
                c.owner_stall_max = if os.is_null() {
                    None
                } else {
                    Some(f64_of(get(Some(os), "max")).unwrap_or(0.15))
                };
            }
        }
        if let Some(v) = f64_of(get(node, "max_pause_s")) {
            if !(MIN_PAUSE_S..=MAX_PAUSE_S).contains(&v) {
                return err(format!("node.max_pause_s {v} is outside {MIN_PAUSE_S}..{MAX_PAUSE_S}"));
            }
            c.max_pause_s = v;
        }
        c.memory = MemoryFloors::from_json(get(node, "memory"));
        let d = get(node, "defaults");
        if let Some(v) = f64_of(get(d, "enter_for_s")) {
            c.enter_for_s = v;
        }
        if let Some(v) = f64_of(get(d, "exit_after_s")) {
            c.exit_after_s = v;
        }
        let cd = get(d, "cooldown");
        if is_object(cd) {
            if let Some(v) = f64_of(get(cd, "base_s")) {
                c.cooldown_base_s = v;
            }
            if let Some(v) = f64_of(get(cd, "backoff")) {
                c.cooldown_backoff = v.max(1.0);
            }
            if let Some(v) = f64_of(get(cd, "max_s")) {
                c.cooldown_max_s = v;
            }
            if let Some(v) = f64_of(get(cd, "window_s")) {
                c.cooldown_window_s = v;
            }
        }
        // "rule" (the TOML array-of-tables name) wins over "rules" whenever it is present
        let raw = get(j, "rule")
            .or_else(|| get(j, "rules"))
            .and_then(|r| r.as_array());
        c.rules = raw
            .into_iter()
            .flatten()
            .map(ProtectionRule::from_json)
            .collect::<Result<_, _>>()?;
        let mut seen = HashSet::new();
        for r in &c.rules {
            if !seen.insert(r.id.as_str()) {
                return err(format!("duplicate rule id {}", r.id));
            }
        }
        c.sources = vec![source.to_string()];
        Ok(c)
    }

    /// Union: stricter mode, stricter floors, local brake if either sets it, shorter enter and longer exit
    /// timing, and both rule lists (a rule id present in both keeps both, the second one suffixed `@local`).
    pub fn union(&self, o: &ProtectionConfig) -> ProtectionConfig {
        let gpu_rank = |s: &str| match s {
            "always" => 0,
            "when_no_gpu_protected" => 1,
            "never" => 2,
            _ => 1,
        };
        let ids: HashSet<&str> = self.rules.iter().map(|r| r.id.as_str()).collect();
        let mut rules = self.rules.clone();
        rules.extend(o.rules.iter().map(|r| {
            let mut r = r.clone();
            if ids.contains(r.id.as_str()) {
                r.id.push_str("@local");
            }
            r
        }));
        ProtectionConfig {
            mode: if o.mode.rank() > self.mode.rank() {
                o.mode
            } else {
                self.mode
            },
            pause: self.pause || o.pause,
            memory: self.memory.union(&o.memory),
            enter_for_s: self.enter_for_s.min(o.enter_for_s),
            exit_after_s: self.exit_after_s.max(o.exit_after_s),
            cooldown_base_s: self.cooldown_base_s.max(o.cooldown_base_s),
            cooldown_backoff: self.cooldown_backoff.max(o.cooldown_backoff),
            cooldown_max_s: self.cooldown_max_s.max(o.cooldown_max_s),
            cooldown_window_s: self.cooldown_window_s.max(o.cooldown_window_s),
            gpu_jobs: if gpu_rank(&o.gpu_jobs) > gpu_rank(&self.gpu_jobs) {
                o.gpu_jobs.clone()
            } else {
                self.gpu_jobs.clone()
            },
            implicit_frontmost: self.implicit_frontmost || o.implicit_frontmost,
            owner_stall_max: match (self.owner_stall_max, o.owner_stall_max) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
            max_pause_s: self.max_pause_s.min(o.max_pause_s),
            rules,
            sources: self.sources.iter().chain(&o.sources).cloned().collect(),
        }
    }

    /// The status page's view of the config.
    pub fn summary(&self) -> Value {
        let ids: Vec<String> = self.rules.iter().map(|r| r.id.clone()).collect();
        Value::Object(obj([
            ("mode", Value::from(self.mode.as_str())),
            ("pause", Value::from(self.pause)),
            ("memory", self.memory.to_json()),
            ("rules", strings(&ids)),
            ("sources", strings(&self.sources)),
        ]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveMetric {
    Cpu,
    Footprint,
}

/// A reservation: a constant, or `peak(<N>s).cpu|footprint [* k] [+ c]` over the matched group's samples.
#[derive(Debug, Clone, PartialEq)]
pub struct ReserveExpr {
    pub constant: Option<f64>,
    pub metric: Option<ReserveMetric>,
    pub window_s: f64,
    pub factor: f64,
    pub add: f64,
}

fn peak_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^peak\(([0-9]+)s\)\.(cpu|footprint)(\*([0-9]+(?:\.[0-9]+)?))?(\+([0-9]+(?:\.[0-9]+)?))?$")
            .expect("static regex")
    })
}

impl ReserveExpr {
    pub fn constant(c: f64) -> Self {
        Self {
            constant: Some(c),
            metric: None,
            window_s: 0.0,
            factor: 1.0,
            add: 0.0,
        }
    }

    pub fn peak(metric: ReserveMetric, window_s: f64, factor: f64, add: f64) -> Self {
        Self {
            constant: None,
            metric: Some(metric),
            window_s,
            factor,
            add,
        }
    }

    /// null: no reservation; a number: a constant; a string: an expression.
    pub fn from_json(v: Option<&Value>) -> Result<Option<Self>, ConfigError> {
        match v {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Number(n)) => Ok(n.as_f64().map(Self::constant)),
            Some(Value::String(s)) => Self::parse(s).map(Some),
            Some(_) => err("reservation must be a number or an expression"),
        }
    }

    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let t = s.replace(' ', "");
        if let Ok(d) = t.parse::<f64>() {
            return Ok(Self::constant(d));
        }
        let caps = peak_re().captures(&t).ok().flatten();
        let Some(m) = caps else {
            return err(format!(
                "reservation {s}: use a number or peak(<N>s).cpu|footprint [* k] [+ c]"
            ));
        };
        let g = |i: usize| m.get(i).map(|x| x.as_str());
        let window_s = g(1).and_then(|x| x.parse().ok()).unwrap_or(0.0);
        let metric = if g(2) == Some("cpu") {
            ReserveMetric::Cpu
        } else {
            ReserveMetric::Footprint
        };
        let factor = g(4).and_then(|x| x.parse().ok()).unwrap_or(1.0);
        let add = g(6).and_then(|x| x.parse().ok()).unwrap_or(0.0);
        Ok(Self::peak(metric, window_s, factor, add))
    }

    /// Evaluate against the group's history: the peak over the window (samples with t >= now - window).
    pub fn evaluate(&self, history: &[GroupSample], now: f64) -> f64 {
        if let Some(c) = self.constant {
            return c.max(0.0);
        }
        let Some(metric) = self.metric else {
            return 0.0;
        };
        let peak = history
            .iter()
            .filter(|s| now - s.t <= self.window_s + 1e-9)
            .map(|s| {
                if metric == ReserveMetric::Cpu {
                    s.cpu_cores
                } else {
                    s.footprint_gb
                }
            })
            .fold(None, |acc: Option<f64>, x| {
                Some(acc.map_or(x, |a| a.max(x)))
            })
            .unwrap_or(0.0);
        (peak * self.factor + self.add).max(0.0)
    }
}
