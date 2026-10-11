//! The paired on/off harness (D52; docs/design/gpu-cotenancy.md): it measures what fleet work under test costs one
//! protected process, as `R = progress(fleet on) / progress(fleet off)`, and decides whether "no slowdown" is shown
//! at the owner's margin. It runs in the agent, as a mode of the controller: each tick it says which arm the work
//! under test is in, and the controller pauses that work (OFF) or lets it run (ON) on top of everything protection
//! does anyway.
//!
//! A run is blocks of one ON and one OFF window in random order (a coin per block), each window starting with a
//! washout that is discarded. A block is excluded, symmetrically, and repeated when an outside cause differed:
//! a `during` phase of the rule was on, the protected process restarted (its group changed), the node slept (a gap
//! in the ticks), the power source changed, the memory guard acted, the rule went inactive, or the source could
//! not be read. Thermal throttling is not a cause: if fleet work heats the machine, that slowdown counts.
//!
//! A pilot of three blocks estimates the between-block spread; a run that cannot reach the margin within its cap
//! is refused. After each block an always-valid test may stop the run early (a slowdown at once; "no slowdown"
//! only when the fixed analysis agrees). In an ON window, harm over twice the rule's target aborts the run as a
//! slowdown.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::abstats::{self, Analysis, Decision, SplitMix};
use crate::sources::Progress;

/// Which fleet work a run (or a certificate) is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkSelector {
    /// Every GPU job (and, from 2.10's workloads on, GPU workloads).
    Gpu,
    /// Every job that does not use the GPU.
    Cpu,
    All,
    /// One module's work.
    Module(String),
    /// One unit of one module: a workload (`<module>/<workload>`).
    Unit(String, String),
}

impl WorkSelector {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "gpu" => Some(Self::Gpu),
            "cpu" => Some(Self::Cpu),
            "all" => Some(Self::All),
            "" => None,
            _ => match s.split_once('/') {
                Some((m, n)) if !m.is_empty() && !n.is_empty() => Some(Self::Unit(m.into(), n.into())),
                Some(_) => None,
                None => Some(Self::Module(s.into())),
            },
        }
    }

    pub fn as_string(&self) -> String {
        match self {
            Self::Gpu => "gpu".into(),
            Self::Cpu => "cpu".into(),
            Self::All => "all".into(),
            Self::Module(m) => m.clone(),
            Self::Unit(m, n) => format!("{m}/{n}"),
        }
    }

    /// Whether a unit of fleet work is selected: its module, its name (a job's stage, a workload's name) and
    /// whether it uses the GPU.
    pub fn matches(&self, module: &str, name: &str, gpu: bool) -> bool {
        match self {
            Self::Gpu => gpu,
            Self::Cpu => !gpu,
            Self::All => true,
            Self::Module(m) => m == module,
            Self::Unit(m, n) => m == module && n == name,
        }
    }

    /// Whether the selection may include GPU work.
    pub fn includes_gpu(&self) -> bool {
        !matches!(self, Self::Cpu)
    }
}

/// How the work under test is OFF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OffMode {
    /// Paused the way protection pauses it (cooperative pause or freeze; work that can do neither is released).
    Paused,
    /// Stopped (released), so the memory it held is free too.
    Evicted,
}

/// A run as the coordinator asks for it (the `ab_run` directive).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbSpec {
    pub run_id: String,
    pub rule: String,
    pub work: String,
    /// The `gpu_duty` the GPU work under test gets in its control document during ON windows (None: none).
    #[serde(default)]
    pub duty: Option<f64>,
    #[serde(default = "d_blocks")]
    pub blocks: u32,
    #[serde(default = "d_window")]
    pub window_s: f64,
    #[serde(default = "d_washout")]
    pub washout_s: f64,
    #[serde(default = "d_margin")]
    pub margin: f64,
    #[serde(default = "d_off")]
    pub off: OffMode,
    #[serde(default = "d_pilot")]
    pub pilot_blocks: u32,
    #[serde(default = "d_max_hours")]
    pub max_hours: f64,
    #[serde(default)]
    pub seed: u64,
}

fn d_blocks() -> u32 {
    12
}
fn d_window() -> f64 {
    300.0
}
fn d_washout() -> f64 {
    60.0
}
fn d_margin() -> f64 {
    0.02
}
fn d_off() -> OffMode {
    OffMode::Paused
}
fn d_pilot() -> u32 {
    3
}
fn d_max_hours() -> f64 {
    8.0
}

impl AbSpec {
    /// Why this spec cannot run (None: it can).
    pub fn invalid(&self) -> Option<String> {
        if WorkSelector::parse(&self.work).is_none() {
            return Some(format!("work {:?}: gpu | cpu | all | <module> | <module>/<workload>", self.work));
        }
        if !(self.window_s >= 30.0 && self.washout_s >= 0.0 && self.washout_s < self.window_s) {
            return Some("window_s must be at least 30 and washout_s below it".into());
        }
        if !(self.margin > 0.0 && self.margin < 0.5) {
            return Some("margin must be in (0, 0.5)".into());
        }
        if self.blocks < 2 || self.blocks > 1000 || self.pilot_blocks < 2 {
            return Some("blocks must be 2..1000 and pilot_blocks at least 2".into());
        }
        if self.duty.is_some_and(|d| !(d > 0.0 && d <= 1.0)) {
            return Some("duty must be in (0, 1]".into());
        }
        if !(self.max_hours > 0.0 && self.max_hours <= 72.0) {
            return Some("max_hours must be in (0, 72]".into());
        }
        None
    }

    pub fn block_s(&self) -> f64 {
        2.0 * self.window_s
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arm {
    On,
    Off,
}

/// One completed block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockResult {
    pub on_first: bool,
    pub on_rate: f64,
    pub off_rate: f64,
    pub start: f64,
    pub end: f64,
}

impl BlockResult {
    pub fn log_ratio(&self) -> f64 {
        (self.on_rate / self.off_rate).ln()
    }
}

/// A block left out, and why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Excluded {
    pub start: f64,
    pub end: f64,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Pilot,
    Running,
    Done,
    Aborted,
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    /// no_slowdown | slowdown | inconclusive | refused | aborted
    pub decision: String,
    pub reason: String,
    pub analysis: Option<Analysis>,
    /// The smallest slowdown the planned blocks detect with 80 % power, from the pilot.
    pub min_detectable: Option<f64>,
    pub ended_at: f64,
}

/// What the harness sees of the node each tick.
#[derive(Debug, Clone, Default)]
pub struct HarnessTick {
    pub now: f64,
    /// The rule's progress since the last tick (None: unreadable, or the first read).
    pub progress: Option<Progress>,
    pub rule_active: bool,
    /// A fingerprint of the rule's protected group (its processes' pids and start times).
    pub group: u64,
    /// A `during` phase of the rule is on.
    pub phase_on: bool,
    /// The memory guard is clear.
    pub guard_clear: bool,
    pub on_battery: bool,
    /// The rule's relative target (`max_slowdown`), for the abort guard.
    pub target: Option<f64>,
}

#[derive(Debug, Clone)]
struct Window {
    arm: Arm,
    start: f64,
    events: f64,
    seconds: f64,
}

#[derive(Debug, Clone)]
struct Current {
    on_first: bool,
    start: f64,
    window: Window,
    first_rate: Option<f64>,
    group: u64,
    on_battery: bool,
    dirty: Option<String>,
}

/// The longest gap between ticks before the node counts as having slept.
pub const SLEEP_GAP_S: f64 = 10.0;
/// In an ON window, the measured time before the abort guard may judge.
pub const GUARD_MIN_S: f64 = 60.0;

/// One run's state machine.
#[derive(Debug, Clone)]
pub struct Harness {
    pub spec: AbSpec,
    pub work: WorkSelector,
    pub state: RunState,
    pub blocks: Vec<BlockResult>,
    pub excluded: Vec<Excluded>,
    pub outcome: Option<Outcome>,
    pub started_at: f64,
    /// Blocks the run aims for (the planned count, raised after the pilot when power needs more).
    pub target_blocks: u32,
    min_detectable: Option<f64>,
    cur: Option<Current>,
    last_tick: Option<f64>,
    rng: SplitMix,
}

impl Harness {
    pub fn new(spec: AbSpec, now: f64) -> Result<Self, String> {
        if let Some(e) = spec.invalid() {
            return Err(e);
        }
        let work = WorkSelector::parse(&spec.work).expect("checked");
        let rng = SplitMix(spec.seed ^ 0x6F61_7262_616E_6B21);
        Ok(Self {
            target_blocks: spec.blocks,
            spec,
            work,
            state: RunState::Pilot,
            blocks: vec![],
            excluded: vec![],
            outcome: None,
            started_at: now,
            min_detectable: None,
            cur: None,
            last_tick: None,
            rng,
        })
    }

    pub fn finished(&self) -> bool {
        matches!(self.state, RunState::Done | RunState::Aborted)
    }

    /// The arm the work under test is in now (OFF also before the first tick and after the run: None).
    pub fn arm(&self) -> Option<Arm> {
        if self.finished() {
            return None;
        }
        self.cur.as_ref().map(|c| c.window.arm)
    }

    /// The coordinator aborted the run.
    pub fn abort(&mut self, now: f64, reason: &str) {
        if !self.finished() {
            self.finish(now, "aborted", reason, None);
            self.state = RunState::Aborted;
        }
    }

    fn finish(&mut self, now: f64, decision: &str, reason: &str, analysis: Option<Analysis>) {
        self.state = RunState::Done;
        self.cur = None;
        self.outcome = Some(Outcome {
            decision: decision.into(),
            reason: reason.into(),
            analysis,
            min_detectable: self.min_detectable,
            ended_at: now,
        });
    }

    fn log_ratios(&self) -> Vec<f64> {
        self.blocks.iter().map(BlockResult::log_ratio).collect()
    }

    fn analysis(&self) -> Analysis {
        abstats::analyse(&self.log_ratios(), self.spec.margin, self.spec.seed)
    }

    fn new_block(&mut self, now: f64, t: &HarnessTick) {
        let on_first = self.rng.coin();
        self.cur = Some(Current {
            on_first,
            start: now,
            window: Window { arm: if on_first { Arm::On } else { Arm::Off }, start: now, events: 0.0, seconds: 0.0 },
            first_rate: None,
            group: t.group,
            on_battery: t.on_battery,
            dirty: None,
        });
    }

    /// The mean OFF rate so far (the abort guard's baseline): this block's OFF window when it came first, else the
    /// completed blocks'.
    fn baseline(&self) -> Option<f64> {
        let c = self.cur.as_ref()?;
        if !c.on_first {
            if let Some(r) = c.first_rate {
                return Some(r);
            }
        }
        (!self.blocks.is_empty()).then(|| abstats::mean(&self.blocks.iter().map(|b| b.off_rate).collect::<Vec<_>>()))
    }

    /// One tick. Returns the arm the work under test must be in until the next tick (None: the run is over).
    pub fn tick(&mut self, t: &HarnessTick) -> Option<Arm> {
        if self.finished() {
            return None;
        }
        let now = t.now;
        let slept = self.last_tick.is_some_and(|l| now - l > SLEEP_GAP_S);
        self.last_tick = Some(now);
        if now - self.started_at > self.spec.max_hours * 3600.0 {
            let a = self.analysis();
            let d = a.decision.as_str().to_string();
            self.finish(now, &d, "the run reached its time cap", Some(a));
            return None;
        }
        if self.cur.is_none() {
            self.new_block(now, t);
            return self.arm();
        }
        // an outside cause makes this block not count
        let cause = {
            let c = self.cur.as_ref().expect("set");
            if slept {
                Some("the node slept (a gap in the agent's ticks)")
            } else if !t.rule_active {
                Some("the protected rule went inactive")
            } else if t.group != c.group {
                Some("the protected process restarted")
            } else if t.phase_on {
                Some("a during phase of the rule was on")
            } else if !t.guard_clear {
                Some("the memory guard acted")
            } else if t.on_battery != c.on_battery {
                Some("the power source changed")
            } else {
                None
            }
        };
        if let (Some(why), Some(c)) = (cause, self.cur.as_mut()) {
            c.dirty.get_or_insert_with(|| why.to_string());
        }
        let (washout, window_s) = (self.spec.washout_s, self.spec.window_s);
        let c = self.cur.as_mut().expect("set");
        let in_measure = now - c.window.start > washout;
        if in_measure {
            match t.progress {
                Some(p) => {
                    // only the part of the interval after the washout counts
                    let s = p.seconds.min(now - c.window.start - washout);
                    if p.seconds > 0.0 {
                        c.window.events += p.events * s / p.seconds;
                    }
                    c.window.seconds += s;
                }
                None => {
                    c.dirty.get_or_insert_with(|| "the progress source could not be read".to_string());
                }
            }
        }
        // the abort guard: a collapse of the protected metric in an ON window
        if c.window.arm == Arm::On && c.window.seconds >= GUARD_MIN_S.min(window_s - washout) {
            let rate = c.window.events / c.window.seconds;
            let target = t.target.unwrap_or(self.spec.margin);
            if let Some(b) = self.baseline().filter(|b| *b > 0.0) {
                let harm = 1.0 - rate / b;
                if harm > 2.0 * target {
                    let a = (self.blocks.len() >= 2).then(|| self.analysis());
                    self.finish(
                        now,
                        "slowdown",
                        &format!("guard: the protected process lost {:.0} % in an ON window (target {:.0} %)",
                                 harm * 100.0, target * 100.0),
                        a,
                    );
                    return None;
                }
            }
        }
        let c = self.cur.as_mut().expect("set");
        if now - c.window.start < window_s {
            return Some(c.window.arm);
        }
        // the window is over
        let rate = if c.window.seconds > 0.0 { Some(c.window.events / c.window.seconds) } else { None };
        if c.first_rate.is_none() {
            c.first_rate = Some(rate.unwrap_or(f64::NAN));
            let other = if c.window.arm == Arm::On { Arm::Off } else { Arm::On };
            c.window = Window { arm: other, start: now, events: 0.0, seconds: 0.0 };
            return Some(other);
        }
        let first = c.first_rate.unwrap_or(f64::NAN);
        let second = rate.unwrap_or(f64::NAN);
        let (on, off) = if c.on_first { (first, second) } else { (second, first) };
        let (start, on_first, dirty) = (c.start, c.on_first, c.dirty.clone());
        self.cur = None;
        let reason = dirty.or_else(|| {
            (!(on.is_finite() && off.is_finite())).then(|| "a window had no measured time".to_string())
        }).or_else(|| (off <= 0.0).then(|| "no progress in the OFF window".to_string()))
            .or_else(|| (on <= 0.0).then(|| "no progress in the ON window".to_string()));
        if let Some(r) = reason {
            // "no progress while ON" is harm, not an outside cause
            if r == "no progress in the ON window" && off > 0.0 {
                self.blocks.push(BlockResult { on_first, on_rate: off * 1e-3, off_rate: off, start, end: now });
            } else {
                self.excluded.push(Excluded { start, end: now, reason: r });
                if self.excluded.len() as u32 > 3 * self.target_blocks.max(self.spec.pilot_blocks) {
                    self.finish(now, "aborted", "too many blocks were excluded", None);
                    self.state = RunState::Aborted;
                    return None;
                }
            }
        } else {
            self.blocks.push(BlockResult { on_first, on_rate: on, off_rate: off, start, end: now });
        }
        self.after_block(now, t)
    }

    fn after_block(&mut self, now: f64, t: &HarnessTick) -> Option<Arm> {
        let n = self.blocks.len() as u32;
        if self.state == RunState::Pilot && n >= self.spec.pilot_blocks {
            let sd = abstats::sd(&self.log_ratios());
            self.min_detectable = Some(abstats::min_detectable(sd, self.spec.blocks));
            let need = abstats::blocks_needed(sd, self.spec.margin) as u32;
            let cap = (self.spec.max_hours * 3600.0 / self.spec.block_s()).floor() as u32;
            if need > cap {
                let a = self.analysis();
                self.finish(
                    now,
                    "refused",
                    &format!("the pilot's spread needs {need} blocks to reach the {:.0} % margin, more than the {cap} \
                              that fit in {} h", self.spec.margin * 100.0, self.spec.max_hours),
                    Some(a),
                );
                return None;
            }
            self.target_blocks = self.spec.blocks.max(need).min(cap.max(n));
            self.state = RunState::Running;
        }
        if n >= 3 {
            match abstats::sequential(&self.log_ratios(), self.spec.margin) {
                Some(Decision::Slowdown) => {
                    let a = self.analysis();
                    self.finish(now, "slowdown", "the sequential test stopped the run early", Some(a));
                    return None;
                }
                Some(Decision::NoSlowdown) => {
                    let a = self.analysis();
                    if a.decision == Decision::NoSlowdown && self.state == RunState::Running {
                        self.finish(now, "no_slowdown", "the sequential test stopped the run early", Some(a));
                        return None;
                    }
                }
                _ => {}
            }
        }
        if self.state == RunState::Running && n >= self.target_blocks {
            let a = self.analysis();
            let (d, r) = (a.decision.as_str().to_string(), a.reason.clone());
            self.finish(now, &d, &r, Some(a));
            return None;
        }
        self.new_block(now, t);
        self.arm()
    }

    /// The heartbeat's view of the run.
    pub fn report(&self, now: f64) -> Value {
        let cur = self.cur.as_ref().map(|c| {
            json!({"arm": c.window.arm, "window_elapsed_s": (now - c.window.start).max(0.0).round(),
                   "on_first": c.on_first, "excluded_reason": c.dirty})
        });
        json!({
            "run_id": self.spec.run_id, "rule": self.spec.rule, "work": self.spec.work, "duty": self.spec.duty,
            "state": self.state, "started_at": self.started_at, "target_blocks": self.target_blocks,
            "blocks": self.blocks, "excluded": self.excluded, "current": cur, "outcome": self.outcome,
            "margin": self.spec.margin, "window_s": self.spec.window_s, "washout_s": self.spec.washout_s,
            "off": self.spec.off,
        })
    }
}
