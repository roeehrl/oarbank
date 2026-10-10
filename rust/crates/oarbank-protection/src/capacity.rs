//! The generic capacity engine: how many fleet jobs a node may run once user caps, thermal state,
//! user presence, running services and host protection's combined constraint are applied. It knows no
//! service, VM or co-tenant by name. Also the owner's caps (`limits`), the capacity-relevant node policy, and
//! hard-cap enforcement.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Serialize, Serializer};
use serde_json::Value;

use crate::evaluator::CombinedConstraint;
use crate::json::{
    bool_of, f64_of, get, int_of, is_null, opt_int, opt_num, opt_str, rounded, str_of,
};
use crate::memory_guard::Thermal;

/// `limits.enforce`: soft only stops admitting; hard also releases attempts until the node is within its caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Enforce {
    #[default]
    Soft,
    Hard,
}

/// `{"days": [0..6], "start": "22:00", "end": "07:30"}` in local time. Days follow Python's
/// `datetime.weekday()` (0 = Monday … 6 = Sunday). An overnight window (start > end) belongs to the day it
/// starts on; start == end means the whole day; missing or empty `days` means every day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    pub days: Option<BTreeSet<u32>>,
    pub start_minute: u32,
    pub end_minute: u32,
}

impl Schedule {
    pub fn new(days: Option<&[u32]>, start_minute: u32, end_minute: u32) -> Self {
        Self {
            days: days.map(|d| d.iter().copied().collect()),
            start_minute,
            end_minute,
        }
    }

    pub fn from_json(j: &Value) -> Option<Self> {
        if !j.is_object() {
            return None;
        }
        let j = Some(j);
        let start = str_of(get(j, "start")).and_then(Self::parse_hhmm)?;
        let end = str_of(get(j, "end")).and_then(Self::parse_hhmm)?;
        let days = get(j, "days")
            .filter(|d| !d.is_null())
            .and_then(|d| d.as_array())
            .and_then(|arr| {
                let ds: BTreeSet<u32> = arr
                    .iter()
                    .filter_map(|x| int_of(Some(x)))
                    .filter(|d| (0..=6).contains(d))
                    .map(|d| d as u32)
                    .collect();
                (!ds.is_empty()).then_some(ds)
            });
        Some(Self {
            days,
            start_minute: start,
            end_minute: end,
        })
    }

    /// "HH:MM" or "HH:MM:SS" -> minutes (24:00 allowed as the end of the day).
    pub fn parse_hhmm(s: &str) -> Option<u32> {
        let parts: Vec<&str> = s
            .trim_matches(|c: char| c == ' ' || c == '\t')
            .split(':')
            .filter(|p| !p.is_empty())
            .collect();
        if parts.len() != 2 && parts.len() != 3 {
            return None;
        }
        let h: i64 = parts[0].parse().ok()?;
        let m: i64 = parts[1].parse().ok()?;
        if !(0..=24).contains(&h) || !(0..=59).contains(&m) {
            return None;
        }
        if h == 24 {
            return (m == 0).then_some(24 * 60);
        }
        Some((h * 60 + m) as u32)
    }

    pub fn to_json(&self) -> Value {
        let fmt = |m: u32| format!("{:02}:{:02}", m / 60, m % 60);
        serde_json::json!({
            "days": self.days.as_ref().map(|d| d.iter().copied().collect::<Vec<_>>()),
            "start": fmt(self.start_minute), "end": fmt(self.end_minute),
        })
    }

    /// 0 = Monday … 6 = Sunday, for a time already shifted into the local zone.
    pub fn monday_zero_weekday(local_unix_s: i64) -> u32 {
        // 1970-01-01 was a Thursday (3)
        (local_unix_s.div_euclid(86400) + 3).rem_euclid(7) as u32
    }

    /// Is a local time inside the window? `utc_offset_s` shifts the Unix time into the local zone.
    pub fn contains_unix(&self, unix_s: i64, utc_offset_s: i64) -> bool {
        let local = unix_s + utc_offset_s;
        let minute = (local.rem_euclid(86400) / 60) as u32;
        self.contains(Self::monday_zero_weekday(local), minute)
    }

    /// Is `minute` of local weekday `weekday` (0 = Monday) inside the window?
    pub fn contains(&self, weekday: u32, minute: u32) -> bool {
        let today = weekday;
        let yesterday = (today + 6) % 7;
        let day_ok = |d: u32| self.days.as_ref().is_none_or(|ds| ds.contains(&d));
        let start = self.start_minute % (24 * 60);
        let end = if self.end_minute == 24 * 60 {
            24 * 60
        } else {
            self.end_minute % (24 * 60)
        };
        if start == end || (start == 0 && end == 24 * 60) {
            return day_ok(today);
        }
        if start < end {
            return day_ok(today) && minute >= start && minute < end;
        }
        // overnight window
        if minute >= start {
            return day_ok(today);
        }
        if minute < end {
            return day_ok(yesterday);
        }
        false
    }
}

/// The owner's caps. Missing or null = uncapped.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Limits {
    pub cpu_cores: Option<f64>,
    pub mem_gb: Option<f64>,
    pub jobs: Option<i64>,
    pub vm_mem_gb: Option<f64>,
    pub vm_cpus: Option<i64>,
    pub disk_gb: Option<f64>,
    pub staging_mbps: Option<f64>,
    pub schedule: Option<Schedule>,
    pub enforce: Enforce,
}

fn non_null(v: Option<&Value>) -> Option<&Value> {
    v.filter(|v| !v.is_null())
}

impl Limits {
    pub fn uncapped() -> Self {
        Self::default()
    }

    /// Parse the directive's `limits`; an unparseable schedule is ignored (uncapped), not fatal.
    pub fn from_json(j: Option<&Value>) -> Self {
        let mut l = Self::default();
        if !j.is_some_and(Value::is_object) {
            return l;
        }
        let floor = |v: Option<f64>| v.map(|x| x.floor() as i64);
        l.cpu_cores = f64_of(non_null(get(j, "cpu_cores")));
        l.mem_gb = f64_of(non_null(get(j, "mem_gb")));
        l.jobs = floor(f64_of(non_null(get(j, "jobs"))));
        l.vm_mem_gb = f64_of(non_null(get(j, "vm_mem_gb")));
        l.vm_cpus = floor(f64_of(non_null(get(j, "vm_cpus"))));
        l.disk_gb = f64_of(non_null(get(j, "disk_gb")));
        l.staging_mbps = f64_of(non_null(get(j, "staging_mbps")));
        l.schedule = non_null(get(j, "schedule")).and_then(Schedule::from_json);
        l.enforce = if str_of(get(j, "enforce")) == Some("hard") {
            Enforce::Hard
        } else {
            Enforce::Soft
        };
        l
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "cpu_cores": opt_num(self.cpu_cores), "mem_gb": opt_num(self.mem_gb), "jobs": opt_int(self.jobs),
            "vm_mem_gb": opt_num(self.vm_mem_gb), "vm_cpus": opt_int(self.vm_cpus), "disk_gb": opt_num(self.disk_gb),
            "staging_mbps": opt_num(self.staging_mbps),
            "schedule": self.schedule.as_ref().map_or(Value::Null, Schedule::to_json),
            "enforce": if self.enforce == Enforce::Hard { "hard" } else { "soft" },
        })
    }
}

/// The capacity- and protection-relevant part of the coordinator-set node policy (the agent's full policy
/// also carries services and module settings).
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub os_reserve_gb: f64,
    pub user_reserve_gb: f64,
    pub max_slots: Option<i64>,
    pub threads_per_job: i64,
    pub job_mem_gb: f64,
    pub user_present_slots: i64,
    pub user_idle_s: f64,
    pub run_on_battery: bool,
    pub nice: i64,
    /// A remote screen-sharing session counts as someone using the machine, even without input (macOS).
    pub screen_sharing_present: bool,
    /// The host budget never exceeds what is available now (the in-use bound); off: the reserves alone decide.
    pub mem_in_use_bound: bool,
    /// The central protection section (unioned with the local file).
    pub protection: Option<Value>,
}

/// The registry's defaults (generated: `settings_table`), what a node runs with before its first heartbeat.
impl Default for Policy {
    fn default() -> Self {
        use crate::settings_table as T;
        Self {
            os_reserve_gb: T::OS_RESERVE_GB,
            user_reserve_gb: T::USER_RESERVE_GB,
            max_slots: T::MAX_SLOTS,
            threads_per_job: T::THREADS_PER_JOB,
            job_mem_gb: T::JOB_MEM_GB,
            user_present_slots: T::USER_PRESENT_SLOTS,
            user_idle_s: T::USER_IDLE_S,
            run_on_battery: T::RUN_ON_BATTERY,
            nice: T::NICE,
            screen_sharing_present: T::SCREEN_SHARING_PRESENT,
            mem_in_use_bound: T::MEM_IN_USE_BOUND,
            protection: None,
        }
    }
}

impl Policy {
    /// Read a policy section the agent already checked against the settings table (`settings::validate`): every key
    /// is present and well-typed there; `base` only fills what a caller's partial section leaves out (tests).
    pub fn from_json(j: Option<&Value>, base: &Policy) -> Self {
        let mut p = base.clone();
        if !j.is_some_and(Value::is_object) {
            return p;
        }
        let d = |k: &str| f64_of(non_null(get(j, k)));
        let i = |k: &str| d(k).map(|x| x.floor() as i64);
        if let Some(v) = d("os_reserve_gb") {
            p.os_reserve_gb = v;
        }
        if let Some(v) = d("user_reserve_gb") {
            p.user_reserve_gb = v;
        }
        if let Some(raw) = get(j, "max_slots") {
            p.max_slots = if raw.is_null() {
                None
            } else {
                raw.as_f64().map(|x| x.floor() as i64)
            };
        }
        if let Some(v) = i("threads_per_job") {
            p.threads_per_job = v.max(1);
        }
        if let Some(v) = d("job_mem_gb").filter(|v| *v > 0.0) {
            p.job_mem_gb = v;
        }
        if let Some(v) = i("user_present_slots") {
            p.user_present_slots = v.max(0);
        }
        if let Some(v) = d("user_idle_s") {
            p.user_idle_s = v;
        }
        if let Some(v) = bool_of(get(j, "run_on_battery")) {
            p.run_on_battery = v;
        }
        if let Some(v) = i("nice") {
            p.nice = v.clamp(0, 20);
        }
        if let Some(v) = bool_of(get(j, "screen_sharing_present")) {
            p.screen_sharing_present = v;
        }
        if let Some(v) = bool_of(get(j, "mem_in_use_bound")) {
            p.mem_in_use_bound = v;
        }
        let prot = get(j, "protection");
        if !is_null(prot) && prot.is_some_and(Value::is_object) {
            p.protection = prot.cloned();
        }
        p
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CapacityInputs {
    pub ram_gb: f64,
    pub perf_cores: i64,
    pub eff_cores: i64,
    pub policy: Policy,
    pub limits: Limits,
    /// Host memory charged by running services (`reserves_host_memory`), GB.
    pub service_reserved_mem_gb: f64,
    /// Pool tokens the node's healthy, enabled services provide.
    pub service_pools: BTreeMap<String, i64>,
    /// Rules, the memory guard and the thermal and battery gates, combined (most restrictive wins).
    pub constraint: CombinedConstraint,
    pub user_present: bool,
    pub thermal: i32,
    pub desired_state: String,
    pub local_pause: bool,
    pub in_schedule: bool,
    /// Summed RSS of the agent's own job process groups.
    pub fleet_rss_gb: f64,
    /// Memory the OS could hand to new work now, GB: RAM minus what the host signals count as used (macOS:
    /// app + wired + compressed, so free, file cache, purgeable and speculative pages count as available; Linux:
    /// MemAvailable; Windows: ullAvailPhys, free plus standby). None: not measured (no in-use bound).
    pub available_gb: Option<f64>,
    /// The part of the fleet jobs' reservations already resident: Σ min(footprint, resources.mem_gb), GB. It is in
    /// use (so not in `available_gb`) but already charged to the budget through `used_mem_gb`.
    pub fleet_resident_gb: f64,
    /// Kept free under the in-use bound: the memory guard's soft floor plus 1 GB (`CapacityModel::mem_margin_gb`), so
    /// admitting up to the budget never trips the guard.
    pub mem_margin_gb: f64,
    pub live_attempts: i64,
    /// Σ spec.resources.cpu / mem_gb of live attempts.
    pub used_cpu: f64,
    pub used_mem_gb: f64,
}

impl CapacityInputs {
    pub fn new(
        ram_gb: f64,
        perf_cores: i64,
        eff_cores: i64,
        policy: Policy,
        limits: Limits,
    ) -> Self {
        Self {
            ram_gb,
            perf_cores,
            eff_cores,
            policy,
            limits,
            service_reserved_mem_gb: 0.0,
            service_pools: BTreeMap::new(),
            constraint: CombinedConstraint::default(),
            user_present: false,
            thermal: 0,
            desired_state: "active".into(),
            local_pause: false,
            in_schedule: true,
            fleet_rss_gb: 0.0,
            available_gb: None,
            fleet_resident_gb: 0.0,
            mem_margin_gb: CapacityModel::mem_margin_gb(ram_gb, 12.0),
            live_attempts: 0,
            used_cpu: 0.0,
            used_mem_gb: 0.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CapacityResult {
    /// CPUs available to fleet jobs after caps, thermal, user presence and protection.
    pub cpu_slots: i64,
    /// CPUs before user caps and protection ceilings (thermal and user presence applied).
    pub auto_cpu_slots: i64,
    /// Host memory budget for new jobs: host_budget − Σ running spec.resources.mem_gb.
    pub mem_gb_free: f64,
    pub pools: BTreeMap<String, i64>,
    /// cpu_slots − Σ running spec.resources.cpu (0 once cap.jobs is reached).
    pub free_cpu: f64,
    /// Job slots: min(cpu slots, memory slots, cap.jobs, cap.cpu_cores / threads, protection slots).
    pub slots: i64,
    pub auto_slots: i64,
    pub free_slots: i64,
    pub binding_limit: String,
    pub admit: bool,
    pub host_budget_gb: f64,
    pub mem_slots: i64,
    pub not_admitting_because: Option<String>,
    /// A rule allows only jobs that reserve these pools (up to the tokens), nothing else.
    pub pool_jobs_only: bool,
    pub reserved_cpu: f64,
    pub reserved_mem_gb: f64,
    /// GPU fleet jobs allowed now (None: no limit; 0 while a protected group is GPU-active).
    pub gpu_jobs: Option<i64>,
    /// Which bound set the host budget: `reserve` (RAM minus the reserves), `in_use` (what is actually available
    /// plus the fleet's own resident memory, minus the margin) or `cap` (the owner's `mem_gb` cap).
    pub mem_binding: String,
    /// The reserve bound: ram − os_reserve − services − protection reservations − (user present: user_reserve).
    pub mem_budget_reserve_gb: f64,
    /// The in-use bound: available + fleet resident − margin (None when available memory is not measured).
    pub mem_budget_in_use_gb: Option<f64>,
    /// Memory in use by everything but the fleet's jobs (the owner's apps, the system, services), GB.
    pub mem_in_use_gb: Option<f64>,
    pub mem_margin_gb: f64,
    pub user_present: bool,
    /// The automatic CPU slots with nobody present (thermal and max_slots applied).
    pub idle_cpu_slots: i64,
}

impl CapacityResult {
    /// The heartbeat's `capacity` object.
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "cpu_slots": self.cpu_slots, "auto_cpu_slots": self.auto_cpu_slots,
            "mem_gb_free": rounded(self.mem_gb_free, 2), "pools": self.pools, "slots": self.slots,
            "auto_slots": self.auto_slots, "binding_limit": self.binding_limit, "admit": self.admit,
            "pool_jobs_only": self.pool_jobs_only, "reserved_cpu": rounded(self.reserved_cpu, 2),
            "reserved_mem_gb": rounded(self.reserved_mem_gb, 2), "why": opt_str(self.not_admitting_because.as_deref()),
            "gpu_jobs": opt_int(self.gpu_jobs), "host_budget_gb": rounded(self.host_budget_gb, 2),
            "mem_binding": self.mem_binding, "mem_budget_reserve_gb": rounded(self.mem_budget_reserve_gb, 2),
            "mem_budget_in_use_gb": self.mem_budget_in_use_gb.map_or(Value::Null, |v| rounded(v, 2)),
            "mem_in_use_gb": self.mem_in_use_gb.map_or(Value::Null, |v| rounded(v, 2)),
            "mem_margin_gb": rounded(self.mem_margin_gb, 2), "user_present": self.user_present,
            "idle_cpu_slots": self.idle_cpu_slots,
        })
    }
}

impl Serialize for CapacityResult {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(s)
    }
}

pub struct CapacityModel;

fn floor_int(x: f64) -> i64 {
    if !x.is_finite() {
        return if x > 0.0 { i64::MAX } else { 0 };
    }
    x.floor().max(0.0) as i64
}

impl CapacityModel {
    /// The margin the in-use bound keeps free: the memory guard's soft floor (`soft_free_pct` of RAM) plus 1 GB.
    pub fn mem_margin_gb(ram_gb: f64, soft_free_pct: f64) -> f64 {
        ram_gb.max(0.0) * soft_free_pct.max(0.0) / 100.0 + 1.0
    }

    /// ```text
    /// reserve     = ram − os_reserve − services_reserved − protection.reserved_mem − (user ? user_reserve : 0)
    /// in_use      = available + fleet_resident − margin          (available measured, policy mem_in_use_bound;
    ///                                                             margin = the guard's soft floor + 1 GB)
    /// host_budget = min(reserve, in_use, cap.mem_gb − services_reserved)        (mem_binding names the smallest)
    /// cpu         = perf + eff/2 − protection.reserved_cpu; ×0.75 at thermal fair, 0 at serious+;
    ///               ≤ user_present_slots while a user is present
    /// auto_cpu    = min(max_slots, cpu)
    /// cpu_slots   = min(auto_cpu, cap.cpu_cores, protection.cpu_cores)
    /// slots       = min(auto_cpu, floor(host_budget / job_mem), cap.jobs, cap.cpu_cores / threads, protection.slots)
    /// pools       = the services' tokens (only the rule's pool tokens while a rule allows pool jobs only)
    /// admit       = active, no local pause, in schedule, no protection brake (rule, memory floor, thermal,
    ///               battery), protection slots ≠ 0, and fleet RSS + services ≤ cap.mem_gb
    /// ```
    pub fn compute(i: &CapacityInputs) -> CapacityResult {
        let p = &i.policy;
        let l = &i.limits;
        let c = &i.constraint;
        let svc = i.service_reserved_mem_gb.max(0.0);
        let reserve_budget = i.ram_gb
            - p.os_reserve_gb
            - svc
            - c.reserved_mem_gb
            - if i.user_present {
                p.user_reserve_gb
            } else {
                0.0
            };
        // never more than the machine has free now, plus what the fleet's own jobs already hold of their reservations
        let in_use_budget = i
            .available_gb
            .filter(|a| a.is_finite() && p.mem_in_use_bound)
            .map(|a| a.max(0.0) + i.fleet_resident_gb.max(0.0) - i.mem_margin_gb.max(0.0));
        let mut uncapped_budget = reserve_budget;
        let mut mem_binding = "reserve";
        if let Some(u) = in_use_budget.filter(|u| *u < reserve_budget) {
            uncapped_budget = u;
            mem_binding = "in_use";
        }
        let mut host_budget = uncapped_budget;
        let mut mem_capped = false;
        if let Some(cap_mem) = l.mem_gb {
            if cap_mem - svc < host_budget {
                host_budget = cap_mem - svc;
                mem_capped = true;
                mem_binding = "cap";
            }
        }

        let base_cpu = i.perf_cores as f64 + i.eff_cores as f64 / 2.0;
        let mut cpu = (base_cpu - c.reserved_cpu.max(0.0)).max(0.0);
        let mut thermal_reduced = false;
        if i.thermal >= Thermal::SERIOUS {
            cpu = 0.0;
            thermal_reduced = true;
        } else if i.thermal == Thermal::FAIR {
            cpu *= 0.75;
            thermal_reduced = true;
        }
        let mut cpu_whole = floor_int(cpu);
        let idle_cpu_whole = cpu_whole;
        if i.user_present {
            cpu_whole = cpu_whole.min(p.user_present_slots.max(0));
        }

        let job_mem = p.job_mem_gb.max(0.01);
        let mem_slots = floor_int(host_budget / job_mem);
        let uncapped_mem_slots = floor_int(uncapped_budget / job_mem);
        let max_slots = p.max_slots.map_or(i64::MAX, |m| m.max(0));
        let auto_slots = max_slots.min(cpu_whole).min(mem_slots).max(0);
        let jobs_cap = l.jobs.map_or(i64::MAX, |j| j.max(0));
        let cpu_cap_jobs = l.cpu_cores.map_or(i64::MAX, |cc| {
            floor_int(cc / p.threads_per_job.max(1) as f64)
        });
        let rule_slots = c.slots.unwrap_or(i64::MAX);
        let slots = auto_slots
            .min(jobs_cap)
            .min(cpu_cap_jobs)
            .min(rule_slots)
            .max(0);

        let auto_cpu_slots = max_slots.min(cpu_whole).max(0);
        let cpu_cores_cap = l.cpu_cores.map_or(i64::MAX, floor_int);
        let rule_cpu = c.cpu_cores.map_or(i64::MAX, floor_int);
        let capped_cpu = auto_cpu_slots.min(cpu_cores_cap).min(rule_cpu);
        let cpu_slots = if c.slots == Some(0) { 0 } else { capped_cpu };
        let mem_gb_free = (host_budget - i.used_mem_gb).max(0.0);
        let free_cpu = if i.live_attempts >= jobs_cap {
            0.0
        } else {
            (cpu_slots as f64 - i.used_cpu).max(0.0)
        };

        let bind = |k: &str| {
            c.binding
                .get(k)
                .cloned()
                .unwrap_or_else(|| "protection".into())
        };
        let mut pools = i.service_pools.clone();
        let mut binding = "auto".to_string();
        if capped_cpu < auto_cpu_slots {
            binding = if rule_cpu < cpu_cores_cap {
                bind("cpu_cores")
            } else {
                "cap.cpu_cores".into()
            };
        } else if jobs_cap < capped_cpu {
            binding = "cap.jobs".into();
        } else if rule_slots < capped_cpu {
            binding = bind("slots");
        } else if mem_capped && mem_slots < capped_cpu && uncapped_mem_slots > mem_slots {
            binding = "cap.mem_gb".into();
        } else if c.reserved_mem_gb > 0.0 && mem_slots < capped_cpu {
            binding = bind("reserve_mem");
        } else if mem_binding == "in_use" && mem_slots < capped_cpu {
            binding = "memory_in_use".into();
        } else if c.reserved_cpu > 0.0
            && floor_int(base_cpu) > auto_cpu_slots
            && !thermal_reduced
            && !i.user_present
        {
            binding = bind("reserve_cpu");
        } else if thermal_reduced
            && !i.user_present
            && cpu_whole == auto_cpu_slots
            && floor_int(base_cpu) > cpu_whole
        {
            binding = "thermal".into();
        }

        let mut admit = true;
        let mut because: Option<String> = None;
        let mem_cap_exceeded = l.mem_gb.is_some_and(|m| i.fleet_rss_gb + svc > m);
        if i.desired_state != "active" {
            admit = false;
            because = Some(format!("desired_state={}", i.desired_state));
            binding = "user".into();
        } else if i.local_pause {
            admit = false;
            because = Some("local_pause".into());
            binding = "user".into();
        } else if !i.in_schedule {
            admit = false;
            because = Some("outside_schedule".into());
            binding = "user".into();
        } else if c.no_admit {
            admit = false;
            binding = bind("admit");
            because = Some(binding.clone());
        } else if c.slots == Some(0) || c.pool_jobs_only.is_some() {
            admit = false;
            binding = c
                .binding
                .get("slots")
                .or_else(|| c.binding.get("pool_jobs_only"))
                .cloned()
                .unwrap_or_else(|| "protection".into());
            because = Some(binding.clone());
        } else if mem_cap_exceeded {
            admit = false;
            because = Some("cap.mem_gb exceeded".into());
            binding = "cap.mem_gb".into();
        }
        // a rule that lets pool jobs through (e.g. short score stages) while holding everything else back
        let pool_only = !admit
            && c.pool_jobs_only.is_some()
            && because.as_deref() == c.binding.get("pool_jobs_only").map(String::as_str)
            && !(i.desired_state != "active" || i.local_pause || !i.in_schedule || c.no_admit);
        if let (Some(allow), true) = (&c.pool_jobs_only, pool_only) {
            pools = pools
                .into_iter()
                .map(|(k, v)| (k.clone(), v.min(allow.get(&k).copied().unwrap_or(0))))
                .collect();
        }
        CapacityResult {
            cpu_slots,
            auto_cpu_slots,
            mem_gb_free,
            pools,
            free_cpu,
            slots,
            auto_slots,
            free_slots: (slots - i.live_attempts).max(0),
            binding_limit: binding,
            admit,
            host_budget_gb: host_budget,
            mem_slots,
            not_admitting_because: because,
            pool_jobs_only: pool_only,
            reserved_cpu: c.reserved_cpu,
            reserved_mem_gb: c.reserved_mem_gb,
            gpu_jobs: c.gpu_jobs,
            mem_binding: mem_binding.into(),
            mem_budget_reserve_gb: reserve_budget,
            mem_budget_in_use_gb: in_use_budget,
            mem_in_use_gb: i
                .available_gb
                .filter(|a| a.is_finite())
                .map(|a| (i.ram_gb - a - i.fleet_rss_gb).max(0.0)),
            mem_margin_gb: i.mem_margin_gb,
            user_present: i.user_present,
            idle_cpu_slots: max_slots.min(idle_cpu_whole).max(0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EnforcementAttempt {
    pub attempt_id: i64,
    pub started_at: f64,
    pub rss_gb: f64,
    pub cpu: f64,
}

impl EnforcementAttempt {
    pub fn new(attempt_id: i64, started_at: f64, rss_gb: f64) -> Self {
        Self {
            attempt_id,
            started_at,
            rss_gb,
            cpu: 1.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseDecision {
    pub attempt_id: i64,
    pub reason: String,
}

impl ReleaseDecision {
    pub fn new(attempt_id: i64, reason: &str) -> Self {
        Self {
            attempt_id,
            reason: reason.into(),
        }
    }
}

pub struct Enforcement;

impl Enforcement {
    /// In `enforce: "hard"`, the attempts to release (youngest first) so the node is within its caps. Soft
    /// enforcement never releases (admission alone stops). Reasons: `limit_schedule` outside the schedule
    /// window; `limit_cpu` while Σ resources.cpu exceeds `cap.cpu_cores` or the attempt count exceeds
    /// `cap.jobs`; `limit_mem` while the fleet RSS plus the services' reserved memory exceeds `cap.mem_gb`.
    pub fn hard_releases(
        limits: &Limits,
        attempts: &[EnforcementAttempt],
        fleet_rss_gb: f64,
        service_reserved_mem_gb: f64,
        in_schedule: bool,
    ) -> Vec<ReleaseDecision> {
        if limits.enforce != Enforce::Hard || attempts.is_empty() {
            return vec![];
        }
        let mut remaining: Vec<EnforcementAttempt> = attempts.to_vec();
        remaining.sort_by(|a, b| {
            (b.started_at, b.attempt_id)
                .partial_cmp(&(a.started_at, a.attempt_id))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        if !in_schedule {
            return remaining
                .iter()
                .map(|a| ReleaseDecision::new(a.attempt_id, "limit_schedule"))
                .collect();
        }
        let mut out = vec![];
        let jobs_cap = limits.jobs.map_or(usize::MAX, |j| j.max(0) as usize);
        let cpu_cap = limits.cpu_cores.unwrap_or(f64::INFINITY);
        let mut used_cpu: f64 = remaining.iter().map(|a| a.cpu).sum();
        let mut remaining: std::collections::VecDeque<EnforcementAttempt> = remaining.into();
        while !remaining.is_empty() && (remaining.len() > jobs_cap || used_cpu > cpu_cap + 1e-9) {
            let Some(a) = remaining.pop_front() else {
                break;
            };
            used_cpu -= a.cpu;
            out.push(ReleaseDecision::new(a.attempt_id, "limit_cpu"));
        }
        if let Some(cap_mem) = limits.mem_gb {
            let released: f64 = out
                .iter()
                .map(|d: &ReleaseDecision| {
                    attempts
                        .iter()
                        .find(|a| a.attempt_id == d.attempt_id)
                        .map_or(0.0, |a| a.rss_gb)
                })
                .sum();
            let mut usage = fleet_rss_gb - released;
            while usage + service_reserved_mem_gb > cap_mem {
                let Some(a) = remaining.pop_front() else {
                    break;
                };
                out.push(ReleaseDecision::new(a.attempt_id, "limit_mem"));
                usage -= a.rss_gb;
            }
        }
        out
    }
}
