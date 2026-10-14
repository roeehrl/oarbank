//! When the agent runs its container runtime (docs/design/macos-containers.md, "When the runtime runs"): the owner's
//! `containers` setting, `always` (from the first release that needs containers, as before), `on_demand` (only while
//! container work is live here or the coordinator says some waits for this node: `containers_wanted` in its heartbeat
//! reply; stopped again after `containers_idle_stop_s` without either) or `off` (never: the node reports its runtime
//! `disabled` and offers no container pool). A runtime whose VM size no longer matches the owner's `vm_mem_gb` and
//! `vm_cpus` is restarted at the new size once no container job is live.
//!
//! The decisions are here, apart from the runtimes, so they are tested without a VM; the agent carries them out
//! (agent.rs `govern_containers`).

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Always,
    OnDemand,
    Off,
}

impl Mode {
    /// The policy's `containers` (always for anything else: the settings table refuses other values).
    pub fn of(policy: &Value) -> Mode {
        match policy["containers"].as_str() {
            Some("on_demand") => Mode::OnDemand,
            Some("off") => Mode::Off,
            _ => Mode::Always,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Always => "always",
            Mode::OnDemand => "on_demand",
            Mode::Off => "off",
        }
    }
}

/// The policy's `containers_idle_stop_s` (the table's default, 600 s; at least 60 s).
pub fn idle_stop(policy: &Value) -> Duration {
    let s = policy["containers_idle_stop_s"].as_u64().unwrap_or(oarbank_protection::settings_table::CONTAINERS_IDLE_STOP_S as u64);
    Duration::from_secs(s.max(60))
}

/// Whether this platform's runtime is a VM the agent starts and stops (macOS, Windows). Linux runs containers on the
/// host's engine, which the agent neither starts nor stops: `on_demand` is `always` there.
pub const STOPPABLE: bool = cfg!(any(target_os = "macos", windows));

/// What the agent does with its runtime now.
#[derive(Debug, Clone, PartialEq)]
pub enum Do {
    Nothing,
    /// Make the runtime and bring it up (on demand: container work is live or waits).
    Start(String),
    /// Stop the runtime and drop it (idle on demand, or containers turned off).
    Stop(String),
    /// Stop it and make it again at the owner's new VM size.
    Restart(String),
}

/// The agent's decisions about its runtime, and what it measured of it.
#[derive(Debug, Default)]
pub struct Gate {
    pub mode: Mode,
    pub idle_stop: Duration,
    /// The coordinator's last `containers_wanted`.
    pub wanted: bool,
    /// When container work was last live here or wanted: the idle time runs from the later of this and `started`.
    last_use: Option<Instant>,
    /// When the agent last made the runtime, and whether it has seen it ready since.
    started: Option<Instant>,
    ready_seen: bool,
    /// How long its last start took to become ready (s).
    pub start_s: Option<u64>,
    /// Its last start failed: not offered as startable before this.
    pub failed_until: Option<Instant>,
    /// The runtime offered GPU passthrough when it last ran (a stopped one offers `gpu` as startable again).
    pub gpu_seen: bool,
    /// The mismatch (wanted size, size found) the runtime was already restarted for: a VM that keeps its size anyway
    /// (a runtime that cannot resize it) is not restarted again and again.
    resized_for: Option<((f64, u32), (f64, u32))>,
}

/// How long a failed on-demand start keeps the node from offering its runtime as startable.
pub const FAILED_HOLD: Duration = Duration::from_secs(1800);

impl Gate {
    /// Take the policy in force (each directive).
    pub fn configure(&mut self, policy: &Value) {
        if policy["containers"].is_string() || self.idle_stop.is_zero() {
            self.mode = Mode::of(policy);
        }
        if policy["containers_idle_stop_s"].is_u64() || self.idle_stop.is_zero() {
            self.idle_stop = idle_stop(policy);
        }
    }

    /// The mode this agent last ran with (its state file): a restarted agent keeps it until the coordinator answers, so
    /// an on-demand or off node does not start its VM at startup.
    pub fn load(&mut self, home: &Path) {
        if let Some(v) = std::fs::read(mode_file(home)).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
            self.configure(&v);
        }
    }

    /// Keep the mode for the next agent run (when it changed).
    pub fn save(&self, home: &Path) {
        let v = json!({"containers": self.mode.as_str(), "containers_idle_stop_s": self.idle_stop.as_secs()});
        if std::fs::read(mode_file(home)).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).as_ref() != Some(&v) {
            let _ = crate::fsutil::write_private(&mode_file(home), &serde_json::to_vec(&v).unwrap_or_default());
        }
    }

    /// Whether the runtime stays down until work needs it: on demand where the runtime is a VM.
    pub fn parked(&self) -> bool {
        self.mode == Mode::OnDemand && STOPPABLE
    }

    /// The agent made the runtime now.
    pub fn started(&mut self, now: Instant) {
        self.started = Some(now);
        self.ready_seen = false;
        self.last_use = Some(now);
    }

    /// The runtime's state now (its report's `state`): the first `ready` after a start measures the start; a `failed`
    /// on-demand start holds the runtime back from being offered for FAILED_HOLD.
    pub fn observe(&mut self, now: Instant, state: &str, gpu: bool) {
        match state {
            "ready" => {
                if !self.ready_seen {
                    if let Some(t) = self.started {
                        self.start_s = Some(now.saturating_duration_since(t).as_secs().max(1));
                    }
                }
                self.ready_seen = true;
                self.failed_until = None;
                self.gpu_seen = gpu;
            }
            "failed" if self.parked() && self.failed_until.is_none() => self.failed_until = Some(now + FAILED_HOLD),
            _ => {}
        }
    }

    /// What to do now. `up`: the agent holds a runtime (made, starting or running); `live`: container attempts live here;
    /// `size`: the VM size the owner's caps ask for and the size the runtime was made at (or runs at), when they differ.
    pub fn decide(&mut self, now: Instant, up: bool, live: usize, size: Option<((f64, u32), (f64, u32))>) -> Do {
        if live > 0 || (self.wanted && self.mode == Mode::OnDemand) {
            self.last_use = Some(now);
        }
        if !up {
            return match self.mode {
                Mode::OnDemand if live > 0 => Do::Start("a container job is live here".into()),
                Mode::OnDemand if self.wanted && STOPPABLE => Do::Start("container work waits for this node".into()),
                _ => Do::Nothing,
            };
        }
        if self.mode == Mode::Off {
            return if live == 0 { Do::Stop("containers = off on this node".into()) } else { Do::Nothing };
        }
        if live > 0 {
            return Do::Nothing;
        }
        if let Some((want, have)) = size {
            let same = |r: ((f64, u32), (f64, u32))| crate::container_runtime::same_size(r.0, want) && crate::container_runtime::same_size(r.1, have);
            if self.resized_for.is_none_or(|r| !same(r)) {
                self.resized_for = Some((want, have));
                return Do::Restart(format!("the VM runs at {:.1} GB and {} CPUs; the owner's settings ask for {:.1} GB and {} CPUs",
                                           have.0, have.1, want.0, want.1));
            }
        }
        if self.parked() && !self.wanted {
            let since = self.last_use.max(self.started).unwrap_or(now);
            if now.saturating_duration_since(since) >= self.idle_stop {
                return Do::Stop(format!("no container work for {} s (containers = on_demand)", self.idle_stop.as_secs()));
            }
        }
        Do::Nothing
    }

    /// Move the gate's clocks `d` into the past (tests: an idle time passes).
    #[cfg(test)]
    pub fn backdate(&mut self, d: Duration) {
        self.started = self.started.map(|t| t - d);
        self.last_use = self.last_use.map(|t| t - d);
    }

    /// The runtime was stopped (by the gate).
    pub fn stopped(&mut self) {
        self.started = None;
        self.ready_seen = false;
    }

    /// Whether a stopped on-demand runtime may be offered as startable now.
    pub fn startable(&self, now: Instant, prerequisites_ok: bool) -> bool {
        self.parked() && prerequisites_ok && self.failed_until.is_none_or(|t| now >= t)
    }

    /// The heartbeat's `containers`: mode, state, the pools a stopped runtime offers once started, how long a start
    /// takes, the idle time, and the VM size (`vm`, from the runtime's report).
    pub fn report(&self, state: &str, startable: &serde_json::Map<String, Value>, vm: &Value) -> Value {
        let mut r = json!({"mode": self.mode.as_str(), "state": state, "idle_stop_s": self.idle_stop.as_secs(),
                           "start_s": self.start_s.unwrap_or(60), "startable": startable});
        if vm.is_object() {
            r["vm"] = vm.clone();
        }
        r
    }
}

/// The state the heartbeat reports for a runtime the agent holds (its report's `state`): `ready` is `running` there.
pub fn held_state(report_state: &str) -> &str {
    match report_state {
        "ready" | "installed" => "running",
        s => s,
    }
}

/// Where the agent keeps the mode it last ran with.
pub fn mode_file(home: &Path) -> PathBuf {
    home.join("state").join("containers-setting.json")
}

/// The file the facts' `containers` read first: what the agent reports while it holds no runtime by the owner's choice
/// (containers off, or an on-demand runtime stopped). Absent while a runtime runs.
pub fn override_file(home: &Path) -> PathBuf {
    home.join("state").join("containers-mode.json")
}

/// The facts' `containers` for a runtime the agent does not run by the owner's choice: `disabled` (off) or `stopped`
/// (on demand), with what is missing for it to start (`missing`), and its VM size.
pub fn idle_report(runtime: &str, mode: Mode, missing: Vec<Value>, vm: &Value) -> Value {
    let (state, detail) = match mode {
        Mode::Off => ("disabled", "containers = off on this node: the agent does not run a container runtime, and the node takes no container work"),
        _ if !missing.is_empty() => ("missing", "containers = on_demand: the runtime starts when container work waits for this node, once what is missing is installed"),
        _ => ("stopped", "containers = on_demand: the runtime starts when container work waits for this node, and stops again when idle"),
    };
    let mut j = json!({"runtime": runtime, "state": state, "mode": mode.as_str(), "detail": detail, "platforms": [],
                       "gpu": "undetected", "missing": missing});
    if vm.is_object() {
        j["vm"] = vm.clone();
    }
    j
}

/// Write (Some) or remove (None) the facts' override; true when it changed.
pub fn set_override(home: &Path, report: Option<&Value>) -> bool {
    let f = override_file(home);
    let now = std::fs::read(&f).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    match report {
        Some(r) if now.as_ref() != Some(r) => {
            let _ = crate::fsutil::write_private(&f, &serde_json::to_vec_pretty(r).unwrap_or_default());
            true
        }
        None if now.is_some() => {
            let _ = std::fs::remove_file(&f);
            true
        }
        _ => false,
    }
}

/// The override the facts read, when there is one.
pub fn read_override(home: &Path) -> Option<Value> {
    std::fs::read(override_file(home)).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).filter(|v| v.is_object())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(mode: &str, idle_s: u64) -> Gate {
        let mut g = Gate::default();
        g.configure(&json!({"containers": mode, "containers_idle_stop_s": idle_s}));
        g
    }

    /// A directive without the keys keeps what the agent had; the mode survives an agent restart.
    #[test]
    fn the_mode_is_kept_without_the_key_and_across_a_restart() {
        let mut g = gate("off", 120);
        g.configure(&json!({"jobs": 2}));
        assert_eq!((g.mode, g.idle_stop), (Mode::Off, Duration::from_secs(120)));
        let tmp = crate::scratch("gate-mode");
        g.save(tmp.path());
        let mut h = Gate::default();
        h.load(tmp.path());
        assert_eq!((h.mode, h.idle_stop), (Mode::Off, Duration::from_secs(120)));
        let mut fresh = Gate::default();
        fresh.load(&tmp.path().join("none"));
        fresh.configure(&json!({}));
        assert_eq!((fresh.mode, fresh.idle_stop), (Mode::Always, Duration::from_secs(600)));
    }

    #[test]
    fn the_policy_names_the_mode_and_the_idle_time() {
        assert_eq!(Mode::of(&json!({})), Mode::Always);
        assert_eq!(Mode::of(&json!({"containers": "on_demand"})), Mode::OnDemand);
        assert_eq!(Mode::of(&json!({"containers": "off"})), Mode::Off);
        assert_eq!(Mode::of(&json!({"containers": "bogus"})), Mode::Always);
        assert_eq!(idle_stop(&json!({})), Duration::from_secs(600));
        assert_eq!(idle_stop(&json!({"containers_idle_stop_s": 5})), Duration::from_secs(60), "at least a minute");
    }

    /// always: never stopped by the gate, never started by it (the agent makes it when a release needs containers).
    #[test]
    fn always_keeps_the_runtime() {
        let mut g = gate("always", 60);
        let t = Instant::now();
        assert_eq!(g.decide(t, false, 0, None), Do::Nothing);
        g.started(t);
        assert_eq!(g.decide(t + Duration::from_secs(7200), true, 0, None), Do::Nothing);
    }

    /// off: a held runtime stops once no container job is live, and nothing starts it.
    #[test]
    fn off_stops_the_runtime_once_idle_and_never_starts_it() {
        let mut g = gate("off", 60);
        let t = Instant::now();
        assert_eq!(g.decide(t, true, 1, None), Do::Nothing, "a live container job finishes first");
        assert!(matches!(g.decide(t, true, 0, None), Do::Stop(_)));
        g.wanted = true;
        assert_eq!(g.decide(t, false, 0, None), Do::Nothing);
        assert!(!g.startable(t, true));
    }

    /// on_demand (a VM platform): started by waiting work or a live job, kept up while either lasts and for the idle
    /// time after, then stopped; a want that comes back during the idle time keeps it up.
    #[test]
    #[cfg(any(target_os = "macos", windows))]
    fn on_demand_starts_for_work_and_stops_after_the_idle_time() {
        let mut g = gate("on_demand", 600);
        let t = Instant::now();
        let s = |n: u64| t + Duration::from_secs(n);
        assert_eq!(g.decide(t, false, 0, None), Do::Nothing, "nothing waits: stays stopped");
        assert!(g.startable(t, true) && !g.startable(t, false));
        g.wanted = true;
        assert!(matches!(g.decide(t, false, 0, None), Do::Start(_)));
        g.started(t);
        g.observe(s(40), "ready", true);
        assert_eq!(g.start_s, Some(40));
        assert!(g.gpu_seen);
        g.wanted = false;
        assert_eq!(g.decide(s(100), true, 1, None), Do::Nothing, "a job runs");
        assert_eq!(g.decide(s(650), true, 0, None), Do::Nothing, "idle 550 s: not yet");
        g.wanted = true;
        assert_eq!(g.decide(s(690), true, 0, None), Do::Nothing, "work waits again: the idle time starts over");
        g.wanted = false;
        assert_eq!(g.decide(s(1200), true, 0, None), Do::Nothing);
        assert!(matches!(g.decide(s(1290), true, 0, None), Do::Stop(_)));
        g.stopped();
        assert_eq!(g.decide(s(1300), false, 0, None), Do::Nothing);
        assert!(matches!(g.decide(s(1301), false, 1, None), Do::Start(_)), "a grant that needs containers starts it");
    }

    /// Linux has no VM to stop: on_demand runs as always.
    #[test]
    #[cfg(target_os = "linux")]
    fn on_demand_on_linux_is_always() {
        let mut g = gate("on_demand", 60);
        let t = Instant::now();
        assert!(!g.parked());
        g.started(t);
        assert_eq!(g.decide(t + Duration::from_secs(3600), true, 0, None), Do::Nothing);
    }

    /// A failed on-demand start is not offered as startable for a while (the coordinator would wake it for nothing).
    #[test]
    #[cfg(any(target_os = "macos", windows))]
    fn a_failed_start_holds_the_runtime_back() {
        let mut g = gate("on_demand", 60);
        let t = Instant::now();
        g.started(t);
        g.observe(t, "failed", false);
        assert!(!g.startable(t + Duration::from_secs(60), true));
        assert!(g.startable(t + FAILED_HOLD, true));
        g.observe(t, "ready", false);
        assert!(g.failed_until.is_none());
    }

    /// A VM at another size than the owner's settings restarts once no container job is live, once per wanted size.
    #[test]
    fn a_vm_at_the_wrong_size_restarts_when_idle_once_per_size() {
        let mut g = gate("always", 60);
        let t = Instant::now();
        g.started(t);
        let m = Some(((2.0, 6), (8.0, 6)));
        assert_eq!(g.decide(t, true, 1, m), Do::Nothing, "a container job is live");
        let Do::Restart(why) = g.decide(t, true, 0, m) else { panic!("restart") };
        assert!(why.contains("8.0 GB") && why.contains("2.0 GB"), "{why}");
        g.started(t);
        assert_eq!(g.decide(t, true, 0, Some(((2.0, 6), (8.2, 6)))), Do::Nothing, "still 8 GB after the restart: not again");
        assert!(matches!(g.decide(t, true, 0, Some(((6.5, 6), (2.0, 6)))), Do::Restart(_)), "a new size");
    }

    #[test]
    fn the_reports_say_why_no_runtime_runs() {
        let vm = json!({"mem_gb": 2.0, "cpus": 6});
        let off = idle_report("colima", Mode::Off, vec![], &vm);
        assert_eq!((off["state"].as_str(), off["mode"].as_str(), off["gpu"].as_str()), (Some("disabled"), Some("off"), Some("undetected")));
        assert_eq!(off["vm"], vm);
        assert_eq!(idle_report("wslc", Mode::OnDemand, vec![], &Value::Null)["state"], "stopped");
        assert_eq!(idle_report("wslc", Mode::OnDemand, vec![json!({"what": "wsl_package"})], &Value::Null)["state"], "missing");
        let mut g = gate("on_demand", 600);
        g.start_s = Some(45);
        let mut pools = serde_json::Map::new();
        pools.insert("containers".into(), json!(2));
        assert_eq!(g.report("stopped", &pools, &vm), json!({"mode": "on_demand", "state": "stopped", "idle_stop_s": 600, "start_s": 45,
                                                             "startable": {"containers": 2}, "vm": vm}));
        assert_eq!(held_state("ready"), "running");
        assert_eq!(held_state("failed"), "failed");
        let tmp = crate::scratch("gate-override");
        let home = tmp.path();
        assert!(read_override(home).is_none());
        assert!(set_override(home, Some(&off)) && !set_override(home, Some(&off)));
        assert_eq!(read_override(home), Some(off));
        assert!(set_override(home, None) && read_override(home).is_none() && !set_override(home, None));
    }
}
