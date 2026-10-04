//! Per-process counters, the metrics a `protect` rule can target, and the [`Meter`] the controller reads
//! them through.

use std::ops::{Add, Sub};

use serde::{Deserialize, Serialize};

use crate::gpu::GpuTimes;

/// Cumulative per-process counters, sampled each tick. Times are seconds, counts raw.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcCounters {
    pub cpu_s: f64,
    /// Time runnable, including time on a core.
    pub runnable_s: f64,
    pub instructions: f64,
    pub cycles: f64,
    pub pageins: f64,
}

impl Sub for ProcCounters {
    type Output = ProcCounters;
    /// A delta, never negative (a counter that went backwards is a new process).
    fn sub(self, b: ProcCounters) -> ProcCounters {
        ProcCounters {
            cpu_s: (self.cpu_s - b.cpu_s).max(0.0),
            runnable_s: (self.runnable_s - b.runnable_s).max(0.0),
            instructions: (self.instructions - b.instructions).max(0.0),
            cycles: (self.cycles - b.cycles).max(0.0),
            pageins: (self.pageins - b.pageins).max(0.0),
        }
    }
}

impl Add for ProcCounters {
    type Output = ProcCounters;
    fn add(self, b: ProcCounters) -> ProcCounters {
        ProcCounters {
            cpu_s: self.cpu_s + b.cpu_s,
            runnable_s: self.runnable_s + b.runnable_s,
            instructions: self.instructions + b.instructions,
            cycles: self.cycles + b.cycles,
            pageins: self.pageins + b.pageins,
        }
    }
}

/// The metrics a `protect` rule can target, computed for a group over one sample interval.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct GroupMetrics {
    /// (Δrunnable − Δcpu) ÷ Δrunnable: the share of runnable time spent waiting for a core (PSI-cpu analogue).
    pub cpu_stall: Option<f64>,
    /// Δinstructions ÷ Δcycles (valid above 0.25 cores).
    pub ipc: Option<f64>,
    /// Pageins per second.
    pub pageins_rate: Option<f64>,
    pub cpu_cores: f64,
    /// Feature-detected; None = unknown.
    pub gpu_share: Option<f64>,
    /// Owner-supplied source, events per second.
    pub progress_rate: Option<f64>,
}

impl GroupMetrics {
    pub fn from_delta(d: ProcCounters, seconds: f64) -> GroupMetrics {
        if seconds <= 0.0 {
            return GroupMetrics::default();
        }
        // runnable time includes time on a core (measured on macOS 26.5 and 27.0: a lone busy thread shows
        // runnable ≈ cpu), so the waiting share is (runnable − cpu) ÷ runnable.
        let cores = d.cpu_s / seconds;
        let stall = if d.runnable_s > 1e-6 {
            ((d.runnable_s - d.cpu_s).max(0.0) / d.runnable_s).min(1.0)
        } else {
            0.0
        };
        GroupMetrics {
            cpu_stall: Some(stall),
            ipc: (cores >= 0.25 && d.cycles > 0.0).then(|| d.instructions / d.cycles),
            pageins_rate: Some(d.pageins / seconds),
            cpu_cores: cores,
            gpu_share: None,
            progress_rate: None,
        }
    }

    pub fn value(&self, metric: &str) -> Option<f64> {
        match metric {
            "cpu_stall" => self.cpu_stall,
            "ipc_ratio" => self.ipc,
            "pageins_rate" => self.pageins_rate,
            "gpu_share" => self.gpu_share,
            "progress_rate" => self.progress_rate,
            _ => None,
        }
    }
}

/// What is in front of the person using the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Front {
    /// Not readable here; a `frontmost` trigger then holds either way (never looser).
    Unknown,
    /// No app: nobody's desktop is on the screen (no one logged in at it, a headless machine).
    Nothing,
    /// The app this process belongs to is in front.
    App(i32),
}

impl Front {
    /// The front app's pid, when one is known.
    pub fn app(self) -> Option<i32> {
        match self {
            Self::App(pid) => Some(pid),
            _ => None,
        }
    }

    /// Does a `frontmost = want` trigger hold for a group (`in_group`: is this pid one of its processes)?
    pub fn holds(self, want: bool, in_group: impl Fn(i32) -> bool) -> bool {
        match self {
            Self::Unknown => true,
            Self::Nothing => !want,
            Self::App(pid) => in_group(pid) == want,
        }
    }

}

/// What is in front, and where it was read (or why it could not be).
#[derive(Debug, Clone, PartialEq)]
pub struct FrontReading {
    pub front: Front,
    pub source: String,
}

impl FrontReading {
    pub fn new(front: Front, source: impl Into<String>) -> Self {
        Self {
            front,
            source: source.into(),
        }
    }

    /// The telemetry form: "app 812 (lsappinfo)", "nothing (no one at seat0)", or the reason it is unknown.
    pub fn describe(&self) -> String {
        match self.front {
            Front::App(pid) => format!("app {pid} ({})", self.source),
            Front::Nothing => format!("nothing ({})", self.source),
            Front::Unknown => self.source.clone(),
        }
    }
}

/// What the controller measures on the host each tick. Every source is feature-detected: None means
/// unknown, and the controller then degrades fail-safe (no budget growth; guards intact).
pub trait Meter: Send {
    /// Cumulative counters for one of the owner's processes (None: gone, or not permitted).
    fn proc_counters(&mut self, pid: i32) -> Option<ProcCounters>;
    /// Every process's accumulated GPU time, or None when the source is unavailable.
    fn gpu_times(&mut self) -> Option<GpuTimes>;
    /// What is in front.
    fn front(&mut self) -> FrontReading;
}

/// A meter that knows nothing (tests, and platforms without a backend yet).
#[derive(Debug, Default, Clone, Copy)]
pub struct NullMeter;

impl Meter for NullMeter {
    fn proc_counters(&mut self, _: i32) -> Option<ProcCounters> {
        None
    }
    fn gpu_times(&mut self) -> Option<GpuTimes> {
        None
    }
    fn front(&mut self) -> FrontReading {
        FrontReading::new(Front::Unknown, "unknown: no meter")
    }
}

/// Whether someone is using the machine, and since when they have not touched it.
#[derive(Debug, Clone, PartialEq)]
pub struct PresenceReading {
    /// Seconds since the last input of anyone using the machine (at the keyboard, or remotely); infinite when
    /// nobody is logged in; None when it cannot be read.
    pub idle_s: Option<f64>,
    /// Where it was read ("hid", "screen sharing", "logind", …), or why it could not be.
    pub source: String,
}

impl PresenceReading {
    pub fn new(idle_s: Option<f64>, source: impl Into<String>) -> Self {
        Self {
            idle_s,
            source: source.into(),
        }
    }

    /// The idle time capacity and the controller act on: unknown presence counts as someone present (S19).
    pub fn effective_idle_s(&self) -> f64 {
        self.idle_s.unwrap_or(0.0)
    }
}

/// The host's user-presence interface.
pub trait Presence: Send {
    fn read(&mut self) -> PresenceReading;
}

/// Parsing for the macOS frontmost-app lookup through `lsappinfo`. `lsappinfo info -only pid front` no longer
/// resolves "front" (empty output on macOS 26.5 and 27), so the app's serial number is read first
/// with `lsappinfo front`. macOS 26.5 answers `"pid"=1234`; macOS 27 ignores `-only` and prints the full
/// record, whose pid line reads `pid = 1234`.
pub mod frontmost {
    /// "ASN:0x0-0x13e0bdf8:" -> itself; anything else -> None.
    pub fn serial_number(s: &str) -> Option<String> {
        let t = s.trim();
        (t.starts_with("ASN:") && !t.contains(' ')).then(|| t.to_string())
    }

    /// `"pid"=1234` (macOS 26) or a full record's `pid = 1234` line (macOS 27) -> 1234; anything else -> None.
    pub fn parse_pid(s: &str) -> Option<i32> {
        for marker in ["\"pid\"=", "pid = "] {
            if let Some(i) = s.find(marker) {
                let digits: String = s[i + marker.len()..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if let Ok(v) = digits.parse::<i32>() {
                    if v > 0 {
                        return Some(v);
                    }
                }
            }
        }
        None
    }
}
