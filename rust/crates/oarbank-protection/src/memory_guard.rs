//! L0: the memory guard, and the thermal and battery gates. They never depend on rules and cannot be
//! loosened by them.

use crate::config::MemoryFloors;
use crate::evaluator::ConstraintVector;

/// Memory pressure levels on the wire (xnu enum): normal 0, warning 1, critical 3.
pub struct MemPressure;

impl MemPressure {
    pub const NORMAL: i32 = 0;
    pub const WARNING: i32 = 1;
    pub const CRITICAL: i32 = 3;
}

/// Thermal states on the wire: nominal 0, fair 1, serious 2, critical 3.
pub struct Thermal;

impl Thermal {
    pub const NOMINAL: i32 = 0;
    pub const FAIR: i32 = 1;
    pub const SERIOUS: i32 = 2;
    pub const CRITICAL: i32 = 3;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MemorySignals {
    pub ram_gb: f64,
    /// App + wired + compressed memory (what cannot be dropped without paging), GB.
    pub used_gb: f64,
    pub pressure: i32,
    /// Swap in use, GB.
    pub swap_used_gb: Option<f64>,
    /// Age of the newest sample, seconds (stale signals count as a violation: fail-safe).
    pub age_s: f64,
}

impl MemorySignals {
    pub fn new(ram_gb: f64, used_gb: f64, pressure: i32) -> Self {
        Self {
            ram_gb,
            used_gb,
            pressure,
            swap_used_gb: None,
            age_s: 0.0,
        }
    }

    pub fn with_swap(mut self, gb: f64) -> Self {
        self.swap_used_gb = Some(gb);
        self
    }

    pub fn with_age(mut self, s: f64) -> Self {
        self.age_s = s;
        self
    }

    pub fn free_pct(&self) -> f64 {
        if self.ram_gb > 0.0 {
            ((self.ram_gb - self.used_gb) / self.ram_gb * 100.0).max(0.0)
        } else {
            0.0
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum GuardLevel {
    #[default]
    Clear,
    Soft,
    Hard,
}

impl GuardLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Soft => "soft",
            Self::Hard => "hard",
        }
    }
}

/// Swap growth counts only while free memory is under this multiple of the soft floor (30 % at the default 12 %).
/// With more free than that, growing swap is the kernel's housekeeping, not pressure: Linux swaps idle anonymous
/// pages out to keep file cache (swappiness) and Windows writes modified pages to its paging file ahead of need.
pub const SWAP_GROWTH_FREE_FACTOR: f64 = 2.5;

/// The soft floor stops admission; the hard floor evicts the largest-footprint fleet job, one every 15 s,
/// until free memory has recovered by the reclaim margin (the Kubernetes guard against re-eviction).
#[derive(Debug, Clone)]
pub struct MemoryGuard {
    pub level: GuardLevel,
    pub reason: String,
    swap_history: Vec<(f64, f64)>,
    hard_since_free_gb: Option<f64>,
    last_evict_at: f64,
    pub evict_every_s: f64,
    pub stale_after_s: f64,
}

impl Default for MemoryGuard {
    fn default() -> Self {
        Self {
            level: GuardLevel::Clear,
            reason: String::new(),
            swap_history: vec![],
            hard_since_free_gb: None,
            last_evict_at: -1e18,
            evict_every_s: 15.0,
            stale_after_s: 6.0,
        }
    }
}

/// Guards compare by what they report.
impl PartialEq for MemoryGuard {
    fn eq(&self, o: &Self) -> bool {
        self.level == o.level && self.reason == o.reason
    }
}

/// One fleet job as the hard floor sees it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VictimCandidate {
    pub attempt_id: i64,
    pub footprint_gb: f64,
    pub started_at: f64,
}

impl MemoryGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Swap growth over the last minute, MB/min (None until two samples 20 s apart exist).
    fn swap_growth_mb_min(&self, now: f64) -> Option<f64> {
        let first = self.swap_history.iter().find(|s| now - s.0 <= 60.0)?;
        let last = self.swap_history.last()?;
        if last.0 - first.0 < 20.0 {
            return None;
        }
        Some((last.1 - first.1) * 1024.0 / ((last.0 - first.0) / 60.0))
    }

    /// Update with this tick's signals; returns the level and whether to evict one job now.
    pub fn update(
        &mut self,
        s: &MemorySignals,
        floors: &MemoryFloors,
        now: f64,
    ) -> (GuardLevel, bool) {
        if let Some(sw) = s.swap_used_gb {
            self.swap_history.push((now, sw));
            self.swap_history.retain(|h| now - h.0 <= 120.0);
        }
        let free = s.free_pct();
        let growth = self
            .swap_growth_mb_min(now)
            .filter(|_| free < floors.soft_free_pct * SWAP_GROWTH_FREE_FACTOR);
        let mut lvl = GuardLevel::Clear;
        let mut why: Vec<String> = vec![];
        if s.age_s > self.stale_after_s {
            lvl = GuardLevel::Soft;
            why.push(format!("memory signals stale ({} s)", s.age_s as i64));
        }
        if s.pressure >= MemPressure::WARNING {
            lvl = lvl.max(GuardLevel::Soft);
            why.push("pressure warning".into());
        }
        if free < floors.soft_free_pct {
            lvl = lvl.max(GuardLevel::Soft);
            why.push(format!("free {free:.1}% < {:.0}%", floors.soft_free_pct));
        }
        if let Some(g) = growth.filter(|g| *g > floors.swap_growth_soft_mb_min) {
            lvl = lvl.max(GuardLevel::Soft);
            why.push(format!("swap +{g:.0} MB/min"));
        }
        if s.pressure >= MemPressure::CRITICAL {
            lvl = GuardLevel::Hard;
            why.push("pressure critical".into());
        }
        if free < floors.hard_free_pct {
            lvl = GuardLevel::Hard;
            why.push(format!("free {free:.1}% < {:.0}%", floors.hard_free_pct));
        }
        if let Some(g) = growth.filter(|g| *g > floors.swap_growth_hard_mb_min) {
            lvl = GuardLevel::Hard;
            why.push(format!("swap +{g:.0} MB/min"));
        }
        // once hard, stay hard until free memory recovered by the reclaim margin
        let free_gb = s.ram_gb - s.used_gb;
        if lvl == GuardLevel::Hard {
            self.hard_since_free_gb.get_or_insert(free_gb);
        } else if let Some(base) = self.hard_since_free_gb {
            if free_gb < base + floors.min_reclaim_gb {
                lvl = GuardLevel::Hard;
                why.push(format!(
                    "reclaiming: {:.1} of {:.1} GB",
                    (free_gb - base).max(0.0),
                    floors.min_reclaim_gb
                ));
            } else {
                self.hard_since_free_gb = None;
            }
        }
        self.level = lvl;
        self.reason = why.join("; ");
        let mut evict = false;
        if lvl == GuardLevel::Hard && now - self.last_evict_at >= self.evict_every_s {
            evict = true;
            self.last_evict_at = now;
        }
        (lvl, evict)
    }

    /// Hard-floor victim: the largest footprint, the one started first on a tie (one band until bands arrive).
    pub fn victim(jobs: &[VictimCandidate]) -> Option<i64> {
        let mut best: Option<&VictimCandidate> = None;
        for j in jobs {
            let better = match best {
                None => true,
                Some(b) => (b.footprint_gb, -b.started_at) < (j.footprint_gb, -j.started_at),
            };
            if better {
                best = Some(j);
            }
        }
        best.map(|j| j.attempt_id)
    }
}

/// Thermal and battery gates.
pub struct SystemGates;

impl SystemGates {
    pub fn vectors(thermal: i32, on_battery: bool, run_on_battery: bool) -> Vec<ConstraintVector> {
        let mut out = vec![];
        if thermal >= Thermal::SERIOUS {
            let mut v = ConstraintVector::no_admit("guard:thermal");
            v.cpu_cores = Some(0.0);
            out.push(v);
        }
        if on_battery && !run_on_battery {
            out.push(ConstraintVector::no_admit("guard:battery"));
        }
        out
    }
}
