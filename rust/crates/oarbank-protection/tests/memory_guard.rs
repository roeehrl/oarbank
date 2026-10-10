//! The L0 memory guard and the system gates.

use oarbank_protection::memory_guard::VictimCandidate;
use oarbank_protection::*;

fn m(used: f64, pressure: i32) -> MemorySignals {
    MemorySignals::new(64.0, used, pressure)
}

#[test]
fn soft_and_hard_floors() {
    let floors = MemoryFloors::default();
    let mut g = MemoryGuard::new();
    assert_eq!(g.update(&m(40.0, 0), &floors, 0.0).0, GuardLevel::Clear);
    assert_eq!(g.update(&m(57.0, 0), &floors, 2.0).0, GuardLevel::Soft); // 10.9 % free
    assert_eq!(g.update(&m(40.0, 1), &floors, 4.0).0, GuardLevel::Soft); // warning
    let hard = g.update(&m(60.0, 0), &floors, 6.0);
    assert_eq!(hard, (GuardLevel::Hard, true));
    assert!(!g.update(&m(60.0, 0), &floors, 10.0).1); // one every 15 s
    assert!(g.update(&m(60.0, 0), &floors, 21.0).1);
    // recovered past the floor but not by the reclaim margin (2 GB): still hard
    assert_eq!(g.update(&m(58.5, 0), &floors, 23.0).0, GuardLevel::Hard);
    assert!(g.reason.contains("reclaiming"));
    assert_eq!(g.update(&m(50.0, 0), &floors, 25.0).0, GuardLevel::Clear);
    assert_eq!(g.reason, "");
}

#[test]
fn swap_growth_and_stale_signals() {
    let floors = MemoryFloors::default();
    let mut g = MemoryGuard::new();
    // 50 of 64 GB used: 21.9 % free, under 2.5 × the soft floor, so growing swap is pressure
    g.update(&m(50.0, 0).with_swap(1.0), &floors, 0.0);
    let r = g.update(&m(50.0, 0).with_swap(1.4), &floors, 30.0);
    assert_eq!(r.0, GuardLevel::Soft); // +800 MB/min
    assert_eq!(g.reason, "swap +819 MB/min");
    let hard = g.update(&m(50.0, 0).with_swap(2.2), &floors, 50.0);
    assert_eq!(hard.0, GuardLevel::Hard);
    let mut s = MemoryGuard::new();
    assert_eq!(
        s.update(&m(30.0, 0).with_age(20.0), &floors, 0.0).0,
        GuardLevel::Soft
    );
    assert_eq!(s.reason, "memory signals stale (20 s)");
}

/// TNT-PC (Windows, 15.8 GB) was held at "swap +282 MB/min" with 54 % of its memory free: the commit charge beyond
/// physical use had been read as swap. Swap growth with that much free is housekeeping, never a floor.
#[test]
fn swap_growth_with_plenty_free_is_not_pressure() {
    let floors = MemoryFloors::default();
    let mut g = MemoryGuard::new();
    let pc = |swap: f64| MemorySignals::new(15.8, 7.3, 0).with_swap(swap);
    g.update(&pc(0.50), &floors, 0.0);
    g.update(&pc(0.64), &floors, 30.0);
    assert_eq!(g.update(&pc(0.78), &floors, 60.0).0, GuardLevel::Clear);
    assert_eq!(g.reason, "");
    // the same growth once free memory is under 30 % counts (and 2 GB/min is the hard floor)
    let mut h = MemoryGuard::new();
    let tight = |swap: f64| MemorySignals::new(15.8, 11.5, 0).with_swap(swap);
    h.update(&tight(0.50), &floors, 0.0);
    assert_eq!(h.update(&tight(0.64), &floors, 30.0).0, GuardLevel::Soft);
    assert_eq!(h.update(&tight(2.0), &floors, 60.0).0, GuardLevel::Hard);
}

#[test]
fn reasons_name_every_cause() {
    let floors = MemoryFloors::default();
    let mut g = MemoryGuard::new();
    g.update(&m(62.0, 3), &floors, 0.0);
    assert_eq!(
        g.reason,
        "pressure warning; free 3.1% < 12%; pressure critical; free 3.1% < 8%"
    );
    assert_eq!(g.level.as_str(), "hard");
}

#[test]
fn victim_is_the_largest_footprint() {
    let c = |attempt_id, footprint_gb, started_at| VictimCandidate {
        attempt_id,
        footprint_gb,
        started_at,
    };
    // a tie goes to the one started first
    assert_eq!(
        MemoryGuard::victim(&[c(1, 2.0, 10.0), c(2, 5.0, 20.0), c(3, 5.0, 5.0)]),
        Some(3)
    );
    assert_eq!(MemoryGuard::victim(&[]), None);
}

#[test]
fn thermal_and_battery_gates() {
    assert!(SystemGates::vectors(Thermal::FAIR, false, false).is_empty());
    let t = SystemGates::vectors(Thermal::SERIOUS, false, false);
    assert_eq!(t.len(), 1);
    assert!(t[0].no_admit && t[0].cpu_cores == Some(0.0) && t[0].source == "guard:thermal");
    let b = SystemGates::vectors(Thermal::NOMINAL, true, false);
    assert_eq!(b[0].source, "guard:battery");
    assert!(SystemGates::vectors(Thermal::NOMINAL, true, true).is_empty());
}
