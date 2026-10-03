//! Coordinator times on this node's clocks (docs/protocol.md, "Clocks").
//!
//! The coordinator writes absolute times in its own clock: a grant's `hard_deadline`, a move statement's time lock and
//! expiry. A node's wall clock may be hours off (a fresh machine without time sync), so the agent never compares those
//! times with its own wall clock. A grant's deadline becomes a local monotonic instant at receipt (only the difference
//! between the grant's `hard_deadline` and `issued_at` is used), and a move's times are compared with the coordinator's
//! clock as estimated from its last answer (`now` in every directive). Certificates and update metadata are checked
//! against this node's wall clock, and say so when that fails (a skewed clock, not a bad signature).

use serde_json::Value;
use std::time::{Duration, Instant};

/// When an attempt must stop: the grant's `hard_deadline`, as an instant on this node's monotonic clock, counted from
/// `received` (when the grant arrived). None when the grant sets no deadline.
pub fn local_deadline(grant: &Value, received: Instant) -> Option<Instant> {
    let (deadline, issued) = (grant["hard_deadline"].as_f64()?, grant["issued_at"].as_f64()?);
    Some(received + Duration::from_secs_f64((deadline - issued).max(0.0)))
}

/// The coordinator's clock as this node sees it: its time at its last answer minus ours.
#[derive(Debug, Default, Clone, Copy)]
pub struct CoordClock {
    offset_s: Option<f64>,
}

impl CoordClock {
    /// A directive arrived at local wall time `local_now` carrying the coordinator's `now`.
    pub fn observe(&mut self, directive: &Value, local_now: f64) {
        if let Some(t) = directive["now"].as_f64() {
            self.offset_s = Some(t - local_now);
        }
    }

    /// The coordinator's time at local wall time `local_now` (this node's own time until the coordinator first answers).
    pub fn now(&self, local_now: f64) -> f64 {
        local_now + self.offset_s.unwrap_or(0.0)
    }
}

/// The hint every wall-clock check adds when it fails: what this node's clock reads, so a skewed clock shows as one.
pub fn skew_hint(local_now: f64) -> String {
    format!("this node's clock reads {local_now:.0} (Unix time); if that is wrong, the node's clock is skewed: set its time")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HOUR: f64 = 3600.0;

    /// A grant as the coordinator writes it at its time `t` for a stage with a `run_s` limit.
    fn grant(t: f64, run_s: f64) -> Value {
        json!({"attempt_id": 1, "issued_at": t, "expires_at": t + 90.0, "hard_deadline": t + run_s})
    }

    #[test]
    fn a_skewed_node_clock_never_moves_a_grants_deadline() {
        let wall = crate::doctor::now();
        let received = Instant::now();
        // the node's clock is 7 h behind or ahead of the coordinator's, or right
        for skew in [-7.0 * HOUR, 0.0, 7.0 * HOUR] {
            let d = local_deadline(&grant(wall - skew, 2.0), received).unwrap();
            assert_eq!(d - received, Duration::from_secs(2), "skew {skew}");
            assert!(Instant::now() < d, "skew {skew}: the job must not time out at once");
        }
    }

    #[test]
    fn the_real_timeout_is_honoured_under_skew() {
        let wall = crate::doctor::now();
        for skew in [-7.0 * HOUR, 7.0 * HOUR] {
            let received = Instant::now();
            let d = local_deadline(&grant(wall - skew, 0.2), received).unwrap();
            assert!(Instant::now() < d);
            std::thread::sleep(Duration::from_millis(250));
            assert!(Instant::now() > d, "skew {skew}: the deadline passes after its real 0.2 s");
        }
    }

    #[test]
    fn a_grant_without_a_deadline_has_none() {
        assert!(local_deadline(&json!({"attempt_id": 1}), Instant::now()).is_none());
    }

    #[test]
    fn the_coordinator_clock_follows_its_answers() {
        let mut c = CoordClock::default();
        assert_eq!(c.now(1000.0), 1000.0);                   // no answer yet: this node's own time
        c.observe(&json!({"now": 1000.0 + 7.0 * HOUR}), 1000.0);
        assert_eq!(c.now(1010.0), 1010.0 + 7.0 * HOUR);
        c.observe(&json!({"heartbeat_s": 10}), 2000.0);      // a directive without `now` changes nothing
        assert_eq!(c.now(2000.0), 2000.0 + 7.0 * HOUR);
    }
}
