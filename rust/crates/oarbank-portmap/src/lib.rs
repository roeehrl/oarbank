//! Router port mapping for inbound listeners (docs/design/inbound-listeners.md; PLAN D48, D49).
//!
//! - `natpmp`, `pcp`: small clients for RFC 6886 and RFC 6887; `upnp`: UPnP IGD v1/v2 through igd-next, plus the
//!   read-back actions it lacks;
//! - `manager`: the lifecycle per listener and family (request, verify, renew, recover, release) over a `Router`, with
//!   the write-ahead `journal`;
//! - `router`: the real router behind the lifecycle (`Target::System`, or fixed addresses for tests);
//! - `classify`: reachability in the owner's words, with the fix; `probe`: the dial-back; `stun`: the opt-in address
//!   check; `addr`, `netinfo`: what kind of address an address is, and the node's default route;
//! - `fake` (tests, feature `fake`): fake NAT-PMP, PCP and UPnP gateways on loopback.

pub mod addr;
pub mod classify;
pub mod journal;
pub mod manager;
pub mod natpmp;
pub mod netinfo;
pub mod pcp;
pub mod probe;
pub mod router;
pub mod stun;
pub mod types;
pub mod upnp;

#[cfg(any(test, feature = "fake"))]
pub mod fake;

#[cfg(test)]
mod tests_fake;
#[cfg(test)]
mod tests_model;

pub use manager::{Manager, Router, Status};
pub use types::*;

/// Wall-clock seconds (the journal and the lifecycle keep wall-clock times: they survive restarts).
pub fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}
