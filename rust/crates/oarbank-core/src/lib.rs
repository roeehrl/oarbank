//! The rules the Python SDK (`oarbank_sdk`, the reference) and the Rust agent must implement identically: canonical
//! JSON and job keys, platform tokens and portable paths, bundle digests and release manifests, the macOS sandbox
//! profile, the egress allow list, wheel/requirements checks and container image set signatures. The shared vectors
//! and goldens under the SDK's `spec/` directory are the contract; `tests/` replays them.

pub mod bundle;
pub mod canonical;
pub mod deps;
pub mod egress;
pub mod images;
pub mod portable;
mod py;
pub mod sandbox;
pub mod service;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
