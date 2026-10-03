//! Windows has no container runtime yet (an agent-owned WSL2 distribution running Podman, docs/design/architecture.md,
//! "Containers"): a module approved for containers fails its attempt with a clear reason (jobs.rs), so no broker ever
//! exists here.

pub enum Broker {}

impl Broker {
    pub fn endpoint(&self) -> String {
        match *self {}
    }
}
