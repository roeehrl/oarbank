//! cgroup v2 containers for jobs and services on Linux (docs/design/architecture.md, "Host interfaces": the job
//! container is a cgroup v2 subtree with cgroup.kill, cgroup.freeze, cpu.max, memory.max and PSI). It works where
//! systemd delegated the agent's cgroup (the unit has `Delegate=yes`; user units are delegated by default): the agent
//! moves itself into an `agent` leaf, enables the cpu, memory and pids controllers for its children, and gives every
//! container a sibling cgroup `c<leader>` holding the hard limits, whose `run` leaf holds the processes and, while
//! host protection lowers the job, its background CPU quota. Without a delegated cgroup the agent keeps to process
//! groups.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();

/// The agent's delegated cgroup, set up on first use (None: not delegated or not writable).
pub fn root() -> Option<&'static Path> {
    ROOT.get_or_init(setup).as_deref()
}

fn setup() -> Option<PathBuf> {
    if std::env::var("OARBANK_CGROUPS").as_deref() == Ok("off") {
        return None;
    }
    let line = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = line.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    let mut root = PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    // already moved by an earlier run of this process image (the leaf is ours): the root is its parent
    if root.file_name().is_some_and(|n| n == "agent") {
        root = root.parent()?.to_path_buf();
    }
    let me = root.join("agent");
    std::fs::create_dir_all(&me).ok()?;
    // a cgroup that holds processes cannot give its children controllers: the launcher (the unit's main process,
    // in the same cgroup) moves too, then the agent
    if let Some(launcher) = std::env::var("OARBANK_LAUNCHER_PID").ok().and_then(|p| p.parse::<u32>().ok()) {
        let same = std::fs::read_to_string(format!("/proc/{launcher}/cgroup")).ok()
            .is_some_and(|c| c.lines().any(|l| l.strip_prefix("0::").map(str::trim) == Some(rel)));
        if same {
            let _ = std::fs::write(me.join("cgroup.procs"), launcher.to_string());
        }
    }
    std::fs::write(me.join("cgroup.procs"), std::process::id().to_string()).ok()?;
    enable_controllers(&root);
    Some(root)
}

/// Enable what is available for the leaves (a missing controller only means no limit of that kind). The root must
/// hold no process then: setup runs when the agent starts, before it has children.
fn enable_controllers(root: &Path) {
    let have = std::fs::read_to_string(root.join("cgroup.subtree_control")).unwrap_or_default();
    for c in ["cpu", "memory", "pids"] {
        if !have.split_whitespace().any(|x| x == c) {
            let _ = std::fs::write(root.join("cgroup.subtree_control"), format!("+{c}"));
        }
    }
}

/// The leaf of a container that holds its processes.
const RUN: &str = "run";
/// A lowered job's CPU quota: a tenth of one core per 100 ms period. The agent's cgroup and the owner's (the user
/// slice) are scheduled apart, so no scheduling class an unprivileged agent can set makes a job yield to the
/// owner's work; a quota does, while the job keeps running (its control document, its network sessions).
const BACKGROUND_QUOTA: &str = "10000 100000";

/// The container led by `pid`.
pub fn container(pid: i32) -> Option<PathBuf> {
    root().map(|r| r.join(format!("c{pid}"))).filter(|p| p.is_dir())
}

/// A container for the group led by `pid`, with `pid` moved into its leaf (its later children start there).
pub fn adopt(pid: i32) -> std::io::Result<()> {
    let Some(r) = root() else { return Ok(()) };
    enable_controllers(r);
    let c = r.join(format!("c{pid}"));
    std::fs::create_dir_all(c.join(RUN))?;
    // the leaf's own cpu.max is the background quota; the container's holds the hard limit
    let _ = std::fs::write(c.join("cgroup.subtree_control"), "+cpu");
    std::fs::write(c.join(RUN).join("cgroup.procs"), pid.to_string())
}

pub fn pids(pid: i32) -> Option<Vec<i32>> {
    let p = container(pid)?.join(RUN);
    let s = std::fs::read_to_string(p.join("cgroup.procs")).ok()?;
    Some(s.lines().filter_map(|l| l.trim().parse().ok()).collect())
}

/// Kill every member at once (`cgroup.kill`, Linux 5.14); false when there is no container or no such file.
pub fn kill(pid: i32) -> bool {
    container(pid).is_some_and(|p| std::fs::write(p.join("cgroup.kill"), "1").is_ok())
}

pub fn freeze(pid: i32, on: bool) -> bool {
    container(pid).is_some_and(|p| std::fs::write(p.join("cgroup.freeze"), if on { "1" } else { "0" }).is_ok())
}

/// Whether containers get the cpu controller (a delegated cgroup whose own processes all moved to the `agent` leaf),
/// which lowering needs.
pub fn cpu_controller() -> bool {
    root().and_then(|r| std::fs::read_to_string(r.join("cgroup.subtree_control")).ok())
        .is_some_and(|c| c.split_whitespace().any(|x| x == "cpu"))
}

/// Lower the job to its background CPU quota, or lift it; false when there is no container or no cpu controller.
pub fn background(pid: i32, on: bool) -> bool {
    container(pid).is_some_and(|p| std::fs::write(p.join(RUN).join("cpu.max"), if on { BACKGROUND_QUOTA } else { "max" }).is_ok())
}

/// CPU seconds and memory of the whole container.
pub fn usage(pid: i32) -> Option<(f64, f64)> {
    let p = container(pid)?;
    let cpu = std::fs::read_to_string(p.join("cpu.stat")).ok()?.lines()
        .find_map(|l| l.strip_prefix("usage_usec ")).and_then(|v| v.trim().parse::<f64>().ok()).unwrap_or(0.0) / 1e6;
    let mem = std::fs::read_to_string(p.join("memory.current")).ok().and_then(|v| v.trim().parse::<f64>().ok()).unwrap_or(0.0);
    Some((cpu, mem / 1073741824.0))
}

/// Hard limits: `cpu.max` as a quota of `cores` per 100 ms, `memory.max` in bytes (and no swap beyond it).
pub fn limit(pid: i32, cores: f64, mem_gb: f64) -> bool {
    let Some(p) = container(pid) else { return false };
    let mut ok = true;
    if cores > 0.0 {
        ok &= std::fs::write(p.join("cpu.max"), format!("{} 100000", (cores * 100_000.0).round() as u64)).is_ok();
    }
    if mem_gb > 0.0 {
        ok &= std::fs::write(p.join("memory.max"), format!("{}", (mem_gb * 1073741824.0) as u64)).is_ok();
        let _ = std::fs::write(p.join("memory.swap.max"), "0");
    }
    ok
}

/// The kernel's OOM killer ended a process of the container (`memory.events`).
pub fn oom_killed(pid: i32) -> bool {
    let Some(p) = container(pid) else { return false };
    std::fs::read_to_string(p.join("memory.events")).ok().and_then(|s| s.lines()
        .find_map(|l| l.strip_prefix("oom_kill ")).and_then(|v| v.trim().parse::<u64>().ok())).is_some_and(|n| n > 0)
}

/// Remove an empty container.
pub fn release(pid: i32) {
    if let Some(p) = container(pid) {
        let _ = std::fs::remove_dir(p.join(RUN));
        let _ = std::fs::remove_dir(p);
    }
}
