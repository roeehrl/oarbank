//! cgroup v2 containers for jobs and services on Linux (docs/design/architecture.md, "Host interfaces": the job
//! container is a cgroup v2 subtree with cgroup.kill, cgroup.freeze, cpu.max, memory.max and PSI). It works where
//! systemd delegated the agent's cgroup (the unit has `Delegate=yes`; user units are delegated by default): the agent
//! moves itself into an `agent` leaf, enables the cpu, memory and pids controllers for its children, and gives every
//! container a sibling cgroup `c<leader>` holding the hard limits, whose `run` leaf holds the processes and, while
//! host protection lowers the job, its background CPU quota. The leader makes and enters its container itself, between
//! fork and exec (`Placement`), so nothing it starts is ever outside. Without a delegated cgroup the agent keeps to
//! process groups (`placement`).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();

/// The agent's delegated cgroup, set up on first use (None: not delegated or not writable).
pub fn root() -> Option<&'static Path> {
    ROOT.get_or_init(setup).as_deref()
}

/// Tests that need a delegated cgroup skip without one, unless `OARBANK_TEST_CGROUPS=required` makes that a failure
/// (CI runs the tests in a delegated user service).
#[cfg(test)]
pub fn required_in_tests() -> bool {
    std::env::var("OARBANK_TEST_CGROUPS").as_deref() == Ok("required")
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

/// How a new leader enters a container of its own: made before the fork (the delegated root as a C path, its
/// controllers enabled), used by the child between fork and exec (`enter`), so the leader and everything it starts are
/// born in the container. None without a delegated cgroup: then the process group alone is the container (it holds
/// every child from the first instruction for signals, but there are no hard limits, freeze or usage, and a child
/// that starts a session of its own leaves it).
pub fn placement() -> Option<Placement> {
    let r = root()?;
    enable_controllers(r);
    let root = std::ffi::CString::new(r.as_os_str().as_encoded_bytes()).ok()?;
    (root.as_bytes().len() < PATH_MAX - 64).then_some(Placement { root })
}

const PATH_MAX: usize = 4096;

pub struct Placement {
    root: std::ffi::CString,
}

impl Placement {
    /// In the child after the fork (system calls only, no allocation): make `c<own pid>` and its `run` leaf, give the
    /// leaf the cpu controller (the background quota), and move itself into the leaf.
    pub fn enter(&self) -> std::io::Result<()> {
        let mut digits = [0u8; 20];
        let mut n = unsafe { libc::getpid() } as u64;
        let mut i = digits.len();
        loop {
            i -= 1;
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        let pid = &digits[i..];
        let mut buf = [0u8; PATH_MAX];
        let path = |buf: &mut [u8; PATH_MAX], tail: &[u8]| -> *const libc::c_char {
            let root = self.root.as_bytes();
            let mut at = 0;
            for part in [root, &b"/c"[..], pid, tail, &b"\0"[..]] {
                buf[at..at + part.len()].copy_from_slice(part);
                at += part.len();
            }
            buf.as_ptr() as *const libc::c_char
        };
        let fail = || Err(std::io::Error::last_os_error());
        unsafe {
            for dir in [&b""[..], b"/run"] {
                if libc::mkdir(path(&mut buf, dir), 0o755) != 0 && *libc::__errno_location() != libc::EEXIST {
                    return fail();
                }
            }
            let fd = libc::open(path(&mut buf, b"/cgroup.subtree_control"), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd >= 0 {
                libc::write(fd, b"+cpu".as_ptr() as *const _, 4);           // only the background quota needs it
                libc::close(fd);
            }
            let fd = libc::open(path(&mut buf, b"/run/cgroup.procs"), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return fail();
            }
            let moved = libc::write(fd, b"0".as_ptr() as *const _, 1) == 1;
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            if moved { Ok(()) } else { Err(e) }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// A file's text once it has some (a loaded host may take seconds to start a Python: up to 60 s).
    fn wait_for(path: &Path) -> String {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if let Some(s) = std::fs::read_to_string(path).ok().filter(|s| !s.is_empty()) {
                return s;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        String::new()
    }

    /// A leader whose first statement forks 20 children, each started directly and through the sandbox launcher (the
    /// test binary answers `sandbox-exec`): the leader and all 20 are in its container's leaf, by the leaf's
    /// cgroup.procs and by each process's own /proc/<pid>/cgroup. Needs a delegated cgroup: run the tests as CI's Linux
    /// step does (.github/workflows/ci.yml: a transient user service with Delegate=yes).
    #[test]
    fn a_leader_and_what_it_forks_at_once_are_born_in_its_cgroup() {
        let Some(r) = root() else {
            assert!(!required_in_tests(), "no delegated cgroup, and OARBANK_TEST_CGROUPS=required");
            eprintln!("no delegated cgroup here (run as CI's Linux step does: .github/workflows/ci.yml): skipped");
            return;
        };
        let script = "import os, sys, time\n\
                      kids = []\n\
                      for _ in range(20):\n\
                      \x20   p = os.fork()\n\
                      \x20   if p == 0:\n\
                      \x20       time.sleep(120)\n\
                      \x20       os._exit(0)\n\
                      \x20   kids.append(p)\n\
                      open(sys.argv[1] + '.tmp', 'w').write(' '.join(map(str, [os.getpid()] + kids)))\n\
                      os.replace(sys.argv[1] + '.tmp', sys.argv[1])\n\
                      time.sleep(120)";
        let python = crate::runtime::which("python3").expect("python3");
        for via_launcher in [false, true] {
            let tmp = crate::scratch("born-in-cgroup");
            let dir = tmp.path().to_path_buf();
            let out = dir.join("pids");
            let mut argv: Vec<String> = vec![python.display().to_string(), "-I".into(), "-c".into(), script.into(), out.display().to_string()];
            if via_launcher {
                let mut pol = oarbank_core::sandbox::Policy::new("dev.test.cgroup");
                pol.rw = vec![dir.display().to_string()];
                pol.exe = Some(argv[0].clone());
                let pf = dir.join("policy.json");
                std::fs::write(&pf, serde_json::to_vec(&pol).unwrap()).unwrap();
                argv = [vec![std::env::current_exe().unwrap().display().to_string(), "sandbox-exec".into(), pf.display().to_string(), "--".into()], argv]
                    .concat();
            }
            let mut cmd = std::process::Command::new(&argv[0]);
            cmd.args(&argv[1..]).stdin(std::process::Stdio::null());
            let mut child = crate::sys::spawn_contained(&mut cmd, false).unwrap();
            let leader = child.id() as i32;
            let started: Vec<i32> = wait_for(&out).split_whitespace().filter_map(|p| p.parse().ok()).collect();
            let members = pids(leader).unwrap_or_default();
            let leaf = format!("0::/{}", r.join(format!("c{leader}")).join(RUN).strip_prefix("/sys/fs/cgroup").unwrap().display());
            let elsewhere: Vec<(i32, String)> = started.iter().filter_map(|p| {
                let c = std::fs::read_to_string(format!("/proc/{p}/cgroup")).unwrap_or_default();
                (c.trim() != leaf).then(|| (*p, c.trim().to_string()))
            }).collect();
            assert!(kill(leader));
            let _ = child.wait();
            let deadline = Instant::now() + Duration::from_secs(30);
            while pids(leader).is_some_and(|p| !p.is_empty()) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            release(leader);
            assert_eq!(started.len(), 21, "launcher {via_launcher}: {started:?}");
            assert_eq!(started.first(), Some(&leader));
            let outside: Vec<&i32> = started.iter().filter(|p| !members.contains(p)).collect();
            assert!(outside.is_empty(), "launcher {via_launcher}: outside {leaf}: {outside:?} (members {members:?})");
            assert!(elsewhere.is_empty(), "launcher {via_launcher}: {elsewhere:?}");
        }
    }

    /// The fallback, in a child copy of this test binary with OARBANK_CGROUPS=off (no delegated cgroup): no container
    /// is made, and the process group is the container, holding the leader's children from their first instruction
    /// and ending with them.
    #[test]
    #[ignore = "the role of without_a_delegated_cgroup_the_process_group_is_the_container"]
    fn no_cgroup_role() {
        if std::env::var("OARBANK_CGROUPS").as_deref() != Ok("off") {
            return;
        }
        assert!(root().is_none() && placement().is_none());
        let tmp = crate::scratch("no-cgroup");
        let dir = tmp.path().to_path_buf();
        let kid_file = dir.join("kid");
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", &format!("sleep 120 & echo $! > {}; wait", kid_file.display())]);
        let mut child = crate::sys::spawn_contained(&mut cmd, false).unwrap();
        let leader = child.id() as i32;
        let kid: i32 = wait_for(&kid_file).trim().parse().unwrap();
        assert!(container(leader).is_none());
        let stat = std::fs::read_to_string(format!("/proc/{kid}/stat")).unwrap();
        let pgrp: i32 = stat[stat.rfind(')').unwrap() + 2..].split_whitespace().nth(2).unwrap().parse().unwrap();
        assert_eq!(pgrp, leader, "the child is in the leader's process group");
        crate::sys::signal_group(leader, crate::sys::Sig::Kill);
        let _ = child.wait();
        let deadline = Instant::now() + Duration::from_secs(30);
        while unsafe { libc::kill(kid, 0) } == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_ne!(unsafe { libc::kill(kid, 0) }, 0, "the child ended with its group");
    }

    #[test]
    fn without_a_delegated_cgroup_the_process_group_is_the_container() {
        let st = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["cgroup::tests::no_cgroup_role", "--exact", "--ignored", "--quiet"]).env("OARBANK_CGROUPS", "off")
            .output().unwrap();
        assert!(st.status.success(), "{}\n{}", String::from_utf8_lossy(&st.stdout), String::from_utf8_lossy(&st.stderr));
    }
}
