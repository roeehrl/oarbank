//! No runner outlives its agent (Unix; on Windows a runner's Job Object is killed when the agent's handle to it closes,
//! however the agent ends). A runner leads a process group of its own (sys.rs), so a service manager that kills the
//! agent's group does not reach it: the agent stops its runners itself when it is asked to stop (agent.rs `stop_jobs`),
//! and for an agent that ends without doing so (killed, crashed) two things end them:
//!
//! - a **record** per running runner, `<home>/state/runners/<attempt>.json`: the agent that started it (pid and start
//!   time), its group's leader and the processes seen in the group (each a pid and its start time, so a recycled pid is
//!   never taken for one of them), written when it starts and when its processes change, removed once it is gone;
//! - a **watchdog**, the agent's binary run as `reap-runners` in a session of its own, which holds the read end of a
//!   pipe only the agent can write to: when the agent has ended, however it ended, the read sees the end of the pipe
//!   and the watchdog ends the processes that agent's records name, then exits.
//!
//! A new agent also ends what the records of an earlier one name before it takes work (`reap`). Only a recorded process
//! that still has its recorded start time is ever signalled, and a whole group only once one of its members is such a
//! process: a group's id is its first leader's pid, and that pid is not reused while the group has members.

use crate::paths::Layout;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// How often a runner's processes are compared with its record.
const TRACK_EVERY: Duration = Duration::from_secs(2);

pub fn dir(layout: &Layout) -> PathBuf {
    layout.state().join("runners")
}

/// This process: its pid and start time (an agent's identity in the records).
fn me() -> Option<(u32, u64)> {
    let pid = std::process::id();
    crate::procs::start_time_us(pid as i32).map(|s| (pid, s))
}

/// The record of one running runner.
pub struct Record {
    path: PathBuf,
    doc: Value,
    members: Vec<(i32, u64)>,
    pgid: i32,
    checked: Instant,
}

impl Record {
    /// Record the runner whose group `pgid` this agent just started for attempt `aid`. None when it cannot be written
    /// (the runner then has only the agent's own stop and the OS's group to end it).
    pub fn create(layout: &Layout, aid: i64, pgid: i32) -> Option<Record> {
        let (agent_pid, agent_start) = me()?;
        let start = crate::procs::start_time_us(pgid)?;
        let d = dir(layout);
        std::fs::create_dir_all(&d).ok()?;
        let mut r = Record { path: d.join(format!("{aid}.json")), pgid, members: vec![(pgid, start)], checked: Instant::now(),
                             doc: json!({"attempt_id": aid, "agent_pid": agent_pid, "agent_start_us": agent_start.to_string(),
                                         "pgid": pgid, "start_us": start.to_string()}) };
        if let Err(e) = r.write() {
            warn!(attempt = aid, error = %e, "could not record the runner (it may outlive an agent that is killed)");
            return None;
        }
        Some(r)
    }

    fn write(&mut self) -> std::io::Result<()> {
        self.doc["members"] = json!(self.members.iter().map(|(p, s)| json!([p, s.to_string()])).collect::<Vec<_>>());
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(&self.doc)?)?;
        std::fs::rename(&tmp, &self.path)
    }

    /// Note the processes the runner's group has now (at most every TRACK_EVERY), and rewrite the record when they
    /// changed. A process that has ended stays listed: its start time keeps a recycled pid out.
    pub fn track(&mut self) {
        if self.checked.elapsed() < TRACK_EVERY {
            return;
        }
        self.checked = Instant::now();
        let mut changed = false;
        for pid in crate::sys::group_pids(self.pgid) {
            if self.members.iter().any(|(p, _)| *p == pid) {
                continue;
            }
            if let Some(s) = crate::procs::start_time_us(pid) {
                self.members.push((pid, s));
                changed = true;
            }
        }
        if changed {
            let _ = self.write();
        }
    }

    /// The runner's processes are gone (the agent killed its group and reaped it).
    pub fn remove(self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// What one record names, read back.
#[derive(Debug, Clone, PartialEq)]
struct Recorded {
    attempt_id: i64,
    agent: (u32, u64),
    pgid: i32,
    leader_start: u64,
    members: Vec<(i32, u64)>,
}

fn parse(v: &Value) -> Option<Recorded> {
    let num = |v: &Value| v.as_str().and_then(|s| s.parse::<u64>().ok()).or_else(|| v.as_u64());
    Some(Recorded {
        attempt_id: v["attempt_id"].as_i64()?,
        agent: (u32::try_from(v["agent_pid"].as_u64()?).ok()?, num(&v["agent_start_us"])?),
        pgid: i32::try_from(v["pgid"].as_i64()?).ok()?,
        leader_start: num(&v["start_us"])?,
        members: v["members"].as_array().map(|a| a.iter().filter_map(|m| {
            Some((i32::try_from(m[0].as_i64()?).ok()?, num(&m[1])?))
        }).collect()).unwrap_or_default(),
    })
}

fn alive_as(pid: i32, start: u64) -> bool {
    pid > 0 && crate::procs::start_time_us(pid) == Some(start)
}

/// The process group a live process is in.
fn pgid_of(pid: i32) -> Option<i32> {
    let g = unsafe { libc::getpgid(pid) };
    (g > 0).then_some(g)
}

/// End what one record names; how many of its recorded processes were still running.
fn end(r: &Recorded) -> usize {
    let leader = alive_as(r.pgid, r.leader_start);
    // the group is the runner's while its leader, or a recorded member, is still in it
    let mut ours = leader;
    let mut live = Vec::new();
    for &(pid, start) in r.members.iter().filter(|(p, _)| *p != r.pgid) {
        if alive_as(pid, start) {
            ours |= pgid_of(pid) == Some(r.pgid);
            live.push(pid);
        }
    }
    if ours {
        unsafe { libc::killpg(r.pgid, libc::SIGKILL) };     // a stopped (paused) process ends too
    }
    for &pid in &live {
        unsafe { libc::kill(pid, libc::SIGKILL) };           // one that left the group
    }
    live.len() + usize::from(leader)
}

/// Which records to act on.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Whose {
    /// The records of this agent instance (the watchdog of an agent that has ended).
    Agent(u32, u64),
    /// Every record of an agent instance that is no longer running (a new agent, before it takes work).
    Ended,
}

/// End the runners the records name (`whose`), and remove those records; one line per runner that was still running.
pub fn reap(layout: &Layout, whose: Whose) -> Vec<String> {
    reap_dir(&dir(layout), whose)
}

fn reap_dir(d: &Path, whose: Whose) -> Vec<String> {
    let mut out = vec![];
    let me = me();
    for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
        let path = e.path();
        if path.extension().is_none_or(|x| x != "json") {
            continue;
        }
        let Some(r) = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).and_then(|v| parse(&v)) else {
            let _ = std::fs::remove_file(&path);                   // unreadable: it names nothing that can be checked
            continue;
        };
        let take = match whose {
            Whose::Agent(pid, start) => r.agent == (pid, start),
            // never the runners of an agent that still runs (this one, or another on the same home)
            Whose::Ended => Some(r.agent) != me && !alive_as(r.agent.0 as i32, r.agent.1),
        };
        if !take {
            continue;
        }
        let n = end(&r);
        if n > 0 {
            out.push(format!("attempt {}: ended {n} process(es) of runner group {} left by agent pid {}", r.attempt_id, r.pgid,
                             r.agent.0));
        }
        let _ = std::fs::remove_file(&path);
    }
    out
}

/// Start the watchdog for this agent; the returned descriptor is the pipe's write end, held for the agent's lifetime
/// (it is never inherited: close-on-exec). None when it could not be started (the agent then runs without one).
pub fn watchdog(layout: &Layout) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    let (pid, start) = me()?;
    let exe = std::env::current_exe().ok()?;
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&read, &write] {
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--home").arg(&layout.home).arg("reap-runners").arg("--agent-pid").arg(pid.to_string())
        .arg("--agent-start").arg(start.to_string())
        .stdin(std::process::Stdio::from(read)).stdout(std::process::Stdio::null());
    // a session of its own: a service manager that kills the agent's process group leaves it to do its work
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    match cmd.spawn() {
        Ok(mut child) => {
            std::thread::spawn(move || child.wait());           // reaped when it exits: never left a zombie
            Some(write)
        }
        Err(e) => {
            warn!(error = %e, "could not start the runner watchdog: a killed agent may leave its runners running until it starts again");
            None
        }
    }
}

/// `reap-runners`: wait until the agent (`agent`) has ended, then end the runners its records name.
pub fn watchdog_main(layout: &Layout, agent: (u32, u64)) {
    use std::io::Read;
    let mut buf = [0u8; 64];
    let mut stdin = std::io::stdin();
    loop {
        match stdin.read(&mut buf) {
            Ok(0) => break,                                       // every write end is closed: the agent has ended
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    for line in reap(layout, Whose::Agent(agent.0, agent.1)) {
        info!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    /// A process group like a runner's: a shell leading its own group, with a child.
    fn runner_group() -> std::process::Child {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sleep 300 & wait"]).stdout(Stdio::null()).stderr(Stdio::null());
        crate::sys::spawn_contained(&mut cmd, false).unwrap()
    }

    fn wait_gone(pid: i32, start: u64) -> bool {
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            if !alive_as(pid, start) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// The records name the runners an agent started; once that agent has ended, `reap` ends every process of each
    /// recorded group (a stopped one too) and removes the records. A record naming a pid that now belongs to another
    /// process (another start time), or a group nothing recorded is in, signals nothing, and the runners of an agent
    /// that still runs are left alone.
    #[test]
    fn records_of_an_ended_agent_end_its_runners_and_nothing_else() {
        let tmp = crate::scratch("runners");
        let layout = Layout::new(tmp.path().to_path_buf());
        let mut a = runner_group();
        let pg = a.id() as i32;
        let mut rec = Record::create(&layout, 7, pg).expect("recorded");
        // its child shows up in the record
        let until = Instant::now() + Duration::from_secs(5);
        while rec.members.len() < 2 && Instant::now() < until {
            rec.checked -= TRACK_EVERY;
            rec.track();
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(rec.members.len(), 2, "{:?}", rec.members);
        let child = rec.members[1];
        unsafe { libc::killpg(pg, libc::SIGSTOP) };              // paused by protection
        // this agent still runs: Ended leaves its records alone
        assert!(reap(&layout, Whose::Ended).is_empty());
        assert!(alive_as(pg, rec.members[0].1) && alive_as(child.0, child.1));
        // a record whose pid now belongs to another process (another start time) signals nothing
        let mut other = Command::new("/bin/sleep").arg("300").spawn().unwrap();
        let o = other.id() as i32;
        std::fs::write(dir(&layout).join("8.json"), serde_json::to_vec(&json!({"attempt_id": 8, "agent_pid": 1,
            "agent_start_us": "1", "pgid": o, "start_us": "12345", "members": [[o, "12345"]]})).unwrap()).unwrap();
        // the agent's watchdog: its own records only
        let (pid, start) = me().unwrap();
        let lines = reap(&layout, Whose::Agent(pid, start));
        assert_eq!(lines.len(), 1, "{lines:?}");
        let _ = a.wait();                                         // the leader is this test's child: reaped here
        assert!(wait_gone(child.0, child.1));
        assert!(!dir(&layout).join("7.json").exists());
        // the stale record: removed by a later agent, the process it seemed to name untouched
        assert!(reap(&layout, Whose::Ended).is_empty());
        assert!(!dir(&layout).join("8.json").exists());
        assert!(other.try_wait().unwrap().is_none(), "an unrelated process was signalled");
        let _ = other.kill();
        let _ = other.wait();
    }

    /// A group whose leader has ended but whose recorded member still runs in it is still the runner's: every process
    /// in it ends, including one that started after the record was last written.
    #[test]
    fn a_leaderless_group_ends_through_a_recorded_member() {
        let tmp = crate::scratch("runners-leaderless");
        let layout = Layout::new(tmp.path().to_path_buf());
        let mut cmd = Command::new("/bin/sh");
        // the leader starts a member, then a second one after a while, then exits; both stay in its group
        cmd.args(["-c", "sleep 300 & sleep 1; sleep 300 & exit 0"]).stdout(Stdio::null()).stderr(Stdio::null());
        let mut a = crate::sys::spawn_contained(&mut cmd, false).unwrap();
        let pg = a.id() as i32;
        let mut rec = Record::create(&layout, 9, pg).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        rec.checked -= TRACK_EVERY;
        rec.track();                                              // the first member (and perhaps the shell's sleep 1)
        let recorded: Vec<(i32, u64)> = rec.members.iter().copied().filter(|(p, _)| *p != pg).collect();
        drop(rec);                                                // the agent dies: the record stays
        let _ = a.wait();                                         // the leader has ended
        std::thread::sleep(Duration::from_millis(1500));          // the unrecorded second member has started
        let first: Vec<(i32, u64)> = recorded.into_iter().filter(|(p, s)| alive_as(*p, *s)).collect();
        assert_eq!(first.len(), 1, "{first:?}");
        let late: Vec<(i32, u64)> = crate::sys::group_pids(pg).into_iter().filter(|p| *p != first[0].0)
            .filter_map(|p| Some((p, crate::procs::start_time_us(p)?))).collect();
        assert_eq!(late.len(), 1, "{late:?}");
        let (pid, start) = me().unwrap();
        assert_eq!(reap(&layout, Whose::Agent(pid, start)).len(), 1);
        assert!(wait_gone(first[0].0, first[0].1) && wait_gone(late[0].0, late[0].1));
    }

    #[test]
    fn a_record_reads_back() {
        let v = json!({"attempt_id": 3, "agent_pid": 10, "agent_start_us": "99", "pgid": 11, "start_us": "100",
                       "members": [[11, "100"], [12, "101"]]});
        assert_eq!(parse(&v), Some(Recorded { attempt_id: 3, agent: (10, 99), pgid: 11, leader_start: 100,
                                              members: vec![(11, 100), (12, 101)] }));
        assert_eq!(parse(&json!({"attempt_id": 3})), None);
    }
}
