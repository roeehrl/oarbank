//! Process facts as Linux's procfs and Windows' native API describe them. The parsing (and, for procfs, the
//! reading under any root directory) is platform-neutral so that every OS tests it against real-shaped
//! samples; the platform backends only point it at the live system.

/// Linux: `/proc/<pid>/{stat,status,cmdline,exe}` and `/proc/<pid>/task/<tid>/schedstat` (proc(5)).
pub mod procfs {
    use std::collections::HashMap;
    use std::fs;
    use std::io::ErrorKind;
    use std::path::PathBuf;

    use crate::signals::ProcCounters;

    /// `PF_KTHREAD` in stat's flags: a kernel thread (no executable, no address space).
    const PF_KTHREAD: u64 = 0x0020_0000;

    /// The fields of `/proc/<pid>/stat` protection reads.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Stat {
        /// The kernel's short name (TASK_COMM_LEN: 15 characters).
        pub comm: String,
        pub state: char,
        pub ppid: i32,
        pub pgrp: i32,
        /// The foreground process group of the process's controlling terminal (-1: none).
        pub tpgid: i32,
        pub flags: u64,
        /// Major page faults: pages read in from disk (the pageins of macOS's rusage).
        pub majflt: u64,
        /// Clock ticks.
        pub utime: u64,
        pub stime: u64,
        /// Clock ticks after boot.
        pub starttime: u64,
        /// Resident pages.
        pub rss_pages: u64,
    }

    impl Stat {
        /// A zombie or dead task, or a kernel thread: nothing an owner runs.
        pub fn is_live_user_process(&self) -> bool {
            !matches!(self.state, 'Z' | 'X' | 'x') && self.flags & PF_KTHREAD == 0
        }
    }

    /// Parse `/proc/<pid>/stat`. The command sits in parentheses and may itself hold spaces and parentheses:
    /// the fields start after the last `)`.
    pub fn parse_stat(s: &str) -> Option<Stat> {
        let open = s.find('(')?;
        let close = s.rfind(')')?;
        let comm = s.get(open + 1..close)?.to_string();
        let f: Vec<&str> = s.get(close + 1..)?.split_whitespace().collect();
        let n = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok());
        let i = |k: usize| f.get(k).and_then(|v| v.parse::<i32>().ok());
        Some(Stat {
            comm,
            state: f.first()?.chars().next()?,
            ppid: i(1)?,
            pgrp: i(2)?,
            tpgid: i(5)?,
            flags: n(6)?,
            majflt: n(9)?,
            utime: n(11)?,
            stime: n(12)?,
            starttime: n(19)?,
            rss_pages: n(21)?,
        })
    }

    /// The fields of `/proc/<pid>/status` protection reads.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Status {
        /// The real user id.
        pub uid: u32,
        pub rss_anon_kb: u64,
        pub rss_shmem_kb: u64,
        pub vm_swap_kb: u64,
    }

    impl Status {
        /// The memory the process holds that the kernel cannot drop without paging: anonymous and shared
        /// resident memory plus what it has in swap (the analogue of macOS's physical footprint), GB.
        pub fn footprint_gb(&self) -> f64 {
            (self.rss_anon_kb + self.rss_shmem_kb + self.vm_swap_kb) as f64 / 1_048_576.0
        }
    }

    pub fn parse_status(s: &str) -> Option<Status> {
        let mut st = Status::default();
        let mut uid = None;
        let kb = |v: &str| {
            v.split_whitespace()
                .next()
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0)
        };
        for line in s.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            match k {
                "Uid" => uid = v.split_whitespace().next().and_then(|u| u.parse().ok()),
                "RssAnon" => st.rss_anon_kb = kb(v),
                "RssShmem" => st.rss_shmem_kb = kb(v),
                "VmSwap" => st.vm_swap_kb = kb(v),
                _ => {}
            }
        }
        st.uid = uid?;
        Some(st)
    }

    /// `/proc/<pid>/cmdline`: NUL-separated arguments (a trailing NUL ends the last one).
    pub fn parse_cmdline(b: &[u8]) -> Vec<String> {
        let b = b.strip_suffix(&[0]).unwrap_or(b);
        if b.is_empty() {
            return vec![];
        }
        b.split(|&c| c == 0)
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect()
    }

    /// `/proc/<pid>/task/<tid>/schedstat`: nanoseconds on a core, nanoseconds waiting on a run queue, and the
    /// number of timeslices.
    pub fn parse_schedstat(s: &str) -> Option<(u64, u64)> {
        let mut f = s.split_whitespace().map(|v| v.parse::<u64>().ok());
        Some((f.next()??, f.next()??))
    }

    /// `btime` (the boot time, seconds since the epoch) from `/proc/stat`.
    pub fn parse_btime(stat: &str) -> Option<u64> {
        stat.lines()
            .find_map(|l| l.strip_prefix("btime "))?
            .trim()
            .parse()
            .ok()
    }

    /// The target of `/proc/<pid>/exe`, without the " (deleted)" the kernel appends once the file is gone.
    pub fn exe_path(target: &str) -> String {
        target
            .strip_suffix(" (deleted)")
            .unwrap_or(target)
            .to_string()
    }

    /// One process as the table lists it.
    #[derive(Debug, Clone, PartialEq)]
    pub struct Entry {
        pub pid: i32,
        pub ppid: i32,
        pub uid: u32,
        pub start_us: u64,
        pub comm: String,
        /// None: the executable link is not readable (another account's process, without ptrace rights).
        pub path: Option<String>,
        pub cpu_s: f64,
        pub footprint_gb: f64,
    }

    /// procfs under a root directory (`/proc` on a live system).
    #[derive(Debug, Clone)]
    pub struct Reader {
        pub root: PathBuf,
        /// Clock ticks per second (`sysconf(_SC_CLK_TCK)`; 100 on every Linux architecture protection runs on).
        pub clk_tck: u64,
    }

    impl Reader {
        pub fn new(root: impl Into<PathBuf>, clk_tck: u64) -> Self {
            Self {
                root: root.into(),
                clk_tck: clk_tck.max(1),
            }
        }

        fn read(&self, pid: i32, file: &str) -> Option<String> {
            fs::read_to_string(self.root.join(pid.to_string()).join(file)).ok()
        }

        pub fn stat(&self, pid: i32) -> Option<Stat> {
            parse_stat(&self.read(pid, "stat")?)
        }

        pub fn btime(&self) -> Option<u64> {
            parse_btime(&fs::read_to_string(self.root.join("stat")).ok()?)
        }

        fn start_us(&self, btime: u64, starttime: u64) -> u64 {
            btime * 1_000_000 + starttime * 1_000_000 / self.clk_tck
        }

        /// When a process started, in microseconds since the epoch: the boot time plus its start in clock ticks.
        pub fn start_time_us(&self, pid: i32) -> Option<u64> {
            Some(self.start_us(self.btime()?, self.stat(pid)?.starttime))
        }

        /// The pids under the root.
        pub fn pids(&self) -> Option<Vec<i32>> {
            Some(
                fs::read_dir(&self.root)
                    .ok()?
                    .flatten()
                    .filter_map(|e| e.file_name().to_str()?.parse().ok())
                    .collect(),
            )
        }

        /// The executable's path: Some(None) when the link may not be read, None when the process is gone.
        pub fn exe(&self, pid: i32) -> Option<Option<String>> {
            match fs::read_link(self.root.join(pid.to_string()).join("exe")) {
                Ok(t) => Some(Some(exe_path(&t.to_string_lossy()))),
                Err(e) if e.kind() == ErrorKind::PermissionDenied => Some(None),
                Err(_) => None,
            }
        }

        /// The arguments (None: unreadable, or the process is gone).
        pub fn cmdline(&self, pid: i32) -> Option<Vec<String>> {
            fs::read(self.root.join(pid.to_string()).join("cmdline"))
                .ok()
                .map(|b| parse_cmdline(&b))
        }

        /// The live user processes whose real uid `owner` accepts, without the pids in `excluding`.
        pub fn list(
            &self,
            owner: impl Fn(u32) -> bool,
            excluding: &std::collections::HashSet<i32>,
        ) -> Option<Vec<Entry>> {
            let btime = self.btime()?;
            let mut out = vec![];
            for pid in self.pids()?.into_iter().filter(|p| !excluding.contains(p)) {
                let (Some(stat), Some(status)) = (
                    self.stat(pid),
                    self.read(pid, "status").as_deref().and_then(parse_status),
                ) else {
                    continue;
                };
                if !stat.is_live_user_process() || !owner(status.uid) {
                    continue;
                }
                let Some(path) = self.exe(pid) else { continue };
                out.push(Entry {
                    pid,
                    ppid: stat.ppid,
                    uid: status.uid,
                    start_us: self.start_us(btime, stat.starttime),
                    comm: stat.comm.clone(),
                    path,
                    cpu_s: (stat.utime + stat.stime) as f64 / self.clk_tck as f64,
                    footprint_gb: status.footprint_gb(),
                });
            }
            Some(out)
        }

        /// Every thread's (nanoseconds on a core, nanoseconds runnable but waiting), by thread id.
        pub fn threads(&self, pid: i32) -> Option<HashMap<i32, (u64, u64)>> {
            let dir = self.root.join(pid.to_string()).join("task");
            Some(
                fs::read_dir(dir)
                    .ok()?
                    .flatten()
                    .filter_map(|e| {
                        let tid: i32 = e.file_name().to_str()?.parse().ok()?;
                        let s = fs::read_to_string(e.path().join("schedstat")).ok()?;
                        Some((tid, parse_schedstat(&s)?))
                    })
                    .collect(),
            )
        }
    }

    /// One process's scheduler times, summed over its threads and kept monotonic: a thread's progress counts
    /// from one reading to the next, a thread born in between counts whole, and a thread that ended takes
    /// only its last interval with it (the kernel keeps no per-process wait time).
    #[derive(Debug, Clone, Default)]
    struct Acc {
        start: u64,
        threads: HashMap<i32, (u64, u64)>,
        run_ns: u64,
        wait_ns: u64,
        read_at: f64,
    }

    /// Per-process counters from procfs: CPU and runnable time from every thread's schedstat (the run-queue
    /// wait macOS reports as runnable time minus CPU time), and major faults as pageins. Linux has no
    /// per-process instruction or cycle counters without perf events, so those stay zero (IPC unknown).
    #[derive(Debug, Clone, Default)]
    pub struct Counters {
        acc: HashMap<i32, Acc>,
        swept_at: f64,
    }

    impl Counters {
        pub fn new() -> Self {
            Self::default()
        }

        /// Fold one reading of a process (its start time in clock ticks, threads, major faults) taken at `now`
        /// (seconds, any monotonic origin). Processes not read for a minute are forgotten.
        pub fn fold(
            &mut self,
            pid: i32,
            starttime: u64,
            threads: HashMap<i32, (u64, u64)>,
            majflt: u64,
            now: f64,
        ) -> ProcCounters {
            if now - self.swept_at >= 10.0 {
                self.acc.retain(|_, a| now - a.read_at < 60.0);
                self.swept_at = now;
            }
            let a = self.acc.entry(pid).or_default();
            if a.start != starttime || a.read_at == 0.0 {
                // a new process (or a reused pid): everything it ran so far counts once, from here on
                *a = Acc {
                    start: starttime,
                    ..Acc::default()
                };
            }
            for (tid, (run, wait)) in &threads {
                let (pr, pw) = a.threads.get(tid).copied().unwrap_or((0, 0));
                a.run_ns += run.saturating_sub(pr);
                a.wait_ns += wait.saturating_sub(pw);
            }
            a.threads = threads;
            a.read_at = now.max(f64::MIN_POSITIVE);
            ProcCounters {
                cpu_s: a.run_ns as f64 / 1e9,
                runnable_s: (a.run_ns + a.wait_ns) as f64 / 1e9,
                instructions: 0.0,
                cycles: 0.0,
                pageins: majflt as f64,
            }
        }
    }
}

/// Windows: the process list `NtQuerySystemInformation(SystemProcessInformation)` returns (one call, no handle
/// to any process), its threads' scheduling states, and command lines as `CommandLineToArgvW` splits them.
pub mod nt {
    /// `SYSTEM_PROCESS_INFORMATION` on 64-bit Windows (x64 and arm64 share the layout): the offsets read here,
    /// held to the windows-sys declaration by a test on Windows.
    pub mod offsets {
        pub const NEXT_ENTRY: usize = 0x00;
        pub const NUMBER_OF_THREADS: usize = 0x04;
        pub const WORKING_SET_PRIVATE: usize = 0x08;
        pub const HARD_FAULT_COUNT: usize = 0x10;
        pub const CREATE_TIME: usize = 0x20;
        pub const USER_TIME: usize = 0x28;
        pub const KERNEL_TIME: usize = 0x30;
        pub const IMAGE_NAME: usize = 0x38;
        pub const PROCESS_ID: usize = 0x50;
        pub const PARENT_ID: usize = 0x58;
        pub const SESSION_ID: usize = 0x64;
        pub const PROCESS_SIZE: usize = 0x100;
        /// `SYSTEM_THREAD_INFORMATION`, which follows each process entry once per thread.
        pub const THREAD_SIZE: usize = 0x50;
        pub const THREAD_STATE: usize = 0x44;
    }

    /// KTHREAD_STATE values of a thread that is runnable but not running: Ready, Standby (picked to run next on
    /// a core) and DeferredReady.
    const READY_STATES: [u32; 3] = [1, 3, 7];
    /// 100 ns intervals between 1601-01-01 and 1970-01-01.
    const EPOCH_1601_TO_1970: i64 = 116_444_736_000_000_000;

    /// One process.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Process {
        pub pid: u32,
        pub ppid: u32,
        pub session: u32,
        /// 100 ns intervals since 1601 (a FILETIME).
        pub create_time: i64,
        pub user_100ns: i64,
        pub kernel_100ns: i64,
        /// The image file name ("notepad.exe"; empty for the idle process).
        pub image_name: String,
        /// The private working set: the private memory that is resident.
        pub private_ws_bytes: u64,
        /// Page faults served from disk (the pageins of macOS's rusage).
        pub hard_faults: u32,
        pub threads: u32,
        /// Threads that were runnable but waiting for a core when the list was taken.
        pub ready_threads: u32,
    }

    impl Process {
        /// The start time in microseconds since the epoch (None for the system's own processes, which have none).
        pub fn start_us(&self) -> Option<u64> {
            filetime_to_unix_us(self.create_time)
        }

        pub fn cpu_s(&self) -> f64 {
            (self.user_100ns + self.kernel_100ns) as f64 / 1e7
        }
    }

    pub fn filetime_to_unix_us(ft: i64) -> Option<u64> {
        (ft > EPOCH_1601_TO_1970).then(|| ((ft - EPOCH_1601_TO_1970) / 10) as u64)
    }

    fn u32_at(b: &[u8], i: usize) -> Option<u32> {
        Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
    }

    fn u64_at(b: &[u8], i: usize) -> Option<u64> {
        Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?))
    }

    /// A UNICODE_STRING at `at` whose buffer pointer points into `buf` (allocated at address `base`).
    fn unicode_at(buf: &[u8], at: usize, base: usize) -> Option<String> {
        let len = u16::from_le_bytes(buf.get(at..at + 2)?.try_into().ok()?) as usize;
        let ptr = u64_at(buf, at + 8)? as usize;
        if len == 0 || ptr == 0 {
            return Some(String::new());
        }
        let off = ptr.checked_sub(base)?;
        let b = buf.get(off..off + len)?;
        let units: Vec<u16> = (0..len / 2)
            .map(|i| u16::from_le_bytes([b[2 * i], b[2 * i + 1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }

    /// Parse the buffer `NtQuerySystemInformation(SystemProcessInformation)` filled. `base` is the buffer's
    /// address: the image names' pointers point into it. A malformed entry ends the list.
    pub fn parse_processes(buf: &[u8], base: usize) -> Vec<Process> {
        use offsets::*;
        let mut out = vec![];
        let mut at = 0usize;
        while let Some(e) = buf.get(at..) {
            let (Some(next), Some(threads)) = (u32_at(e, NEXT_ENTRY), u32_at(e, NUMBER_OF_THREADS))
            else {
                break;
            };
            let ready = (0..threads as usize)
                .filter_map(|t| u32_at(e, PROCESS_SIZE + t * THREAD_SIZE + THREAD_STATE))
                .filter(|s| READY_STATES.contains(s))
                .count() as u32;
            let (Some(pid), Some(ppid), Some(session), Some(image_name)) = (
                u64_at(e, PROCESS_ID),
                u64_at(e, PARENT_ID),
                u32_at(e, SESSION_ID),
                unicode_at(buf, at + IMAGE_NAME, base),
            ) else {
                break;
            };
            out.push(Process {
                pid: pid as u32,
                ppid: ppid as u32,
                session,
                create_time: u64_at(e, CREATE_TIME).unwrap_or(0) as i64,
                user_100ns: u64_at(e, USER_TIME).unwrap_or(0) as i64,
                kernel_100ns: u64_at(e, KERNEL_TIME).unwrap_or(0) as i64,
                image_name,
                private_ws_bytes: u64_at(e, WORKING_SET_PRIVATE).unwrap_or(0),
                hard_faults: u32_at(e, HARD_FAULT_COUNT).unwrap_or(0),
                threads,
                ready_threads: ready,
            });
            if next == 0 {
                break;
            }
            at += next as usize;
        }
        out
    }

    /// Split a command line as `CommandLineToArgvW` (and the C runtime) do: arguments are separated by spaces
    /// or tabs; double quotes group; 2n backslashes before a quote are n backslashes and the quote toggles
    /// grouping, 2n+1 are n backslashes and a literal quote; other backslashes are literal; inside quotes a
    /// doubled quote is one literal quote. The program name (argv[0]) ends at the first space outside quotes,
    /// and backslashes in it are always literal.
    pub fn split_command_line(s: &str) -> Vec<String> {
        let chars: Vec<char> = s.chars().collect();
        let mut out = vec![];
        let mut i = 0;
        // argv[0]
        let mut arg = String::new();
        let mut quoted = false;
        while i < chars.len() {
            let c = chars[i];
            if c == '"' {
                quoted = !quoted;
            } else if (c == ' ' || c == '\t') && !quoted {
                break;
            } else {
                arg.push(c);
            }
            i += 1;
        }
        out.push(arg);
        loop {
            while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
                i += 1;
            }
            if i >= chars.len() {
                break;
            }
            let mut arg = String::new();
            let mut quoted = false;
            while i < chars.len() {
                let c = chars[i];
                if c == '\\' {
                    let start = i;
                    while i < chars.len() && chars[i] == '\\' {
                        i += 1;
                    }
                    let n = i - start;
                    if i < chars.len() && chars[i] == '"' {
                        arg.extend(std::iter::repeat_n('\\', n / 2));
                        if n % 2 == 1 {
                            arg.push('"');
                            i += 1;
                        }
                    } else {
                        arg.extend(std::iter::repeat_n('\\', n));
                    }
                    continue;
                }
                if c == '"' {
                    if quoted && chars.get(i + 1) == Some(&'"') {
                        arg.push('"');
                        i += 2;
                        continue;
                    }
                    quoted = !quoted;
                    i += 1;
                    continue;
                }
                if (c == ' ' || c == '\t') && !quoted {
                    break;
                }
                arg.push(c);
                i += 1;
            }
            out.push(arg);
        }
        out
    }

    /// A kernel path (`\Device\HarddiskVolume3\Windows\notepad.exe`) as a drive path, given the drives'
    /// devices (`("C:", "\Device\HarddiskVolume3")`, from QueryDosDeviceW). None when no drive holds it.
    pub fn dos_path(nt: &str, drives: &[(String, String)]) -> Option<String> {
        drives.iter().find_map(|(drive, device)| {
            let rest = nt.strip_prefix(device.as_str())?;
            rest.starts_with('\\').then(|| format!("{drive}{rest}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::procfs::*;
    use std::collections::HashMap;

    /// `/proc/<pid>/stat` of a Python process whose command holds a space and parentheses (Ubuntu 26.04, 7.0).
    const STAT: &str = "4242 (py (train) x) S 2171 4242 2171 34816 4242 4194304 18234 0 37 0 1520 230 0 0 20 0 9 0 \
                        482113 1201504256 61234 18446744073709551615 1 1 0 0 0 0 0 16781312 134235650 0 0 0 17 2 0 0 0 0 0";

    const STATUS: &str = "Name:\tpy (train) x\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4242\nNgid:\t0\nPid:\t4242\n\
        PPid:\t2171\nTracerPid:\t0\nUid:\t501\t501\t501\t501\nGid:\t1000\t1000\t1000\t1000\nFDSize:\t64\n\
        VmPeak:\t 1173344 kB\nVmSize:\t 1173344 kB\nVmRSS:\t  244936 kB\nRssAnon:\t  198124 kB\nRssFile:\t   46812 kB\n\
        RssShmem:\t       0 kB\nVmSwap:\t    1024 kB\nThreads:\t9\n";

    #[test]
    fn parses_stat_status_cmdline_and_schedstat() {
        let s = parse_stat(STAT).unwrap();
        assert_eq!(s.comm, "py (train) x");
        assert_eq!(
            (
                s.state,
                s.ppid,
                s.pgrp,
                s.tpgid,
                s.majflt,
                s.utime,
                s.stime,
                s.starttime
            ),
            ('S', 2171, 4242, 4242, 37, 1520, 230, 482113)
        );
        assert!(s.is_live_user_process());
        let kthread = parse_stat("2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 2 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 0 1 0 0 0 0 0").unwrap();
        assert!(!kthread.is_live_user_process());
        let zombie = parse_stat("77 (sh) Z 1 77 77 0 -1 4227084 0 0 0 0 0 0 0 0 20 0 1 0 9000 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0").unwrap();
        assert!(!zombie.is_live_user_process());
        assert_eq!(parse_stat("garbage"), None);

        let st = parse_status(STATUS).unwrap();
        assert_eq!(
            (st.uid, st.rss_anon_kb, st.rss_shmem_kb, st.vm_swap_kb),
            (501, 198_124, 0, 1024)
        );
        assert!((st.footprint_gb() - 199_148.0 / 1_048_576.0).abs() < 1e-12);
        assert_eq!(
            parse_status("Name:\tx\n"),
            None,
            "no Uid line: not a process status"
        );

        assert_eq!(
            parse_cmdline(b"python3\0train.py\0--lr\0\0"),
            ["python3", "train.py", "--lr", ""]
        );
        assert_eq!(
            parse_cmdline(b"python3\0train.py\0"),
            ["python3", "train.py"]
        );
        assert_eq!(parse_cmdline(b"retitled: worker 3"), ["retitled: worker 3"]);
        assert!(parse_cmdline(b"").is_empty());
        assert_eq!(
            parse_schedstat("3150483712 22510283 9123\n"),
            Some((3_150_483_712, 22_510_283))
        );
        assert_eq!(
            parse_btime("cpu  1 2 3\nbtime 1790000000\nprocesses 12\n"),
            Some(1_790_000_000)
        );
        assert_eq!(
            exe_path("/usr/bin/python3.13 (deleted)"),
            "/usr/bin/python3.13"
        );
    }

    #[test]
    fn counters_sum_threads_monotonically() {
        let mut c = Counters::new();
        let t = |v: &[(i32, u64, u64)]| {
            v.iter()
                .map(|&(t, r, w)| (t, (r, w)))
                .collect::<HashMap<_, _>>()
        };
        // first reading: everything so far counts
        let a = c.fold(
            10,
            500,
            t(&[(10, 2_000_000_000, 500_000_000), (11, 1_000_000_000, 0)]),
            3,
            1.0,
        );
        assert_eq!((a.cpu_s, a.runnable_s, a.pageins), (3.0, 3.5, 3.0));
        // thread 11 ended, thread 12 was born: 10 ran 1 s and waited 1 s more, 12 ran 0.5 s
        let b = c.fold(
            10,
            500,
            t(&[(10, 3_000_000_000, 1_500_000_000), (12, 500_000_000, 0)]),
            4,
            3.0,
        );
        assert_eq!((b.cpu_s, b.runnable_s), (4.5, 6.0));
        let d = b - a;
        assert_eq!(
            (d.cpu_s, d.runnable_s - d.cpu_s, d.instructions, d.cycles),
            (1.5, 1.0, 0.0, 0.0)
        );
        // a reused pid (another start time) starts over
        let r = c.fold(10, 900, t(&[(10, 100_000_000, 0)]), 0, 5.0);
        assert_eq!(r.cpu_s, 0.1);
        assert_eq!(
            c.fold(10, 900, t(&[(10, 150_000_000, 0)]), 0, 7.0).cpu_s,
            0.15
        );
        // a process not read for a minute is forgotten: its next reading starts over
        c.fold(11, 1, t(&[(11, 1, 0)]), 0, 100.0);
        assert_eq!(
            c.fold(10, 900, t(&[(10, 200_000_000, 0)]), 0, 101.0).cpu_s,
            0.2
        );
    }

    /// A `SystemProcessInformation` buffer as Windows lays it out: entries chained by NextEntryOffset, each
    /// followed by its threads, the image names (UTF-16) in the same buffer and pointed to by absolute address.
    fn nt_buffer(base: usize) -> Vec<u8> {
        use super::nt::offsets::*;
        let mut b = vec![0u8; 0x400];
        let put32 =
            |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let put64 =
            |b: &mut Vec<u8>, at: usize, v: u64| b[at..at + 8].copy_from_slice(&v.to_le_bytes());
        // entry 0 at 0: the idle process (pid 0, no name, no create time), no threads
        put32(&mut b, NEXT_ENTRY, 0x100);
        // entry 1 at 0x100: notepad.exe, pid 4321 in session 1, two threads (Ready, Waiting)
        let e = 0x100;
        put32(
            &mut b,
            e + NEXT_ENTRY,
            (PROCESS_SIZE + 2 * THREAD_SIZE) as u32,
        );
        put32(&mut b, e + NUMBER_OF_THREADS, 2);
        put64(&mut b, e + WORKING_SET_PRIVATE, 50 << 20);
        put32(&mut b, e + HARD_FAULT_COUNT, 12);
        put64(&mut b, e + CREATE_TIME, 134_355_356_307_331_278);
        put64(&mut b, e + USER_TIME, 25_000_000);
        put64(&mut b, e + KERNEL_TIME, 5_000_000);
        let name: Vec<u8> = "notepad.exe"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let name_at = 0x380;
        b[name_at..name_at + name.len()].copy_from_slice(&name);
        b[e + IMAGE_NAME..e + IMAGE_NAME + 2].copy_from_slice(&(name.len() as u16).to_le_bytes());
        put64(&mut b, e + IMAGE_NAME + 8, (base + name_at) as u64);
        put64(&mut b, e + PROCESS_ID, 4321);
        put64(&mut b, e + PARENT_ID, 900);
        put32(&mut b, e + SESSION_ID, 1);
        put32(&mut b, e + PROCESS_SIZE + THREAD_STATE, 1);
        put32(&mut b, e + PROCESS_SIZE + THREAD_SIZE + THREAD_STATE, 5);
        // entry 2: a third process, last (NextEntryOffset 0), in session 0
        let e = 0x100 + PROCESS_SIZE + 2 * THREAD_SIZE;
        b.resize(e + PROCESS_SIZE + 0x40, 0);
        put64(&mut b, e + PROCESS_ID, 4);
        put32(&mut b, e + SESSION_ID, 0);
        b
    }

    #[test]
    fn parses_the_windows_process_list() {
        let base = 0x7ff6_0000_0000usize;
        let p = super::nt::parse_processes(&nt_buffer(base), base);
        assert_eq!(p.len(), 3);
        assert_eq!(
            (p[0].pid, p[0].image_name.as_str(), p[0].start_us()),
            (0, "", None)
        );
        let n = &p[1];
        assert_eq!(
            (n.pid, n.ppid, n.session, n.image_name.as_str()),
            (4321, 900, 1, "notepad.exe")
        );
        assert_eq!(
            (
                n.threads,
                n.ready_threads,
                n.hard_faults,
                n.private_ws_bytes
            ),
            (2, 1, 12, 50 << 20)
        );
        assert_eq!(n.cpu_s(), 3.0);
        assert_eq!(n.start_us(), Some(1_791_062_030_733_127));
        assert_eq!((p[2].pid, p[2].session), (4, 0));
        // a list cut short ends at the last whole entry
        assert_eq!(
            super::nt::parse_processes(&nt_buffer(base)[..0x150], base).len(),
            1
        );
    }

    #[test]
    fn splits_command_lines_like_the_c_runtime() {
        use super::nt::split_command_line as split;
        assert_eq!(
            split(r#""C:\Program Files\Blender\blender.exe" --background scene.blend"#),
            [
                r"C:\Program Files\Blender\blender.exe",
                "--background",
                "scene.blend"
            ]
        );
        assert_eq!(
            split(r#"python.exe train.py "a b" c\d"#),
            ["python.exe", "train.py", "a b", r"c\d"]
        );
        // backslashes before a quote halve; an odd one escapes the quote
        assert_eq!(
            split(r#"x a\\"b c" d\"e f\\\"g"#),
            ["x", r"a\b c", r#"d"e"#, r#"f\"g"#]
        );
        // a doubled quote inside quotes is one quote
        assert_eq!(split(r#"x "say ""hi"" now""#), ["x", r#"say "hi" now"#]);
        // argv[0]'s backslashes are literal, tabs separate, trailing blanks end nothing
        assert_eq!(split("C:\\tools\\a.exe\t-v   "), [r"C:\tools\a.exe", "-v"]);
        assert_eq!(split(""), [""]);
    }

    #[test]
    fn maps_kernel_paths_to_drives() {
        use super::nt::dos_path;
        let drives = vec![
            ("C:".to_string(), r"\Device\HarddiskVolume3".to_string()),
            ("D:".to_string(), r"\Device\HarddiskVolume13".to_string()),
        ];
        assert_eq!(
            dos_path(r"\Device\HarddiskVolume3\Windows\notepad.exe", &drives).as_deref(),
            Some(r"C:\Windows\notepad.exe")
        );
        assert_eq!(
            dos_path(r"\Device\HarddiskVolume13\x.exe", &drives).as_deref(),
            Some(r"D:\x.exe")
        );
        assert_eq!(
            dos_path(r"\Device\HarddiskVolume31\x.exe", &drives),
            None,
            "a longer volume number is another device"
        );
        assert_eq!(dos_path(r"\Device\Mup\server\share\x.exe", &drives), None);
    }

    /// A procfs tree as it looks for two of the owner's processes, another account's (whose `exe` may not be
    /// read: here a dangling link stands in for EACCES, which a fixture cannot produce), a zombie and a kernel
    /// thread.
    #[cfg(unix)]
    #[test]
    fn reads_a_procfs_tree() {
        use std::collections::HashSet;
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("oarbank-procfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mk = |pid: i32, stat: &str, uid: u32, exe: Option<&str>, cmdline: &[u8]| {
            let d = root.join(pid.to_string());
            std::fs::create_dir_all(d.join("task").join(pid.to_string())).unwrap();
            std::fs::write(d.join("stat"), stat).unwrap();
            std::fs::write(
                d.join("status"),
                STATUS.replace("Uid:\t501\t501", &format!("Uid:\t{uid}\t{uid}")),
            )
            .unwrap();
            std::fs::write(d.join("cmdline"), cmdline).unwrap();
            std::fs::write(
                d.join("task").join(pid.to_string()).join("schedstat"),
                "2000000000 1000000000 5\n",
            )
            .unwrap();
            if let Some(e) = exe {
                symlink(e, d.join("exe")).unwrap();
            }
        };
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("stat"), "cpu  1 2 3\nbtime 1790000000\n").unwrap();
        mk(
            4242,
            STAT,
            501,
            Some("/opt/trainer/bin/py (deleted)"),
            b"python3\0train.py\0",
        );
        mk(
            4300,
            &STAT.replace("4242 (py (train) x)", "4300 (bash)"),
            501,
            Some("/usr/bin/bash"),
            b"bash\0",
        );
        mk(
            5000,
            &STAT.replace("4242 (py (train) x)", "5000 (other)"),
            1000,
            Some("/usr/bin/other"),
            b"other\0",
        );
        mk(77, "77 (sh) Z 1 77 77 0 -1 4227084 0 0 0 0 0 0 0 0 20 0 1 0 9000 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0", 501, None, b"");
        let r = Reader::new(&root, 100);
        let mine = r.list(|uid| uid == 501, &HashSet::from([4300])).unwrap();
        assert_eq!(mine.len(), 1, "{mine:?}"); // the excluded pid, the other account's and the zombie are not listed
        let p = &mine[0];
        assert_eq!(
            (p.pid, p.ppid, p.uid, p.comm.as_str()),
            (4242, 2171, 501, "py (train) x")
        );
        assert_eq!(p.path.as_deref(), Some("/opt/trainer/bin/py"));
        assert_eq!(p.start_us, 1_790_000_000_000_000 + 4_821_130_000);
        assert_eq!(p.cpu_s, 17.5);
        assert_eq!(r.start_time_us(4242), Some(p.start_us));
        assert_eq!(r.cmdline(4242).unwrap(), ["python3", "train.py"]);
        assert_eq!(
            r.threads(4242).unwrap(),
            HashMap::from([(4242, (2_000_000_000, 1_000_000_000))])
        );
        // both accounts when the owner rule takes both
        assert_eq!(r.list(|_| true, &HashSet::new()).unwrap().len(), 3);
        // gone: no stat, no start time
        assert_eq!(r.start_time_us(9999), None);
        let _ = std::fs::remove_dir_all(&root);
    }
}
