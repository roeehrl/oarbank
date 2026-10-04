//! Platform primitives (docs/design/architecture.md, "Host interfaces"): the account, the host name, free disk, and
//! process containers. A job or service runs in a container the agent created and signals as a whole: a
//! process group (setsid) on Unix, a Job Object on Windows. Callers name a container by its leader's pid.

use std::path::Path;

/// What the agent asks of a process container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sig {
    /// Ask to stop (Unix SIGTERM; Windows has no such request for a whole container: it terminates).
    Term,
    Kill,
    /// Freeze and thaw every member: host protection's pause on Linux and Windows (prot.rs; on macOS protection
    /// signals through its own actuator).
    #[cfg(not(target_os = "macos"))]
    Stop,
    #[cfg(not(target_os = "macos"))]
    Cont,
}

#[cfg(unix)]
mod imp {
    use super::Sig;
    use std::io;
    use std::path::Path;

    pub fn uid() -> u32 {
        unsafe { libc::getuid() }
    }

    pub fn hostname() -> String {
        let mut buf = [0u8; 256];
        unsafe {
            if libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) == 0 {
                let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                return String::from_utf8_lossy(&buf[..n]).to_string();
            }
        }
        "unknown".into()
    }

    /// The local zone's offset from UTC at a Unix time, in seconds (0 where the zone cannot be read).
    pub fn utc_offset_s(t: i64) -> i64 {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let tt = t as libc::time_t;
        if unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() { 0 } else { tm.tm_gmtoff as i64 }
    }

    pub fn disk_free_gb(path: &Path) -> Option<f64> {
        let c = std::ffi::CString::new(path.to_string_lossy().as_bytes()).ok()?;
        unsafe {
            let mut s: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c.as_ptr(), &mut s) != 0 {
                return None;
            }
            Some((s.f_bavail as f64) * (s.f_frsize as f64) / 1e9)
        }
    }

    /// The child leads a new session and process group and, on Linux with a delegated cgroup, enters a container of
    /// its own (cgroup.rs `Placement`): both between the fork and the exec, so its first instruction, and everything it
    /// starts, are already inside.
    pub(super) fn new_group(cmd: &mut std::process::Command) {
        use std::os::unix::process::CommandExt;
        #[cfg(target_os = "linux")]
        let placement = crate::cgroup::placement();
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                #[cfg(target_os = "linux")]
                if let Some(p) = &placement {
                    p.enter()?;
                }
                Ok(())
            });
        }
    }

    /// Hard limits on the container (Linux cgroups; nothing on macOS, where admission control is the limit).
    pub fn limit(pgid: i32, cores: f64, mem_gb: f64) -> bool {
        #[cfg(target_os = "linux")]
        return crate::cgroup::limit(pgid, cores, mem_gb);
        #[allow(unreachable_code)]
        {
            let _ = (pgid, cores, mem_gb);
            false
        }
    }

    /// The OS ended a member for exceeding the container's memory limit.
    pub fn oom(pgid: i32) -> bool {
        #[cfg(target_os = "linux")]
        return crate::cgroup::oom_killed(pgid);
        #[allow(unreachable_code)]
        {
            let _ = pgid;
            false
        }
    }

    /// Lower a container's processes to background scheduling, or restore them (host protection's lowering on
    /// Linux: the container's background CPU quota, cgroup.rs; none without a delegated cgroup).
    #[cfg(target_os = "linux")]
    pub fn set_background(pgid: i32, on: bool) -> bool {
        crate::cgroup::background(pgid, on)
    }

    /// Whether this node can lower its jobs (Linux: only with a delegated cgroup that has the cpu controller).
    #[cfg(target_os = "linux")]
    pub fn can_lower() -> bool {
        crate::cgroup::cpu_controller()
    }

    /// The agent is done with the container (its leader ended and was reaped).
    pub fn release(pgid: i32) {
        #[cfg(target_os = "linux")]
        crate::cgroup::release(pgid);
        let _ = pgid;
    }

    /// A job's nudge to re-read control.json (runner protocol 1, "Control"): SIGUSR1 to the container's leader, the
    /// runner, only. Its children are never sent one: they did not ask for it, and an exec resets a handled signal to
    /// its default action, which ends them. The runner starts with SIGUSR1 ignored, so a nudge that comes before it has
    /// installed its handler is lost harmlessly: a runner installs its handler, then reads the document.
    pub struct Nudge;

    impl Nudge {
        pub fn new() -> io::Result<Nudge> {
            Ok(Nudge)
        }

        /// The runner's command: SIGUSR1 ignored from its first instruction (an ignored disposition survives exec).
        pub fn prepare(&self, cmd: &mut std::process::Command) {
            use std::os::unix::process::CommandExt;
            unsafe {
                cmd.pre_exec(|| {
                    if libc::signal(libc::SIGUSR1, libc::SIG_IGN) == libc::SIG_ERR {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }

        pub fn send(&self, leader: i32) -> bool {
            leader > 1 && unsafe { libc::kill(leader, libc::SIGUSR1) == 0 }
        }
    }

    pub fn signal_group(pgid: i32, sig: Sig) -> bool {
        if pgid <= 1 {
            return false;
        }
        #[cfg(target_os = "linux")]
        match sig {
            Sig::Kill if crate::cgroup::kill(pgid) => return true,
            Sig::Stop if crate::cgroup::freeze(pgid, true) => return true,
            Sig::Cont if crate::cgroup::freeze(pgid, false) => return true,
            _ => {}
        }
        let s = match sig {
            Sig::Term => libc::SIGTERM,
            Sig::Kill => libc::SIGKILL,
            #[cfg(target_os = "linux")]
            Sig::Stop => libc::SIGSTOP,
            #[cfg(target_os = "linux")]
            Sig::Cont => libc::SIGCONT,
        };
        unsafe { libc::killpg(pgid, s) == 0 }
    }

    #[cfg(test)]
    pub fn alive(pid: i32) -> bool {
        pid > 0 && unsafe { libc::kill(pid, 0) == 0 }
    }

    /// Whether any member of the group is alive (a group we may not signal still counts).
    pub fn group_alive(pgid: i32) -> bool {
        #[cfg(target_os = "linux")]
        if let Some(p) = crate::cgroup::pids(pgid) {
            return !p.is_empty();
        }
        pgid > 1 && unsafe { libc::kill(-pgid, 0) == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) }
    }

    /// The exit was a signal (for faults: killed rather than failed).
    pub fn exit_signal(st: &std::process::ExitStatus) -> Option<i32> {
        use std::os::unix::process::ExitStatusExt;
        st.signal()
    }
}

#[cfg(windows)]
mod imp {
    use super::Sig;
    use std::collections::HashMap;
    use std::io;
    use std::path::Path;
    use std::sync::Mutex;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, STILL_ACTIVE};
    use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicProcessIdList,
                                                 QueryInformationJobObject, TerminateJobObject, JOBOBJECT_BASIC_PROCESS_ID_LIST};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                                                PROCESS_SET_QUOTA, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE};

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSuspendProcess(h: HANDLE) -> i32;
        fn NtResumeProcess(h: HANDLE) -> i32;
    }

    /// Leader pid → its Job Object (a HANDLE kept as usize so the map is Send).
    static JOBS: Mutex<Option<HashMap<i32, usize>>> = Mutex::new(None);

    fn job_of(pgid: i32) -> Option<HANDLE> {
        JOBS.lock().unwrap().as_ref().and_then(|m| m.get(&pgid).copied()).map(|h| h as HANDLE)
    }

    pub fn uid() -> u32 {
        0
    }

    pub fn hostname() -> String {
        use windows_sys::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};
        let mut buf = [0u16; 256];
        let mut n = buf.len() as u32;
        if unsafe { GetComputerNameExW(ComputerNameDnsHostname, buf.as_mut_ptr(), &mut n) } != 0 {
            return String::from_utf16_lossy(&buf[..n as usize]);
        }
        "unknown".into()
    }

    pub fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// The local zone's offset from UTC at a Unix time, in seconds (0 where the zone cannot be read).
    pub fn utc_offset_s(t: i64) -> i64 {
        use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
        use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToFileTime, SystemTimeToTzSpecificLocalTime};
        let ticks = (t + 11_644_473_600) * 10_000_000;                   // 100 ns since 1601
        let ft = FILETIME { dwLowDateTime: ticks as u32, dwHighDateTime: (ticks >> 32) as u32 };
        unsafe {
            let (mut utc, mut local): (SYSTEMTIME, SYSTEMTIME) = (std::mem::zeroed(), std::mem::zeroed());
            let mut back: FILETIME = std::mem::zeroed();
            if FileTimeToSystemTime(&ft, &mut utc) == 0 || SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) == 0
                || SystemTimeToFileTime(&local, &mut back) == 0 {
                return 0;
            }
            ((((back.dwHighDateTime as i64) << 32) | back.dwLowDateTime as i64) - ticks) / 10_000_000
        }
    }

    pub fn disk_free_gb(path: &Path) -> Option<f64> {
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        let w = wide(path.as_os_str());
        let mut free: u64 = 0;
        (unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut free, std::ptr::null_mut(), std::ptr::null_mut()) } != 0)
            .then_some(free as f64 / 1e9)
    }

    /// A child with no console at all (its output goes to the handles it is given): a console, even a hidden one,
    /// starts a conhost.exe beside the child, inside its Job Object, and outside the AppContainer, so a sandboxed
    /// runner would never come up confined (sandbox_windows.rs `is_confined`).
    const CHILD_FLAGS: u32 = 0x0000_0200 /* CREATE_NEW_PROCESS_GROUP */ | 0x0000_0008 /* DETACHED_PROCESS */;

    /// The child starts suspended: no instruction of it runs before `contain` has put it in its Job Object.
    pub(super) fn new_group(cmd: &mut std::process::Command) {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
        cmd.creation_flags(CHILD_FLAGS | CREATE_SUSPENDED);
    }

    /// Put the suspended leader in a Job Object of its own, then let it run: every process it starts is born in the
    /// job (no breakaway is allowed), so the chain agent -> sandbox-exec shim -> runner -> its children never runs a
    /// line outside it. `lasting`: the job outlives the agent (a module service, adopted again after a restart);
    /// otherwise it dies with the agent, as attempts do not survive an agent restart.
    pub(super) fn contain(pid: u32, lasting: bool) -> io::Result<()> {
        adopt_job(pid, !lasting)?;
        resume(pid)
    }

    /// Resume the threads of a process started suspended (it has one, its first).
    fn resume(pid: u32) -> io::Result<()> {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD,
                                                                THREADENTRY32};
        use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let mut e: THREADENTRY32 = std::mem::zeroed();
            e.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            let mut resumed = 0;
            let mut more = Thread32First(snap, &mut e) != 0;
            while more {
                if e.th32OwnerProcessID == pid {
                    let t = OpenThread(THREAD_SUSPEND_RESUME, 0, e.th32ThreadID);
                    if !t.is_null() {
                        if ResumeThread(t) != u32::MAX {
                            resumed += 1;
                        }
                        CloseHandle(t);
                    }
                }
                more = Thread32Next(snap, &mut e) != 0;
            }
            CloseHandle(snap);
            if resumed == 0 {
                return Err(io::Error::other(format!("no thread of process {pid} to resume")));
            }
        }
        Ok(())
    }

    fn adopt_job(pid: u32, kill_on_close: bool) -> io::Result<()> {
        use windows_sys::Win32::System::JobObjects::{JobObjectExtendedLimitInformation, SetInformationJobObject,
                                                     JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE};
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            if kill_on_close {
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info as *const _ as *const _,
                                        std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32);
            }
            let p = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
            if p.is_null() {
                CloseHandle(job);
                return Err(io::Error::last_os_error());
            }
            let ok = AssignProcessToJobObject(job, p);
            CloseHandle(p);
            if ok == 0 {
                let e = io::Error::last_os_error();
                CloseHandle(job);
                return Err(e);
            }
            JOBS.lock().unwrap().get_or_insert_with(HashMap::new).insert(pid as i32, job as usize);
        }
        Ok(())
    }

    /// Put another process in the container's job (a test stands in for an escape with it).
    #[cfg(test)]
    pub fn join(pgid: i32, pid: u32) -> io::Result<()> {
        let job = job_of(pgid).ok_or_else(|| io::Error::other("no such container"))?;
        unsafe {
            let p = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
            if p.is_null() {
                return Err(io::Error::last_os_error());
            }
            let ok = AssignProcessToJobObject(job, p);
            CloseHandle(p);
            if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
        }
    }

    /// How many processes have ever been in the container (alive or not): its job's accounting.
    #[cfg(test)]
    pub fn processes_ever(pgid: i32) -> Option<u32> {
        use windows_sys::Win32::System::JobObjects::{JobObjectBasicAccountingInformation, QueryInformationJobObject,
                                                     JOBOBJECT_BASIC_ACCOUNTING_INFORMATION};
        let job = job_of(pgid)?;
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe { QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &mut info as *mut _ as *mut _,
                                                    std::mem::size_of_val(&info) as u32, std::ptr::null_mut()) };
        (ok != 0).then_some(info.TotalProcesses)
    }

    /// Whether process `pid` is in the container led by `pgid` (its Job Object; checked on the process's own handle, so
    /// a recycled pid is never taken for a member).
    pub fn in_container(pgid: i32, pid: u32) -> bool {
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
        let Some(job) = job_of(pgid) else { return false };
        unsafe {
            let p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if p.is_null() {
                return false;
            }
            let mut inside = 0;
            let ok = IsProcessInJob(p, job, &mut inside);
            CloseHandle(p);
            ok != 0 && inside != 0
        }
    }

    pub fn release(pgid: i32) {
        if let Some(h) = JOBS.lock().unwrap().as_mut().and_then(|m| m.remove(&pgid)) {
            unsafe { CloseHandle(h as HANDLE) };
        }
    }

    pub fn group_pids(pgid: i32) -> Vec<i32> {
        let Some(job) = job_of(pgid) else { return if alive(pgid) { vec![pgid] } else { vec![] } };
        // the list struct ends in a one-element array: ask with room for 1024 processes
        let mut buf = vec![0usize; 2 + 1024];
        let ok = unsafe {
            QueryInformationJobObject(job, JobObjectBasicProcessIdList, buf.as_mut_ptr() as *mut _,
                                      (buf.len() * std::mem::size_of::<usize>()) as u32, std::ptr::null_mut())
        };
        if ok == 0 {
            return vec![];
        }
        let n = unsafe { &*(buf.as_ptr() as *const JOBOBJECT_BASIC_PROCESS_ID_LIST) }.NumberOfProcessIdsInList as usize;
        // the ids start after the two u32 counts: one usize in, on 64-bit Windows
        let first = std::mem::offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList) / std::mem::size_of::<usize>();
        buf[first..first + n.min(1024)].iter().map(|&p| p as i32).collect()
    }

    fn each_member(pgid: i32, access: u32, f: impl Fn(HANDLE) -> bool) -> bool {
        let mut any = false;
        for pid in group_pids(pgid) {
            let h = unsafe { OpenProcess(access, 0, pid as u32) };
            if !h.is_null() {
                any |= f(h);
                unsafe { CloseHandle(h) };
            }
        }
        any
    }

    pub fn signal_group(pgid: i32, sig: Sig) -> bool {
        if pgid <= 0 {
            return false;
        }
        match sig {
            Sig::Term | Sig::Kill => match job_of(pgid) {
                Some(job) => unsafe { TerminateJobObject(job, 1) != 0 },
                None => each_member(pgid, PROCESS_TERMINATE, |h| unsafe { TerminateProcess(h, 1) != 0 }),
            },
            Sig::Stop => each_member(pgid, PROCESS_SUSPEND_RESUME, |h| unsafe { NtSuspendProcess(h) } >= 0),
            Sig::Cont => each_member(pgid, PROCESS_SUSPEND_RESUME, |h| unsafe { NtResumeProcess(h) } >= 0),
        }
    }

    /// Where the runner finds its control event: the handle's value, in decimal.
    pub const CONTROL_EVENT_ENV: &str = "OARBANK_CONTROL_EVENT";

    /// A job's nudge to re-read control.json (runner protocol 1, "Control"): an unnamed auto-reset event whose handle
    /// is inheritable, named to the runner by OARBANK_CONTROL_EVENT. The runner inherits it through the sandbox shim,
    /// which passes it (and the standard handles) on and nothing else; access was checked when the event was created,
    /// so an AppContainer runner can wait on the inherited handle. A nudge that comes before the runner waits stays
    /// set until it does. Closed when the job ends.
    pub struct Nudge {
        event: usize,
    }

    impl Nudge {
        pub fn new() -> io::Result<Nudge> {
            use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
            use windows_sys::Win32::System::Threading::CreateEventW;
            let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                                           lpSecurityDescriptor: std::ptr::null_mut(), bInheritHandle: 1 };
            let h = unsafe { CreateEventW(&sa, 0, 0, std::ptr::null()) };
            if h.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Nudge { event: h as usize })
        }

        /// The runner's command (after its environment is set): the event's handle in OARBANK_CONTROL_EVENT. The
        /// agent's CreateProcess inherits every inheritable handle, the event among them.
        pub fn prepare(&self, cmd: &mut std::process::Command) {
            cmd.env(CONTROL_EVENT_ENV, self.event.to_string());
        }

        pub fn send(&self, _leader: i32) -> bool {
            use windows_sys::Win32::System::Threading::SetEvent;
            unsafe { SetEvent(self.event as HANDLE) != 0 }
        }
    }

    impl Drop for Nudge {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.event as HANDLE) };
        }
    }

    pub fn alive(pid: i32) -> bool {
        if pid <= 0 {
            return false;
        }
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
            if h.is_null() {
                return GetLastError() == 5;               // ERROR_ACCESS_DENIED: it exists, we may not look
            }
            let mut code = 0u32;
            let ok = GetExitCodeProcess(h, &mut code);
            CloseHandle(h);
            ok != 0 && code == STILL_ACTIVE as u32
        }
    }

    pub fn group_alive(pgid: i32) -> bool {
        !group_pids(pgid).is_empty()
    }

    /// Hard limits on the Job Object: the job's committed memory and a CPU rate cap of `cores` of the machine's.
    pub fn limit(pgid: i32, cores: f64, mem_gb: f64) -> bool {
        use windows_sys::Win32::System::JobObjects::{JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation,
                                                     SetInformationJobObject, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
                                                     JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
                                                     JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_JOB_MEMORY};
        let Some(job) = job_of(pgid) else { return false };
        let mut ok = true;
        unsafe {
            if mem_gb > 0.0 {
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                let mut len = 0u32;
                QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &mut info as *mut _ as *mut _,
                                          std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32, &mut len);
                info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
                info.JobMemoryLimit = (mem_gb * 1073741824.0) as usize;
                ok &= SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info as *const _ as *const _,
                                              std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32) != 0;
            }
            if cores > 0.0 {
                let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as f64;
                let mut cr: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = std::mem::zeroed();
                cr.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
                cr.Anonymous.CpuRate = ((cores / n).min(1.0) * 10_000.0).max(1.0) as u32;
                ok &= SetInformationJobObject(job, JobObjectCpuRateControlInformation, &cr as *const _ as *const _,
                                              std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32) != 0;
            }
        }
        ok
    }

    /// Lower a container's processes to background scheduling, or restore them (host protection's lowering on
    /// Windows): the Job Object's priority class limit, idle while lowered (every member, and children started
    /// later), and EcoQoS on each member (efficiency cores and lower clocks on hybrid CPUs). Restoring forces the
    /// normal class back, then lifts the limit.
    pub fn set_background(pgid: i32, on: bool) -> bool {
        use windows_sys::Win32::System::JobObjects::{JobObjectExtendedLimitInformation, SetInformationJobObject,
                                                     JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_PRIORITY_CLASS};
        use windows_sys::Win32::System::Threading::{ProcessPowerThrottling, SetPriorityClass, SetProcessInformation,
                                                    IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS, PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                                                    PROCESS_POWER_THROTTLING_EXECUTION_SPEED, PROCESS_POWER_THROTTLING_STATE,
                                                    PROCESS_SET_INFORMATION};
        let class = if on { IDLE_PRIORITY_CLASS } else { NORMAL_PRIORITY_CLASS };
        let size = std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
        let ok = match job_of(pgid) {
            Some(job) => unsafe {
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                let mut len = 0u32;
                QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &mut info as *mut _ as *mut _, size, &mut len) != 0 && {
                    info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PRIORITY_CLASS;
                    info.BasicLimitInformation.PriorityClass = class;
                    let set = SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info as *const _ as *const _, size) != 0;
                    if !on {
                        info.BasicLimitInformation.LimitFlags &= !JOB_OBJECT_LIMIT_PRIORITY_CLASS;
                        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info as *const _ as *const _, size);
                    }
                    set
                }
            },
            None => each_member(pgid, PROCESS_SET_INFORMATION, |h| unsafe { SetPriorityClass(h, class) != 0 }),
        };
        // EcoQoS where the OS has it (Windows 11, 10 21H2): a request, so a refusal is no failure
        let state = PROCESS_POWER_THROTTLING_STATE {
            Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask: if on { PROCESS_POWER_THROTTLING_EXECUTION_SPEED } else { 0 },
            StateMask: if on { PROCESS_POWER_THROTTLING_EXECUTION_SPEED } else { 0 },
        };
        each_member(pgid, PROCESS_SET_INFORMATION, |h| unsafe {
            SetProcessInformation(h, ProcessPowerThrottling, &state as *const _ as *const _,
                                  std::mem::size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32) != 0
        });
        ok
    }

    /// Job Objects can always lower their members.
    pub fn can_lower() -> bool {
        true
    }

    /// The job hit its memory limit (the Job Object refuses the allocation; the process usually fails then).
    pub fn oom(pgid: i32) -> bool {
        use windows_sys::Win32::System::JobObjects::{JobObjectLimitViolationInformation, JOBOBJECT_LIMIT_VIOLATION_INFORMATION,
                                                     JOB_OBJECT_LIMIT_JOB_MEMORY};
        let Some(job) = job_of(pgid) else { return false };
        let mut v: JOBOBJECT_LIMIT_VIOLATION_INFORMATION = unsafe { std::mem::zeroed() };
        let mut len = 0u32;
        let ok = unsafe { QueryInformationJobObject(job, JobObjectLimitViolationInformation, &mut v as *mut _ as *mut _,
                                                    std::mem::size_of::<JOBOBJECT_LIMIT_VIOLATION_INFORMATION>() as u32, &mut len) } != 0;
        ok && v.ViolationLimitFlags & JOB_OBJECT_LIMIT_JOB_MEMORY != 0
    }
}

pub use imp::*;

/// Start `cmd` as the leader of a process container of its own, in it before it runs a line, so nothing it starts is
/// ever outside: a process group and, on Linux with a delegated cgroup, a cgroup, both entered between fork and exec;
/// on Windows a Job Object (started suspended, put in the job, resumed). When the container cannot be made the spawn
/// fails (on Windows the child is killed before it ran).
/// `lasting`: the container outlives the agent (a module service).
pub fn spawn_contained(cmd: &mut std::process::Command, lasting: bool) -> std::io::Result<std::process::Child> {
    imp::new_group(cmd);
    #[allow(unused_mut)]
    let mut child = cmd.spawn()?;
    #[cfg(windows)]
    if let Err(e) = imp::contain(child.id(), lasting) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(std::io::Error::other(format!("process container: {e}")));
    }
    #[cfg(unix)]
    let _ = lasting;
    Ok(child)
}

/// `spawn_contained` for a tokio command.
pub fn spawn_contained_async(cmd: &mut tokio::process::Command, lasting: bool) -> std::io::Result<tokio::process::Child> {
    imp::new_group(cmd.as_std_mut());
    #[allow(unused_mut)]
    let mut child = cmd.spawn()?;
    #[cfg(windows)]
    if let Err(e) = imp::contain(child.id().unwrap_or(0), lasting) {
        let _ = child.start_kill();
        return Err(std::io::Error::other(format!("process container: {e}")));
    }
    #[cfg(unix)]
    let _ = lasting;
    Ok(child)
}

/// The pids in a container: the members of a Job Object on Windows; on Unix, the cgroup leaf (Linux, when
/// delegated) or the process group.
#[cfg(unix)]
pub fn group_pids(pgid: i32) -> Vec<i32> {
    #[cfg(target_os = "linux")]
    if let Some(p) = crate::cgroup::pids(pgid) {
        return p;
    }
    crate::procs::unix_group_pids(pgid)
}

/// The minimal environment a child process needs from the OS, beyond what the agent sets: a system PATH, the home,
/// the temporary directory. Windows programs (Python included) also need SystemRoot and friends to start at all.
pub fn os_env(home: &Path, tmp: &Path) -> Vec<(String, String)> {
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let mut v = vec![("PATH".to_string(), format!(r"{root}\System32;{root};{root}\System32\WindowsPowerShell\v1.0")),
                         ("SystemRoot".into(), root.clone()), ("windir".into(), root),
                         ("USERPROFILE".into(), home.display().to_string()), ("TEMP".into(), tmp.display().to_string()),
                         ("TMP".into(), tmp.display().to_string()),
                         // CreateProcess for an AppContainer rewrites LOCALAPPDATA to the container's folder and fails
                         // with ERROR_ENVVAR_NOT_FOUND (203) when it is missing.
                         ("LOCALAPPDATA".into(), home.join(r"AppData\Local").display().to_string())];
        for k in ["SystemDrive", "ComSpec", "PATHEXT", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE"] {
            if let Ok(val) = std::env::var(k) {
                v.push((k.into(), val));
            }
        }
        v
    } else {
        vec![("PATH".into(), "/usr/bin:/bin:/usr/sbin:/sbin".into()), ("HOME".into(), home.display().to_string()),
             ("TMPDIR".into(), format!("{}/", tmp.display()))]
    }
}


#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The file's text once it has some (a loaded host may take seconds to start a Python: up to 30 s).
    fn wait_for(path: &Path) -> String {
        for _ in 0..600 {
            if let Some(s) = std::fs::read_to_string(path).ok().filter(|s| !s.is_empty()) {
                return s;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        String::new()
    }

    /// A Python leader (a shell cannot trap a signal that was ignored when it started, as SIGUSR1 is for runners).
    fn python(dir: &Path, script: &str) -> (std::process::Child, Nudge) {
        let mut cmd = std::process::Command::new("python3");
        cmd.args(["-I", "-c", script]).arg(dir);
        let nudge = Nudge::new().unwrap();
        nudge.prepare(&mut cmd);
        (spawn_contained(&mut cmd, false).unwrap(), nudge)
    }

    /// The nudge reaches the runner only: its children did not ask for it, and SIGUSR1's default action (an exec
    /// resets a handled signal to it) ends them.
    #[test]
    fn the_nudge_reaches_the_leader_and_spares_its_children() {
        let dir = std::env::temp_dir().join(format!("oarbank-nudge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (mut leader, nudge) = python(&dir, "import pathlib, signal, subprocess, sys, time\n\
            d = pathlib.Path(sys.argv[1])\n\
            signal.signal(signal.SIGUSR1, lambda *_: (d / 'runner.log').write_text('nudged'))\n\
            (d / 'child.pid').write_text(str(subprocess.Popen(['/bin/sleep', '30']).pid))\n\
            while True: time.sleep(0.05)\n");
        let pgid = leader.id() as i32;
        let child: i32 = wait_for(&dir.join("child.pid")).trim().parse().unwrap_or(0);
        assert!(child > 0);
        assert!(nudge.send(pgid));
        assert!(wait_for(&dir.join("runner.log")).contains("nudged"));
        assert!(alive(child), "the child must survive the nudge");
        signal_group(pgid, Sig::Kill);
        let _ = leader.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A nudge before the runner has installed its handler is lost, not fatal: the runner starts with SIGUSR1 ignored.
    #[test]
    fn a_nudge_before_the_handler_is_harmless() {
        let dir = std::env::temp_dir().join(format!("oarbank-early-nudge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (mut leader, nudge) = python(&dir, "import pathlib, signal, sys, time\n\
            d = pathlib.Path(sys.argv[1])\n\
            (d / 'started').write_text('1')\n\
            time.sleep(0.5)\n\
            signal.signal(signal.SIGUSR1, lambda *_: (d / 'runner.log').write_text('nudged'))\n\
            (d / 'ready').write_text('1')\n\
            while True: time.sleep(0.05)\n");
        let pid = leader.id() as i32;
        assert!(!wait_for(&dir.join("started")).is_empty());
        assert!(nudge.send(pid));                                    // before the handler: ignored
        assert!(!wait_for(&dir.join("ready")).is_empty(), "the early nudge ended the runner");
        assert!(leader.try_wait().unwrap().is_none());
        assert!(nudge.send(pid));                                    // after it: handled
        assert!(wait_for(&dir.join("runner.log")).contains("nudged"));
        signal_group(pid, Sig::Kill);
        let _ = leader.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    /// The event a prepared command names in OARBANK_CONTROL_EVENT.
    pub fn event_of(cmd: &std::process::Command) -> HANDLE {
        let v = cmd.get_envs().find(|(k, _)| *k == CONTROL_EVENT_ENV).and_then(|(_, v)| v).expect("OARBANK_CONTROL_EVENT is set");
        v.to_str().unwrap().parse::<usize>().unwrap() as HANDLE
    }

    #[test]
    fn the_control_event_is_inheritable_named_in_the_environment_and_auto_reset() {
        let nudge = Nudge::new().unwrap();
        let mut cmd = std::process::Command::new("cmd.exe");
        nudge.prepare(&mut cmd);
        let h = event_of(&cmd);
        let mut flags = 0u32;
        assert!(unsafe { GetHandleInformation(h, &mut flags) } != 0);
        assert!(flags & HANDLE_FLAG_INHERIT != 0, "the runner must be able to inherit the event");
        assert_eq!(unsafe { WaitForSingleObject(h, 0) }, WAIT_TIMEOUT);
        assert!(nudge.send(0));
        assert_eq!(unsafe { WaitForSingleObject(h, 0) }, WAIT_OBJECT_0);
        assert_eq!(unsafe { WaitForSingleObject(h, 0) }, WAIT_TIMEOUT, "one nudge wakes one wait");
    }

    /// A console child brings a conhost.exe into its Job Object; with none, the job holds the child alone (a
    /// sandboxed runner's job must hold only AppContainer processes besides the shim).
    #[test]
    fn a_new_group_runs_without_a_console_host_in_its_job() {
        let ping = format!(r"{}\System32\PING.EXE", std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()));
        let mut cmd = std::process::Command::new(ping);
        cmd.args(["-n", "4", "127.0.0.1"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        let mut child = spawn_contained(&mut cmd, false).unwrap();
        let pid = child.id();
        std::thread::sleep(std::time::Duration::from_millis(1000));
        let members = group_pids(pid as i32);
        signal_group(pid as i32, Sig::Kill);
        let _ = child.wait();
        assert_eq!(members, vec![pid as i32], "only the child itself, no console host");
    }

    /// A contained process runs no instruction before it is in its Job Object: started suspended, it has not made its
    /// file a second later; once contained it runs, and it is in the job.
    #[test]
    fn a_contained_process_runs_nothing_before_its_job() {
        let d = std::env::temp_dir().join(format!("oarbank-suspended-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mark = d.join("ran");
        let cmd_exe = format!(r"{}\System32\cmd.exe", std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()));
        let mut cmd = std::process::Command::new(cmd_exe);
        // no quotes: the path has no spaces, and cmd would keep them
        cmd.args(["/c", &format!("echo x> {}", mark.display())]).stdout(std::process::Stdio::null());
        imp::new_group(&mut cmd);
        let mut child = cmd.spawn().unwrap();
        let pid = child.id();
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(!mark.exists(), "it ran before it was in a job");
        assert!(child.try_wait().unwrap().is_none());
        imp::contain(pid, false).unwrap();
        assert!(group_pids(pid as i32).contains(&(pid as i32)) || !alive(pid as i32));
        assert!(child.wait().unwrap().success());
        assert!(mark.exists());
        release(pid as i32);
        let _ = std::fs::remove_dir_all(&d);
    }
}
