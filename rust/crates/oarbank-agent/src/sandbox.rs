//! The module sandbox, per OS (spec/sandbox.md; docs/design/architecture.md, "The module sandbox"): one policy
//! (oarbank-core's `Policy`), three backends. Every module process starts through `oarbank-agent sandbox-exec`, which
//! confines itself (macOS Seatbelt, Linux Landlock + seccomp) and then execs the module, or (Windows) starts it inside
//! an AppContainer and waits for it. The launcher says when its sandbox holds (`ConfinedSignal`); the parent then
//! verifies the confinement and kills a process that is not confined.

use oarbank_core::sandbox::Policy;
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;

/// Whether this node can confine module processes at all (else it reports no backend and gets no module work).
pub fn available() -> bool {
    #[cfg(target_os = "macos")]
    return true;
    #[cfg(target_os = "linux")]
    return crate::sandbox_linux::available();
    #[cfg(windows)]
    return crate::sandbox_windows::available();
    #[allow(unreachable_code)]
    false
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_file_name(format!(".{}.{:?}.tmp", path.file_name().and_then(|n| n.to_str()).unwrap_or("p"),
                                          std::thread::current().id()));
    std::fs::write(&tmp, data).and_then(|_| std::fs::rename(&tmp, path)).map_err(|e| format!("sandbox policy {}: {e}", path.display()))
}

/// This executable, which every module process starts through.
pub fn me() -> String {
    std::env::current_exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| "oarbank-agent".into())
}

/// Write what the launcher needs for `pol` to `path` (a Seatbelt profile, or the policy as JSON) and return the argv
/// that runs `argv` confined.
#[cfg(target_os = "macos")]
pub fn wrap(pol: &Policy, path: &Path, argv: &[String]) -> Result<Vec<String>, String> {
    let (text, params) = oarbank_core::sandbox::render(pol).map_err(|e| format!("sandbox: {}", e.0))?;
    write_atomic(path, text.as_bytes())?;
    Ok(crate::seatbelt::launch_argv(path, &params, argv))
}

#[cfg(not(target_os = "macos"))]
pub fn wrap(pol: &Policy, path: &Path, argv: &[String]) -> Result<Vec<String>, String> {
    write_atomic(path, &serde_json::to_vec(pol).map_err(|e| e.to_string())?)?;
    let mut out = vec![me(), "sandbox-exec".into(), path.to_string_lossy().to_string(), "--".into()];
    out.extend(argv.iter().cloned());
    Ok(out)
}

/// Whether the process started through `wrap` is confined (on Windows: the AppContainer child of the launcher shim).
pub fn is_confined(pid: i32) -> bool {
    #[cfg(target_os = "macos")]
    return crate::seatbelt::is_sandboxed(pid as u32);
    #[cfg(target_os = "linux")]
    return crate::sandbox_linux::is_confined(pid);
    #[cfg(windows)]
    return crate::sandbox_windows::is_confined(pid);
    #[allow(unreachable_code)]
    {
        let _ = pid;
        false
    }
}

/// After the launcher said it is confined: nothing it started runs unconfined. On macOS and Linux the launcher has
/// become the module process, which must be confined; on Windows every member of the shim's job besides the shim
/// must be in an AppContainer (the runner may already have ended).
pub fn holds(pid: i32) -> bool {
    #[cfg(windows)]
    return crate::sandbox_windows::holds(pid);
    #[allow(unreachable_code)]
    is_confined(pid)
}

/// A process of the container led by `pid` that runs outside the module sandbox, described; watched for as long as
/// the container lives. Windows: a member of the shim's job besides the shim outside the AppContainer
/// (sandbox_windows.rs `escape`: nothing confined can start one). Elsewhere none can exist: Seatbelt and Landlock with
/// seccomp pass to every child and cannot be dropped.
pub fn escape(pid: i32) -> Option<String> {
    #[cfg(windows)]
    return crate::sandbox_windows::escape(pid);
    #[allow(unreachable_code)]
    {
        let _ = pid;
        None
    }
}

/// Names the launcher's confinement signal in its environment: a pipe's write end on POSIX (an fd), an event on
/// Windows (a handle value), inherited from the agent.
pub const CONFINED_ENV: &str = "OARBANK_CONFINED";

/// Only a guard against a launcher that hangs before it confines itself: confining is a few system calls, so a
/// healthy launcher on a loaded host signals long before, and reaching it is logged as a fault.
pub const CONFINE_GUARD: Duration = Duration::from_secs(60);

/// How the wait for a launcher's confinement ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Came {
    /// It signalled: its sandbox holds and the module is about to run (the parent still verifies, with `holds`).
    Confined,
    /// It ended without signalling: it could not confine itself (exit 70) or start the module (71, 64).
    Ended,
    /// Neither within the guard.
    Hung,
}

/// The parent's side of the launcher's word that it is confined, instead of a timer: made before the spawn, given to
/// the launcher with `prepare`, waited on with `wait`. The launcher signals once its sandbox holds, just before the
/// module runs (POSIX: before the exec; Windows: once the AppContainer child exists), and closes its end so the module
/// never holds it (`Launcher`).
pub struct ConfinedSignal(sig::Parent);

impl ConfinedSignal {
    pub fn new() -> std::io::Result<ConfinedSignal> {
        sig::Parent::new().map(ConfinedSignal)
    }

    pub fn prepare(&self, cmd: &mut std::process::Command) {
        self.0.prepare(cmd)
    }

    /// Wait for the launcher `pid` started with `prepare` to signal, or to end, for at most `limit`.
    pub fn wait(self, pid: u32, limit: Duration) -> Came {
        self.0.wait(pid, limit)
    }
}

/// The launcher's side: taken from the environment when it starts (so the module does not see it), signalled once
/// the sandbox holds. None when the parent passed none (the coordinator, a test).
pub struct Launcher(sig::Child);

impl Launcher {
    pub fn take() -> Option<Launcher> {
        let v = std::env::var(CONFINED_ENV).ok()?;
        std::env::remove_var(CONFINED_ENV);
        sig::Child::parse(&v).map(Launcher)
    }

    pub fn confined(self) {
        self.0.signal()
    }
}

#[cfg(unix)]
mod sig {
    use super::Came;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::time::{Duration, Instant};

    pub struct Parent {
        read: OwnedFd,
        write: OwnedFd,
    }

    impl Parent {
        pub fn new() -> std::io::Result<Parent> {
            let mut fds = [0 as RawFd; 2];
            #[cfg(target_os = "linux")]
            let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
            #[cfg(not(target_os = "linux"))]
            let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            #[cfg(not(target_os = "linux"))]
            for fd in fds {
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            }
            Ok(unsafe { Parent { read: OwnedFd::from_raw_fd(fds[0]), write: OwnedFd::from_raw_fd(fds[1]) } })
        }

        /// The launcher inherits the write end (only it: the end is close-on-exec everywhere else).
        pub fn prepare(&self, cmd: &mut std::process::Command) {
            use std::os::unix::process::CommandExt;
            let fd = self.write.as_raw_fd();
            cmd.env(super::CONFINED_ENV, fd.to_string());
            unsafe {
                cmd.pre_exec(move || {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }

        /// A byte: confined; end of file: the launcher closed its end without one (it ended).
        pub fn wait(self, _pid: u32, limit: Duration) -> Came {
            let Parent { read, write } = self;
            drop(write);
            let deadline = Instant::now() + limit;
            loop {
                let left = deadline.saturating_duration_since(Instant::now()).as_millis().min(i32::MAX as u128) as i32;
                let mut p = libc::pollfd { fd: read.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                match unsafe { libc::poll(&mut p, 1, left) } {
                    0 => return Came::Hung,
                    n if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => continue,
                    n if n < 0 => return Came::Ended,
                    _ => {}
                }
                let mut b = [0u8; 1];
                return if unsafe { libc::read(read.as_raw_fd(), b.as_mut_ptr() as *mut _, 1) } == 1 { Came::Confined } else { Came::Ended };
            }
        }
    }

    pub struct Child(RawFd);

    impl Child {
        pub fn parse(v: &str) -> Option<Child> {
            v.parse().ok().filter(|fd: &RawFd| *fd > 2).map(Child)
        }

        pub fn signal(self) {
            unsafe {
                libc::write(self.0, b"1".as_ptr() as *const _, 1);
                libc::close(self.0);
            }
        }
    }
}

#[cfg(windows)]
mod sig {
    use super::Came;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Threading::{CreateEventW, OpenProcess, SetEvent, WaitForMultipleObjects, PROCESS_SYNCHRONIZE};

    /// An inheritable manual-reset event, as a handle value (handles are not Send).
    pub struct Parent(usize);

    impl Parent {
        pub fn new() -> std::io::Result<Parent> {
            let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                                           lpSecurityDescriptor: std::ptr::null_mut(), bInheritHandle: 1 };
            let h = unsafe { CreateEventW(&sa, 1, 0, std::ptr::null()) };
            if h.is_null() { Err(std::io::Error::last_os_error()) } else { Ok(Parent(h as usize)) }
        }

        pub fn prepare(&self, cmd: &mut std::process::Command) {
            cmd.env(super::CONFINED_ENV, self.0.to_string());
        }

        /// The event: confined; the shim's process handle: it ended (the event wins when both are set).
        pub fn wait(self, pid: u32, limit: Duration) -> Came {
            let p = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            let handles = [self.0 as HANDLE, p];
            let n = if p.is_null() { 1 } else { 2 };
            let ms = limit.as_millis().min(u32::MAX as u128 - 1) as u32;
            let r = unsafe { WaitForMultipleObjects(n, handles.as_ptr(), 0, ms) };
            if !p.is_null() {
                unsafe { CloseHandle(p) };
            }
            match r {
                WAIT_OBJECT_0 => Came::Confined,
                WAIT_TIMEOUT => Came::Hung,
                _ => Came::Ended,
            }
        }
    }

    impl Drop for Parent {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0 as HANDLE) };
        }
    }

    pub struct Child(usize);

    impl Child {
        pub fn parse(v: &str) -> Option<Child> {
            v.parse().ok().filter(|h: &usize| *h != 0).map(Child)
        }

        pub fn signal(self) {
            unsafe {
                SetEvent(self.0 as HANDLE);
                CloseHandle(self.0 as HANDLE);
            }
        }
    }
}

/// `oarbank-agent sandbox-exec …`: never returns.
pub fn exec(args: &[String]) -> ! {
    #[cfg(target_os = "macos")]
    crate::seatbelt::exec(args);
    #[cfg(target_os = "linux")]
    crate::sandbox_linux::exec(args);
    #[cfg(windows)]
    crate::sandbox_windows::exec(args);
    #[allow(unreachable_code)]
    {
        let _ = args;
        eprintln!("sandbox launch: no sandbox backend on this OS");
        std::process::exit(70)
    }
}

/// The facts' `sandbox`: the backend and, per capability, `enforced`, `cooperative` or `unavailable`.
pub fn report() -> Value {
    #[cfg(target_os = "macos")]
    return json!({"backend": "seatbelt", "enforcement": {
        "filesystem": "enforced", "ipc": "enforced", "net.none": "enforced", "net.egress-allowlist": "enforced",
        "net.egress-any": "enforced", "no_loopback": "enforced", "gpu.compute": "enforced",
        "exec_writable_deny": "enforced", "no_link_local": "unavailable"}});
    #[cfg(target_os = "linux")]
    return crate::sandbox_linux::report();
    #[cfg(windows)]
    return crate::sandbox_windows::report();
    #[allow(unreachable_code)]
    {
        json!({"backend": null, "enforcement": {}})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    /// The launcher's side, in a child copy of this test binary (`OARBANK_TEST_LAUNCHER`): signal after that many
    /// milliseconds, end without signalling (`never`), or hang (`hang`).
    #[test]
    #[ignore = "the launcher role of a_launcher_is_waited_for_by_its_signal_not_a_timer"]
    fn launcher_role() {
        let Ok(mode) = std::env::var("OARBANK_TEST_LAUNCHER") else { return };
        let l = Launcher::take().expect("the parent's signal");
        assert!(std::env::var(CONFINED_ENV).is_err(), "taken out of the environment the module would inherit");
        match mode.as_str() {
            "never" => {}
            "hang" => std::thread::sleep(Duration::from_secs(60)),
            ms => {
                std::thread::sleep(Duration::from_millis(ms.parse().unwrap()));
                l.confined();
            }
        }
    }

    fn launch(mode: &str) -> (ConfinedSignal, std::process::Child) {
        let s = ConfinedSignal::new().unwrap();
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["sandbox::tests::launcher_role", "--exact", "--ignored", "--quiet"]).env("OARBANK_TEST_LAUNCHER", mode)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        s.prepare(&mut cmd);
        let child = cmd.spawn().unwrap();
        (s, child)
    }

    #[test]
    fn a_launcher_is_waited_for_by_its_signal_not_a_timer() {
        // slower than the fixed window the agent used to allow (2 s), and still confined, not killed
        let (s, mut c) = launch("3000");
        let t = Instant::now();
        assert_eq!(s.wait(c.id(), CONFINE_GUARD), Came::Confined);
        assert!(t.elapsed() >= Duration::from_secs(3));
        assert!(c.wait().unwrap().success());
        // one that ends without confining itself is seen at once, not at the guard
        let (s, mut c) = launch("never");
        let t = Instant::now();
        assert_eq!(s.wait(c.id(), CONFINE_GUARD), Came::Ended);
        assert!(t.elapsed() < CONFINE_GUARD / 2);
        let _ = c.wait();
        // and one that hangs meets the guard
        let (s, mut c) = launch("hang");
        assert_eq!(s.wait(c.id(), Duration::from_millis(500)), Came::Hung);
        let _ = c.kill();
        let _ = c.wait();
    }
}
