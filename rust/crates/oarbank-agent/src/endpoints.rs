//! Service endpoints (the SDK's spec/service-protocol.md, "Endpoints"; docs/design/service-endpoints.md). The agent
//! owns every end of every channel, so module code never listens and nothing is reachable by name:
//!
//! - an endpoint service gets one **channel** when it starts (`OARBANK_ENDPOINT_CHANNEL`), an inherited,
//!   already-connected stream; it says hello on it, and every connection a job opens arrives on it as a handle;
//! - an attempt whose stage reserves one of the service's pools gets a **connector** (`OARBANK_SERVICE_<NAME>`),
//!   another inherited stream; each `connect` on it makes a fresh connected pair, one end for the job, one for the
//!   service.
//!
//! macOS and Linux: socketpairs, handles sent with SCM_RIGHTS. The agent keeps its copy of each end it sent until the
//! receiver says it has it (`accepted`, `received`): macOS disposes of a socket in flight whose last outside reference
//! closes while the receiver is still installing it. Windows: named-pipe pairs, each end duplicated straight into a
//! process the agent has checked is in the right Job Object; nothing is in flight, so the agent closes its copies at
//! once. Every message is one JSON line of at most 4096 bytes; threads read with blocking reads, never a timer.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tracing::warn;

pub const CHANNEL_ENV: &str = "OARBANK_ENDPOINT_CHANNEL";
pub const SERVICE_ENV_PREFIX: &str = "OARBANK_SERVICE_";
const MAX_LINE: usize = 4096;
/// The connect rate a connector allows: a burst, then so many a second.
const BURST: f64 = 64.0;
const PER_SECOND: f64 = 32.0;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The variable a job finds a service's connector in.
pub fn env_name(service: &str) -> String {
    format!("{SERVICE_ENV_PREFIX}{}", service.to_ascii_uppercase())
}

/// A refusal on a connector: `{ok: false, error, detail}`.
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    pub code: &'static str,
    pub detail: String,
}

impl Refusal {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Refusal {
        Refusal { code, detail: detail.into() }
    }
}

// MARK: streams, per OS

#[cfg(unix)]
mod os {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    /// One end of a connected unix stream socket.
    pub type End = OwnedFd;

    /// A connected pair, both ends close-on-exec (an end meant for a child is made inheritable in that child only).
    pub fn pair() -> io::Result<(End, End)> {
        let mut fds = [0 as RawFd; 2];
        #[cfg(target_os = "linux")]
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) };
        #[cfg(not(target_os = "linux"))]
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(not(target_os = "linux"))]
        for fd in fds {
            unsafe {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                let one: libc::c_int = 1;                       // a write to a closed peer is an error, never SIGPIPE
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_NOSIGPIPE, &one as *const _ as *const _, 4);
            }
        }
        Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
    }

    /// How a child names an end it inherits.
    pub fn value(end: &End) -> String {
        format!("fd:{}", end.as_raw_fd())
    }

    #[cfg(target_os = "linux")]
    const FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    const FLAGS: libc::c_int = 0;

    /// One message, with an end attached (SCM_RIGHTS) when given: one sendmsg, so lines and descriptors stay in order.
    pub fn send(on: &End, line: &[u8], attach: Option<&End>) -> io::Result<()> {
        let mut off = 0;
        let mut first = true;
        while off < line.len() {
            let mut iov = libc::iovec { iov_base: line[off..].as_ptr() as *mut _, iov_len: line.len() - off };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
            let mut cbuf = vec![0u8; space];
            if let (true, Some(e)) = (first, attach) {
                msg.msg_control = cbuf.as_mut_ptr() as *mut _;
                msg.msg_controllen = space as _;
                unsafe {
                    let c = libc::CMSG_FIRSTHDR(&msg);
                    (*c).cmsg_level = libc::SOL_SOCKET;
                    (*c).cmsg_type = libc::SCM_RIGHTS;
                    (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
                    std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut RawFd, e.as_raw_fd());
                }
            }
            let n = unsafe { libc::sendmsg(on.as_raw_fd(), &msg, FLAGS) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            off += n as usize;
            first = false;
        }
        Ok(())
    }

    /// A plain read: a descriptor a peer attaches to what the agent reads is discarded by the kernel.
    pub fn read(from: &End, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = unsafe { libc::read(from.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }

    /// Ends both directions, waking a thread blocked reading it.
    pub fn shutdown(end: &End) {
        unsafe { libc::shutdown(end.as_raw_fd(), libc::SHUT_RDWR) };
    }

    /// Make `end` inherited by the command's child (only there: it stays close-on-exec in the agent).
    pub fn inherit(end: &End, cmd: &mut std::process::Command) {
        use std::os::unix::process::CommandExt;
        let fd = end.as_raw_fd();
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

#[cfg(windows)]
mod os {
    use std::io;
    use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, ERROR_IO_PENDING,
                                         ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE,
                                                  FILE_FLAG_OVERLAPPED, OPEN_EXISTING, PIPE_ACCESS_DUPLEX};
    use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
                                            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT};
    use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE};
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

    /// A pipe handle, owned (kept as usize so ends are Send). `overlapped`: the agent's own end of a channel or
    /// connector, read on one thread while others write to it.
    pub struct End {
        h: usize,
        overlapped: bool,
    }

    unsafe impl Send for End {}
    unsafe impl Sync for End {}

    impl End {
        pub fn raw(&self) -> HANDLE {
            self.h as HANDLE
        }
    }

    impl Drop for End {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.h as HANDLE) };
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A connected pair of a fresh named pipe: (its server end, its client end). The name is random and used once
    /// (first instance, one instance, remote clients refused); the client is opened at once. `ours_overlapped`: the
    /// server end is the agent's (overlapped); `inheritable`: the client end will be inherited by a child.
    pub fn pair_with(ours_overlapped: bool, inheritable: bool) -> io::Result<(End, End)> {
        let name = wide(&format!(r"\\.\pipe\oarbank-ep-{}", hex::encode(rand::random::<[u8; 16]>())));
        let mut open = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE;
        if ours_overlapped {
            open |= FILE_FLAG_OVERLAPPED;
        }
        unsafe {
            let srv = CreateNamedPipeW(name.as_ptr(), open, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                       1, 65536, 65536, 0, std::ptr::null());
            if srv == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let srv = End { h: srv as usize, overlapped: ours_overlapped };
            let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                                           lpSecurityDescriptor: std::ptr::null_mut(), bInheritHandle: inheritable.into() };
            let cli = CreateFileW(name.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, &sa, OPEN_EXISTING, 0, std::ptr::null_mut());
            if cli == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let cli = End { h: cli as usize, overlapped: false };
            if ours_overlapped {
                let mut ov: OVERLAPPED = std::mem::zeroed();
                ov.hEvent = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
                let ok = ConnectNamedPipe(srv.raw(), &mut ov);
                let err = GetLastError();
                CloseHandle(ov.hEvent);
                if ok == 0 && err != ERROR_PIPE_CONNECTED && err != ERROR_IO_PENDING {
                    return Err(io::Error::from_raw_os_error(err as i32));
                }
            } else if ConnectNamedPipe(srv.raw(), std::ptr::null_mut()) == 0 && GetLastError() != ERROR_PIPE_CONNECTED {
                return Err(io::Error::last_os_error());
            }
            Ok((srv, cli))
        }
    }

    /// The agent's end and a child's inheritable end of a channel or connector.
    pub fn pair() -> io::Result<(End, End)> {
        pair_with(true, true)
    }

    pub fn value(end: &End) -> String {
        format!("handle:{}", end.h)
    }

    fn io_op(end: &End, f: impl FnOnce(*mut OVERLAPPED) -> i32) -> io::Result<usize> {
        unsafe {
            if !end.overlapped {
                let mut ov: OVERLAPPED = std::mem::zeroed();
                return if f(&mut ov) != 0 { Ok(ov.InternalHigh) } else { Err(io::Error::last_os_error()) };
            }
            let mut ov: OVERLAPPED = std::mem::zeroed();
            ov.hEvent = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
            if ov.hEvent.is_null() {
                return Err(io::Error::last_os_error());
            }
            let ok = f(&mut ov);
            let r = if ok == 0 && GetLastError() != ERROR_IO_PENDING {
                Err(io::Error::last_os_error())
            } else {
                let mut n = 0u32;
                if GetOverlappedResult(end.raw(), &ov, &mut n, 1) != 0 { Ok(n as usize) } else { Err(io::Error::last_os_error()) }
            };
            CloseHandle(ov.hEvent);
            r
        }
    }

    pub fn send(on: &End, line: &[u8], attach: Option<&End>) -> io::Result<()> {
        debug_assert!(attach.is_none(), "Windows places handles with DuplicateHandle");
        let mut off = 0;
        while off < line.len() {
            let chunk = &line[off..];
            let n = io_op(on, |ov| unsafe {
                let mut put = 0u32;
                WriteFile(on.raw(), chunk.as_ptr(), chunk.len() as u32, if on.overlapped { std::ptr::null_mut() } else { &mut put }, ov)
            })?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            off += n;
        }
        Ok(())
    }

    /// A read; a pipe whose other end is gone reads as end of file.
    pub fn read(from: &End, buf: &mut [u8]) -> io::Result<usize> {
        match io_op(from, |ov| unsafe {
            let mut got = 0u32;
            ReadFile(from.raw(), buf.as_mut_ptr(), buf.len() as u32, if from.overlapped { std::ptr::null_mut() } else { &mut got }, ov)
        }) {
            Err(e) if matches!(e.raw_os_error(), Some(109 | 232 | 233 | 995)) => Ok(0),   // broken, closing, not connected, aborted
            r => r,
        }
    }

    pub fn shutdown(end: &End) {
        unsafe {
            CancelIoEx(end.raw(), std::ptr::null());
            DisconnectNamedPipe(end.raw());
        }
    }

    /// Duplicate `end` into process `pid` and close the agent's copy: its handle value there.
    pub fn place(end: End, pid: u32) -> io::Result<usize> {
        unsafe {
            let p = OpenProcess(PROCESS_DUP_HANDLE, 0, pid);
            if p.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut there: HANDLE = std::ptr::null_mut();
            let ok = DuplicateHandle(GetCurrentProcess(), end.raw(), p, &mut there, 0, 0, DUPLICATE_SAME_ACCESS);
            let e = io::Error::last_os_error();
            CloseHandle(p);
            if ok == 0 {
                return Err(e);
            }
            drop(end);
            Ok(there as usize)
        }
    }

    /// Whether process `pid` is a member of the container led by `pgid` (its Job Object).
    pub fn in_container(pgid: i32, pid: u32) -> bool {
        crate::sys::in_container(pgid, pid)
    }
}

pub use os::End;

/// The child's end of a channel or connector, until the child has it.
pub struct ChildEnd {
    end: Option<End>,
    value: String,
}

impl ChildEnd {
    fn new(end: End) -> ChildEnd {
        ChildEnd { value: os::value(&end), end: Some(end) }
    }

    /// What the child finds in its variable (`fd:<n>`, `handle:<n>`).
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Let the command's child inherit the end (POSIX: only that child; Windows: the end is inheritable, and the sandbox
    /// shim passes it on in the module's handle list).
    pub fn prepare(&self, cmd: &mut std::process::Command) {
        #[cfg(unix)]
        if let Some(e) = &self.end {
            os::inherit(e, cmd);
        }
        #[cfg(windows)]
        let _ = cmd;
    }

    /// The child exists (or could not start): the agent's copy goes, so the child's close is seen.
    pub fn spawned(&mut self) {
        self.end.take();
    }
}

/// Reads one JSON object per line.
struct Lines<'a> {
    end: &'a End,
    buf: Vec<u8>,
}

impl<'a> Lines<'a> {
    fn new(end: &'a End) -> Lines<'a> {
        Lines { end, buf: Vec::new() }
    }

    /// The next object; None at end of file, on an error, or on a line that is too long or not an object.
    fn next(&mut self) -> Option<Value> {
        loop {
            if let Some(i) = self.buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=i).collect();
                return serde_json::from_slice::<Value>(&line[..i]).ok().filter(Value::is_object);
            }
            if self.buf.len() > MAX_LINE {
                return None;
            }
            let mut chunk = [0u8; MAX_LINE];
            match os::read(self.end, &mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

fn line(v: &Value) -> Vec<u8> {
    let mut b = serde_json::to_vec(v).unwrap_or_default();
    b.push(b'\n');
    b
}

/// Ends sent over a socket, kept until the receiver says it has them (POSIX; see the module comment).
#[derive(Default)]
struct Held(Mutex<HashMap<u64, End>>);

impl Held {
    #[cfg(unix)]
    fn keep(&self, conn: u64, end: End) {
        lock(&self.0).insert(conn, end);
    }

    fn drop_one(&self, conn: u64) {
        lock(&self.0).remove(&conn);
    }

    fn clear(&self) {
        lock(&self.0).clear();
    }
}

/// The container a channel or connector belongs to (its leader's pid), learnt when the child is spawned; a Windows
/// handle is placed only in one of its members.
#[derive(Default)]
struct Container {
    pgid: Mutex<Option<i32>>,
    set: Condvar,
}

impl Container {
    fn bind(&self, pgid: i32) {
        *lock(&self.pgid) = Some(pgid);
        self.set.notify_all();
    }

    /// Waits for `bind` (the child sends nothing before it exists, but its first message may race the agent's spawn
    /// returning), at most `limit`.
    #[cfg_attr(unix, allow(dead_code))]
    fn wait(&self, limit: Duration) -> Option<i32> {
        let g = lock(&self.pgid);
        let (g, _) = self.set.wait_timeout_while(g, limit, |p| p.is_none()).unwrap_or_else(|e| e.into_inner());
        *g
    }
}

/// Whether `pid` may receive a handle for the container led by `pgid` (POSIX: descriptors go to whoever reads them).
fn member(container: &Container, pid: Option<u64>) -> bool {
    #[cfg(windows)]
    {
        let (Some(pgid), Some(pid)) = (container.wait(Duration::from_secs(10)), pid) else { return false };
        os::in_container(pgid, pid as u32)
    }
    #[cfg(unix)]
    {
        let _ = (container, pid);
        true
    }
}

// MARK: the service's channel

/// Wakes whoever waits on a service's state (the readiness gate, a connect waiting for a restart).
pub trait Waker: Send + Sync {
    fn changed(&self);
}

/// One run of an endpoint service: its channel, from `start` until it stops.
pub struct Channel {
    pub service: String,
    end: End,
    child: Mutex<Option<ChildEnd>>,
    container: Container,
    hello: Mutex<Option<u32>>,
    closed: AtomicBool,
    write: Mutex<()>,
    next: AtomicU64,
    held: Held,
    reader: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel").field("service", &self.service).field("hello", &*lock(&self.hello))
            .field("closed", &self.closed.load(Ordering::SeqCst)).finish()
    }
}

impl Channel {
    /// A new channel; `lost` runs once if the service closes it first (it died, or exited).
    pub fn new(service: &str, waker: Arc<dyn Waker>, lost: Box<dyn FnOnce() + Send>) -> std::io::Result<Arc<Channel>> {
        let (end, child) = os::pair()?;
        let ch = Arc::new(Channel { service: service.into(), end, child: Mutex::new(Some(ChildEnd::new(child))),
                                    container: Container::default(), hello: Mutex::new(None), closed: AtomicBool::new(false),
                                    write: Mutex::new(()), next: AtomicU64::new(0), held: Held::default(),
                                    reader: Mutex::new(None) });
        let c2 = ch.clone();
        let t = std::thread::Builder::new().name(format!("endpoint {service}")).spawn(move || {
            let mut lines = Lines::new(&c2.end);
            while let Some(m) = lines.next() {
                match m["op"].as_str() {
                    Some("hello") if lock(&c2.hello).is_none() => {
                        let pid = m["pid"].as_u64();
                        if member(&c2.container, pid) {
                            *lock(&c2.hello) = pid.map(|p| p as u32);
                            waker.changed();
                        } else {
                            warn!(service = %c2.service, pid = ?pid, "endpoint hello from a process outside the service: ignored");
                        }
                    }
                    Some("accepted") => {
                        if let Some(n) = m["conn"].as_u64() {
                            c2.held.drop_one(n);
                        }
                    }
                    _ => {}
                }
            }
            c2.held.clear();
            if !c2.closed.swap(true, Ordering::SeqCst) {
                lost();
            }
            waker.changed();
        })?;
        *lock(&ch.reader) = Some(t);
        Ok(ch)
    }

    /// The service's end, for `start`'s environment.
    pub fn child_value(&self) -> String {
        lock(&self.child).as_ref().map(|c| c.value().to_string()).unwrap_or_default()
    }

    pub fn prepare(&self, cmd: &mut std::process::Command) {
        if let Some(c) = lock(&self.child).as_ref() {
            c.prepare(cmd);
        }
    }

    /// `start` was spawned in the container led by `pgid` (or could not be: `None`).
    pub fn spawned(&self, pgid: Option<i32>) {
        if let Some(c) = lock(&self.child).as_mut() {
            c.spawned();
        }
        if let Some(p) = pgid {
            self.container.bind(p);
        }
    }

    /// The service said hello and the channel is open: it accepts connections.
    pub fn accepting(&self) -> bool {
        !self.closed.load(Ordering::SeqCst) && lock(&self.hello).is_some()
    }

    fn send(&self, v: &Value, attach: Option<&End>) -> std::io::Result<()> {
        let _g = lock(&self.write);
        os::send(&self.end, &line(v), attach)
    }

    /// A new connection for `attempt`: the service's end goes to the service; the job's end is returned.
    fn hand(&self, attempt: i64) -> Result<(u64, End), Refusal> {
        if !self.accepting() {
            return Err(Refusal::new("service_unavailable", format!("{} is not accepting connections", self.service)));
        }
        let n = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let unavailable = |e: std::io::Error| Refusal::new("service_unavailable", format!("{}: {e}", self.service));
        #[cfg(unix)]
        {
            let (job, svc) = os::pair().map_err(unavailable)?;
            self.send(&json!({"op": "connection", "conn": n, "attempt": attempt}), Some(&svc)).map_err(unavailable)?;
            self.held.keep(n, svc);
            Ok((n, job))
        }
        #[cfg(windows)]
        {
            let (svc, job) = os::pair_with(false, false).map_err(unavailable)?;
            let pid = lock(&self.hello).ok_or_else(|| Refusal::new("service_unavailable", "no hello"))?;
            let h = os::place(svc, pid).map_err(unavailable)?;
            self.send(&json!({"op": "connection", "conn": n, "attempt": attempt, "handle": h}), None).map_err(unavailable)?;
            Ok((n, job))
        }
    }

    /// The attempt is over: the service drops whatever it still holds of it.
    pub fn ended(&self, attempt: i64) {
        if !self.closed.load(Ordering::SeqCst) {
            let _ = self.send(&json!({"op": "ended", "attempt": attempt}), None);
        }
    }

    /// The agent stops the service: close the channel (the service exits on its end of file).
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        os::shutdown(&self.end);
        if let Some(t) = lock(&self.reader).take() {
            if t.thread().id() != std::thread::current().id() {
                let _ = t.join();
            }
        }
        self.held.clear();
    }
}

// MARK: an attempt's connector

/// How a connector finds its service's channel: waits (event-driven) until the service accepts, at most `limit`.
pub type Lookup = Arc<dyn Fn(Duration) -> Result<Arc<Channel>, Refusal> + Send + Sync>;

/// One attempt's connector to one endpoint service.
pub struct Connector {
    pub service: String,
    pub attempt: i64,
    end: Arc<End>,
    child: ChildEnd,
    container: Arc<Container>,
    channels: Arc<Mutex<Vec<Arc<Channel>>>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn take(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * PER_SECOND).min(BURST);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Connector {
    /// A connector for `attempt` to `service`, answering on a thread of its own; `wait` bounds a connect's wait for a
    /// service that is (re)starting.
    pub fn new(service: &str, attempt: i64, lookup: Lookup, wait: Duration) -> std::io::Result<Connector> {
        let (end, child) = os::pair()?;
        let end = Arc::new(end);
        let container = Arc::new(Container::default());
        let channels: Arc<Mutex<Vec<Arc<Channel>>>> = Arc::default();
        let (e2, c2, ch2) = (end.clone(), container.clone(), channels.clone());
        let reader = std::thread::Builder::new().name(format!("connector {attempt} {service}")).spawn(move || {
            let held = Held::default();
            let mut bucket = Bucket { tokens: BURST, at: Instant::now() };
            let mut lines = Lines::new(&e2);
            while let Some(m) = lines.next() {
                match m["op"].as_str() {
                    Some("received") => {
                        if let Some(n) = m["conn"].as_u64() {
                            held.drop_one(n);
                        }
                        continue;
                    }
                    Some("connect") => {}
                    _ => {
                        let _ = os::send(&e2, &line(&json!({"ok": false, "error": "bad_request", "detail": "unknown op"})), None);
                        continue;
                    }
                }
                let pid = m["pid"].as_u64();
                let answer = if !bucket.take() {
                    Err(Refusal::new("rate_limited", format!("more than {BURST} connections at once or {PER_SECOND} a second")))
                } else if !member(&c2, pid) {
                    Err(Refusal::new("bad_pid", format!("process {pid:?} is not in this attempt")))
                } else {
                    lookup(wait).and_then(|ch| {
                        let r = ch.hand(attempt);
                        let mut seen = lock(&ch2);
                        if !seen.iter().any(|c| Arc::ptr_eq(c, &ch)) {
                            seen.push(ch.clone());
                        }
                        r
                    })
                };
                let sent = match answer {
                    Err(r) => os::send(&e2, &line(&json!({"ok": false, "error": r.code, "detail": r.detail})), None),
                    #[cfg(unix)]
                    Ok((n, job)) => {
                        let r = os::send(&e2, &line(&json!({"ok": true, "conn": n})), Some(&job));
                        held.keep(n, job);
                        r
                    }
                    #[cfg(windows)]
                    Ok((n, job)) => match os::place(job, pid.unwrap_or(0) as u32) {
                        Ok(h) => os::send(&e2, &line(&json!({"ok": true, "conn": n, "handle": h})), None),
                        Err(e) => os::send(&e2, &line(&json!({"ok": false, "error": "bad_pid", "detail": e.to_string()})), None),
                    },
                };
                if sent.is_err() {
                    break;
                }
            }
            held.clear();
        })?;
        Ok(Connector { service: service.into(), attempt, end, child: ChildEnd::new(child), container, channels, reader: Some(reader) })
    }

    /// The runner's variable and its value.
    pub fn env(&self) -> (String, String) {
        (env_name(&self.service), self.child.value().to_string())
    }

    pub fn prepare(&self, cmd: &mut std::process::Command) {
        self.child.prepare(cmd);
    }

    /// The runner was spawned in the container led by `pgid` (or could not be: `None`).
    pub fn spawned(&mut self, pgid: Option<i32>) {
        self.child.spawned();
        if let Some(p) = pgid {
            self.container.bind(p);
        }
    }
}

impl Drop for Connector {
    /// The attempt ended (its container is gone): close the connector, then tell every service run it reached.
    fn drop(&mut self) {
        self.child.spawned();
        os::shutdown(&self.end);
        if let Some(t) = self.reader.take() {
            let _ = t.join();
        }
        for ch in lock(&self.channels).drain(..) {
            ch.ended(self.attempt);
        }
    }
}

#[cfg(test)]
pub mod tests {
    //! The agent's side against the SDK's own client and acceptor: the reference `modelserver` module's service under
    //! the service manager and job processes with their connectors, all of them real processes under the module
    //! sandbox, on macOS, Linux and Windows.
    use super::*;
    use crate::paths::Layout;
    use crate::release::Release;
    use crate::runtime::Runtime;
    use crate::services::ServiceManager;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    pub struct NoWake;

    impl Waker for NoWake {
        fn changed(&self) {}
    }

    #[test]
    fn env_names_follow_the_service_name() {
        assert_eq!(env_name("model"), "OARBANK_SERVICE_MODEL");
        assert_eq!(env_name("llm_7b"), "OARBANK_SERVICE_LLM_7B");
    }

    #[test]
    fn the_bucket_allows_a_burst_then_a_rate() {
        let mut b = Bucket { tokens: BURST, at: Instant::now() };
        let n = (0..200).filter(|_| b.take()).count();
        assert!((64..=66).contains(&n), "{n}");
        std::thread::sleep(Duration::from_millis(100));
        assert!(b.take() && b.take(), "about three more after 100 ms");
    }

    #[test]
    fn a_connect_is_refused_until_the_service_says_hello_and_closing_is_no_loss() {
        let lost = Arc::new(AtomicBool::new(false));
        let l2 = lost.clone();
        let ch = Channel::new("svc", Arc::new(NoWake), Box::new(move || l2.store(true, Ordering::SeqCst))).unwrap();
        assert_eq!(ch.hand(1).err().map(|r| r.code), Some("service_unavailable"));
        ch.spawned(None);
        ch.close();
        assert!(!ch.accepting() && !lost.load(Ordering::SeqCst), "closed by the agent: not a loss");
    }

    /// The repository's Python with the SDK (OARBANK_TEST_PYTHON, else the repository's .venv) and what the sandbox must
    /// let it read: its prefixes and the SDK's source.
    fn python() -> (PathBuf, Vec<String>) {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let venv = if cfg!(windows) { repo.join(r".venv\Scripts\python.exe") } else { repo.join(".venv/bin/python") };
        let py = std::env::var_os("OARBANK_TEST_PYTHON").map(PathBuf::from).unwrap_or(venv);
        let probe = "import json, os, sys, oarbank_sdk\n\
                     r = {sys.prefix, sys.base_prefix, sys.exec_prefix, os.path.dirname(os.path.realpath(sys.executable)),\n\
                          os.path.dirname(os.path.dirname(os.path.realpath(oarbank_sdk.__file__)))}\n\
                     print(json.dumps(sorted(r | {os.path.realpath(x) for x in r})))";
        let out = std::process::Command::new(&py).args(["-I", "-c", probe]).output().unwrap_or_else(|e| panic!("{}: {e}", py.display()));
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        (py, serde_json::from_slice(&out.stdout).unwrap())
    }

    /// A release holding the SDK's reference module `modelserver`, and a service manager for it.
    struct Fx {
        root: PathBuf,
        release: Release,
        python: PathBuf,
        roots: Vec<String>,
    }

    fn copy_dir(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for e in std::fs::read_dir(from).unwrap().flatten() {
            let (src, dst) = (e.path(), to.join(e.file_name()));
            if src.is_dir() {
                if e.file_name() != "__pycache__" {
                    copy_dir(&src, &dst);
                }
            } else {
                std::fs::copy(&src, &dst).unwrap();
            }
        }
    }

    impl Fx {
        fn new(tag: &str) -> Fx {
            let root = std::env::temp_dir().join(format!("oarbank-ep-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let root = dunce(std::fs::canonicalize(&root).unwrap());
            let dir = root.join("releases").join("r_test");
            let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../vendor/oarbank-sdk/examples/modelserver");
            copy_dir(&example, &dir.join("modules").join("modelserver"));
            let entry = json!({"name": "modelserver", "module_id": "dev.codonic.oarbank.modelserver", "bundle": "modules/modelserver",
                "services": [{"name": "model", "exec": ["python", "-I", "{bundle}/model_service.py"], "lifecycle": "on_demand",
                              "idle_timeout_s": 1, "start_timeout_s": 60, "stop_timeout_s": 20, "endpoint": true,
                              "provides": {"pools": ["model"], "capabilities": []}, "reserves_host_memory": true, "yieldable": true}],
                "probes": [], "sandbox": {"contract": 1, "net": {"mode": "none"}, "tools": [], "devices": {"gpu": "none"},
                                          "exec_writable": false}});
            let (python, roots) = python();
            Fx { root, release: Release { id: "r_test".into(), dir, modules: vec![entry] }, python, roots }
        }

        fn manager(&self) -> ServiceManager {
            let l = Layout::new(self.root.join("home"));
            l.ensure().unwrap();
            let rt = Runtime { python: self.python.clone(), uv: None, site_dirs: vec![], roots: self.roots.clone() };
            let mut m = ServiceManager::new(l, rt, None, true);
            m.configure(&self.release, &json!({"module_settings": {"modelserver": {"load_s": 0.3, "generate_s": 0.3}}}), Some("node-1"));
            m
        }

        fn data(&self, name: &str) -> PathBuf {
            self.root.join("home").join("modules-data").join("modelserver").join(name)
        }

        fn loads(&self) -> Vec<String> {
            std::fs::read_to_string(self.data("model.loads")).unwrap_or_default().lines().map(str::to_string).collect()
        }

        /// A job of attempt `aid`: a Python process under the sandbox with its connectors, as jobs.rs starts a runner;
        /// it sends `prompts` at once and writes the answers to its work directory.
        fn job(&self, m: &ServiceManager, aid: i64, prompts: &[&str]) -> Job {
            let ws = self.root.join("work").join(aid.to_string());
            std::fs::create_dir_all(ws.join("tmp")).unwrap();
            let mut connectors = m.connectors("modelserver", &["model".to_string()], aid).unwrap();
            assert_eq!(connectors.len(), 1);
            let script = "import json, sys\nfrom concurrent.futures import ThreadPoolExecutor\n\
                          from oarbank_sdk import service_endpoint as ep\nout = {}\n\
                          try:\n    with ThreadPoolExecutor(4) as pool:\n\
                          \x20       out['answers'] = list(pool.map(lambda p: ep.request('model', 'POST', '/v1/generate', {'prompt': p}).json(), sys.argv[2:]))\n\
                          except Exception as e:\n    out['error'] = repr(e)\n\
                          import socket\ntry:\n    u = socket.socket(socket.AF_UNIX)\n    u.connect('/var/run/mDNSResponder')\n    out['unix_socket'] = 'connected'\n\
                          except (OSError, AttributeError):\n    out['unix_socket'] = 'refused'\n\
                          open(sys.argv[1] + '/out.tmp', 'w').write(json.dumps(out))\n\
                          import os\nos.replace(sys.argv[1] + '/out.tmp', sys.argv[1] + '/out.json')\n\
                          import time\ntime.sleep(float(__import__('os').environ.get('HOLD', '0')))";
            let mut argv = vec![self.python.display().to_string(), "-I".into(), "-c".into(), script.into(), ws.display().to_string()];
            argv.extend(prompts.iter().map(|p| p.to_string()));
            let mut pol = oarbank_core::sandbox::Policy::new("dev.codonic.oarbank.modelserver");
            pol.ro = [vec![self.release.dir.join("modules").join("modelserver").display().to_string()], self.roots.clone()].concat();
            pol.rw = vec![ws.display().to_string()];
            pol.kind = "runner".into();
            pol.exe = Some(self.python.display().to_string());
            let argv = crate::sandbox::wrap(&pol, &ws.join("runner.sb"), &argv).unwrap();
            let mut env = crate::doctor::base_env("modelserver", &ws, &ws.join("tmp"));
            env.extend(connectors.iter().map(|c| c.env()));
            env.push(("HOLD".into(), "3".into()));
            let mut cmd = std::process::Command::new(&argv[0]);
            cmd.args(&argv[1..]).env_clear().envs(env).current_dir(&ws).stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null()).stderr(std::fs::File::create(ws.join("stderr")).unwrap());
            for c in &connectors {
                c.prepare(&mut cmd);
            }
            let child = crate::sys::spawn_contained(&mut cmd, false).unwrap();
            for c in connectors.iter_mut() {
                c.spawned(Some(child.id() as i32));
            }
            Job { child, ws, connectors }
        }
    }

    fn dunce(p: PathBuf) -> PathBuf {
        let s = p.display().to_string();
        s.strip_prefix(r"\\?\").map(PathBuf::from).unwrap_or(p)
    }

    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    struct Job {
        child: std::process::Child,
        ws: PathBuf,
        connectors: Vec<Connector>,
    }

    impl Job {
        /// Its answers (up to 120 s on a loaded host).
        fn out(&mut self) -> Value {
            let deadline = Instant::now() + Duration::from_secs(120);
            while Instant::now() < deadline {
                if let Ok(s) = std::fs::read_to_string(self.ws.join("out.json")) {
                    return serde_json::from_str(&s).unwrap();
                }
                if self.child.try_wait().unwrap().is_some() && !self.ws.join("out.json").exists() {
                    panic!("the job ended without answers: {}", std::fs::read_to_string(self.ws.join("stderr")).unwrap_or_default());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("no answers: {}", std::fs::read_to_string(self.ws.join("stderr")).unwrap_or_default());
        }

        /// The attempt ends: its container is killed, then its connectors go.
        fn end(mut self) {
            let pid = self.child.id() as i32;
            crate::sys::signal_group(pid, crate::sys::Sig::Kill);
            let _ = self.child.wait();
            crate::sys::release(pid);
            self.connectors.clear();
        }
    }

    fn need(n: i64) -> BTreeMap<String, i64> {
        if n == 0 { BTreeMap::new() } else { [("model".to_string(), n)].into() }
    }

    fn tick_until(m: &mut ServiceManager, n: i64, secs: f64, mut cond: impl FnMut(&ServiceManager) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs_f64(secs);
        while Instant::now() < deadline {
            m.tick(&need(n), &[], false);
            if cond(m) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    fn ready(m: &ServiceManager) -> bool {
        m.ready_for(&["model".to_string()])
    }

    fn gone(pid: i32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(20);
        while crate::sys::alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        !crate::sys::alive(pid)
    }

    fn daemon(fx: &Fx) -> i32 {
        std::fs::read_to_string(fx.data("model.ready")).unwrap().trim().parse().unwrap()
    }

    #[test]
    fn two_concurrent_jobs_share_one_warm_sandboxed_service_that_loads_once() {
        let fx = Fx::new("share");
        let mut m = fx.manager();
        assert!(tick_until(&mut m, 2, 90.0, ready), "{}", m.report());
        let pid = daemon(&fx);
        #[cfg(unix)]
        assert!(crate::sandbox::is_confined(pid), "the service's daemon runs sandboxed");
        let (mut a, mut b) = (fx.job(&m, 101, &["a1", "a2", "a3"]), fx.job(&m, 102, &["b1", "b2", "b3"]));
        let (oa, ob) = (a.out(), b.out());
        for (o, tag) in [(&oa, "a"), (&ob, "b")] {
            let answers = o["answers"].as_array().unwrap_or_else(|| panic!("{o}"));
            assert_eq!(answers.len(), 3, "{o}");
            for (i, x) in answers.iter().enumerate() {
                assert!(x["text"].as_str().unwrap().starts_with(&format!("{tag}{} -> ", i + 1)), "{x}");
                assert_eq!(x["pid"], pid, "one service for both jobs");
                assert_eq!(x["loads"], 1);
            }
        }
        assert_eq!(fx.loads(), [pid.to_string()], "loaded once for both jobs");
        // the endpoint added nothing to the job's sandbox: it still reaches no unix socket of its own (Linux refuses the
        // socket, macOS the connect)
        #[cfg(unix)]
        assert_eq!(oa["unix_socket"], "refused");
        #[cfg(windows)]
        assert_eq!(crate::sandbox::escape(a.child.id() as i32), None);
        a.end();
        b.end();
        // no users: stopped after its idle timeout, its daemon gone (it exits on the end of its channel)
        assert!(tick_until(&mut m, 0, 30.0, |m| m.running().is_empty()), "{}", m.report());
        assert!(gone(pid) && !fx.data("model.ready").exists());
        // and a later job starts it again, with a new channel
        assert!(tick_until(&mut m, 1, 90.0, ready));
        let mut c = fx.job(&m, 103, &["c1"]);
        assert_eq!(c.out()["answers"][0]["loads"], 1);
        assert_eq!(fx.loads().len(), 2);
        c.end();
        m.stop_all();
    }

    #[test]
    fn a_hold_by_host_protection_stops_the_service_and_keeps_it_down() {
        let fx = Fx::new("hold");
        let mut m = fx.manager();
        assert!(tick_until(&mut m, 1, 90.0, ready), "{}", m.report());
        let pid = daemon(&fx);
        let mut j = fx.job(&m, 201, &["x"]);
        assert!(j.out()["answers"].is_array());
        m.set_held(&[("modelserver/model".to_string(), "preempt_memory".to_string())].into());
        assert!(tick_until(&mut m, 1, 30.0, |m| m.running().is_empty()), "{}", m.report());
        assert!(gone(pid), "its processes are ended");
        assert_eq!(m.held(), BTreeMap::from([("modelserver/model".to_string(), "preempt_memory".to_string())]));
        assert!(!tick_until(&mut m, 1, 2.0, |m| !m.running().is_empty()), "not started again while held, even with users");
        let refused = fx.job(&m, 202, &["y"]).out();
        assert!(refused["error"].as_str().unwrap().contains("service_unavailable"), "{refused}");
        j.end();
        m.set_held(&BTreeMap::new());
        assert!(tick_until(&mut m, 1, 90.0, ready), "free again: started on demand");
        assert_eq!(fx.loads().len(), 2);
        m.stop_all();
    }

    #[test]
    fn a_release_without_the_module_stops_its_service() {
        let fx = Fx::new("unload");
        let mut m = fx.manager();
        assert!(tick_until(&mut m, 1, 90.0, ready), "{}", m.report());
        let pid = daemon(&fx);
        let empty = Release { id: "r_none".into(), dir: fx.release.dir.clone(), modules: vec![] };
        m.configure(&empty, &json!({}), None);
        assert!(gone(pid), "the module's service is stopped with the module");
        assert!(m.running().is_empty() && !fx.data("model.ready").exists());
    }

    /// A connect names the requesting process; on Windows the agent places a handle only in a member of the attempt's
    /// Job Object (on macOS and Linux a descriptor goes to whoever reads the connector).
    #[test]
    fn a_connect_from_outside_the_attempt_is_refused_on_windows() {
        let lookup: Lookup = Arc::new(|_| Err(Refusal::new("service_unavailable", "none")));
        let mut c = Connector::new("model", 7, lookup, Duration::from_secs(1)).unwrap();
        // the attempt's container is someone else's: this test process is outside it
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "endpoints::tests::sleeper", "--ignored"]).stdout(std::process::Stdio::null());
        let mut sleeper = crate::sys::spawn_contained(&mut cmd, false).unwrap();
        let end = c.child.end.take().unwrap();
        c.spawned(Some(sleeper.id() as i32));
        os::send(&end, &line(&json!({"op": "connect", "pid": std::process::id()})), None).unwrap();
        let a = Lines::new(&end).next().unwrap();
        let _ = sleeper.kill();
        let _ = sleeper.wait();
        let want = if cfg!(windows) { "bad_pid" } else { "service_unavailable" };
        assert_eq!(a["error"], want, "{a}");
        drop(c);
    }

    #[test]
    #[ignore = "the process a_connect_from_outside_the_attempt_is_refused_on_windows contains"]
    fn sleeper() {
        std::thread::sleep(Duration::from_secs(30));
    }
}
