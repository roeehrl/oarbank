//! The Windows sandbox backend (spec/sandbox.md; PLAN D30: Windows 10 1809+). Windows has no exec: `oarbank-agent
//! sandbox-exec POLICY.json -- argv` is a small unconfined shim, already inside the attempt's Job Object, that starts
//! the module inside an AppContainer and waits for it, passing its exit code on. Children of the shim stay in the
//! job, and children of the module stay in its AppContainer.
//!
//! - **Files.** One AppContainer profile per module (`Oarbank.<module>`); its SID is granted read and execute on the
//!   policy's read-only roots and full access to its read-write roots. Anything else is reachable only where
//!   Windows grants every AppContainer (`ALL APPLICATION PACKAGES`: the system directories).
//! - **Network.** None without a capability. `egress-any` adds `internetClient`; AppContainer loopback isolation
//!   keeps it off loopback. The egress allowlist goes through the agent's proxy on loopback: the elevated helper (a
//!   LocalSystem service, oarbank-launcher's helper_windows.rs) exempts the container from loopback isolation for
//!   the job and filters every loopback port but the proxy's. Without the helper the allowlist is unavailable.
//! - **IPC.** Named pipes, sections and other objects outside the AppContainer's namespace are denied.
//! - Execution of written files cannot be refused without application control: `exec_writable_deny` is unavailable.
//! - **Handles.** The module inherits its standard handles and, for a job, the control event the agent names in
//!   OARBANK_CONTROL_EVENT (sys.rs `Nudge`), and nothing else the shim inherited: a handle list
//!   (PROC_THREAD_ATTRIBUTE_HANDLE_LIST), as the agent's own CreateProcess passes every inheritable handle it holds,
//!   other jobs' events among them.
//!
//! The parent checks that the shim's children run with an AppContainer token.

use oarbank_core::sandbox::Policy;
use serde_json::{json, Value};
use windows_sys::Win32::Foundation::{CloseHandle, GetHandleInformation, LocalFree, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{GetTokenInformation, TokenIsAppContainer, TOKEN_QUERY};
use windows_sys::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};

fn build() -> u32 {
    use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(v: *mut OSVERSIONINFOW) -> i32;
    }
    let mut v: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
    v.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
    if unsafe { RtlGetVersion(&mut v) } == 0 { v.dwBuildNumber } else { 0 }
}

/// Windows 10 1809 (build 17763) or later.
pub fn available() -> bool {
    build() >= 17763
}

pub const HELPER_PIPE: &str = r"\\.\pipe\oarbank-helper";

/// The helper is installed and listening (`WaitNamedPipe` times out only on a pipe that exists).
pub fn helper_present() -> bool {
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
    let w = wide(HELPER_PIPE);
    if unsafe { WaitNamedPipeW(w.as_ptr(), 1) } != 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(121)              // ERROR_SEM_TIMEOUT: busy, but there
}

/// One request to the helper: a line of JSON each way.
pub fn helper(req: &Value) -> Result<(), String> {
    use std::io::{BufRead, Write};
    let mut f = None;
    for _ in 0..50 {
        match std::fs::OpenOptions::new().read(true).write(true).open(HELPER_PIPE) {
            Ok(x) => {
                f = Some(x);
                break;
            }
            Err(e) if e.raw_os_error() == Some(231) => std::thread::sleep(std::time::Duration::from_millis(100)),  // ERROR_PIPE_BUSY
            Err(e) => return Err(format!("the elevated helper is not reachable: {e}")),
        }
    }
    let mut f = f.ok_or("the elevated helper stayed busy")?;
    f.write_all(format!("{req}\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    std::io::BufReader::new(&f).read_line(&mut line).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&line).map_err(|e| format!("helper reply: {e}"))?;
    if v["ok"].as_bool() == Some(true) { Ok(()) } else { Err(format!("the helper refused: {}", v["error"])) }
}

pub fn report() -> Value {
    if !available() {
        return json!({"backend": null, "enforcement": {}});
    }
    let allowlist = if helper_present() { "enforced" } else { "unavailable" };
    json!({"backend": "appcontainer", "helper": helper_present(), "enforcement": {
        "filesystem": "enforced", "ipc": "enforced", "net.none": "enforced",
        "net.egress-allowlist": allowlist, "net.egress-any": "enforced", "no_loopback": "enforced",
        "no_link_local": "unavailable", "gpu.compute": "enforced", "exec_writable_deny": "unavailable"}})
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Whether a process runs in an AppContainer: None when it is gone (it ended between being listed and asked); a process
/// that cannot be asked for any other reason is not shown to be confined.
fn app_container(pid: u32) -> Option<bool> {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_INVALID_PARAMETER};
    unsafe {
        let p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if p.is_null() {
            return (GetLastError() != ERROR_INVALID_PARAMETER).then_some(false);
        }
        let mut tok: HANDLE = std::ptr::null_mut();
        let ok = OpenProcessToken(p, TOKEN_QUERY, &mut tok);
        CloseHandle(p);
        if ok == 0 {
            return Some(false);
        }
        let mut v: u32 = 0;
        let mut len = 0u32;
        let got = GetTokenInformation(tok, TokenIsAppContainer, &mut v as *mut u32 as *mut _, 4, &mut len);
        CloseHandle(tok);
        Some(got != 0 && v != 0)
    }
}

fn is_app_container(pid: u32) -> bool {
    app_container(pid) == Some(true)
}

/// A process's executable path, or None when it cannot be asked (it ended).
fn image_of(pid: u32) -> Option<String> {
    use windows_sys::Win32::System::Threading::QueryFullProcessImageNameW;
    unsafe {
        let p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if p.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut n = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(p, 0, buf.as_mut_ptr(), &mut n);
        CloseHandle(p);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..n as usize]))
    }
}

/// Every process's parent, from one snapshot.
fn parents() -> std::collections::HashMap<u32, u32> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                                                            TH32CS_SNAPPROCESS};
    let mut out = std::collections::HashMap::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snap, &mut e) != 0;
        while more {
            out.insert(e.th32ProcessID, e.th32ParentProcessID);
            more = Process32NextW(snap, &mut e) != 0;
        }
        CloseHandle(snap);
    }
    out
}

/// The first member of the shim `pid`'s job, besides the shim, that runs outside the AppContainer, described. Nothing a
/// confined process starts can be: its children inherit the AppContainer, the job refuses breakaway, and the console
/// host Windows starts for a console client runs in the client's AppContainer (and the runner has its own windowless
/// one, so its console children share it). So any such member is an escape, with no exception.
pub fn escape(pid: i32) -> Option<String> {
    let bad = crate::sys::group_pids(pid).into_iter().find(|p| *p != pid && app_container(*p as u32) == Some(false))?;
    let parent = parents().get(&(bad as u32)).copied().unwrap_or(0);
    Some(format!("process {bad} ({}, started by {parent}) runs in the job outside the AppContainer",
                 image_of(bad as u32).unwrap_or_else(|| "?".into())))
}

/// `pid` is the shim: confined when every other member of its job runs in an AppContainer (and there is one).
pub fn is_confined(pid: i32) -> bool {
    let others: Vec<i32> = crate::sys::group_pids(pid).into_iter().filter(|p| *p != pid).collect();
    !others.is_empty() && others.iter().all(|p| is_app_container(*p as u32))
}

/// No member of the shim's job besides the shim is outside an AppContainer (after the shim said its runner started:
/// the runner may have ended since).
pub fn holds(pid: i32) -> bool {
    escape(pid).is_none()
}

/// The AppContainer name for a module: `Oarbank.` and the id's letters, digits, dots and dashes (64 at most).
pub fn container_name(module: &str) -> String {
    let clean: String = module.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '-' }).collect();
    let mut n = format!("Oarbank.{clean}");
    n.truncate(64);
    n
}

/// One argument quoted the way CommandLineToArgvW and the C runtime read it back.
pub fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '\n', '"']) {
        return a.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in a.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// What the module may inherit: each handle that is open, inheritable and not listed already (a handle list refuses
/// anything else).
fn inheritable(handles: &[HANDLE]) -> Vec<HANDLE> {
    let mut out: Vec<HANDLE> = vec![];
    for &h in handles {
        let mut flags = 0u32;
        if !h.is_null() && h != INVALID_HANDLE_VALUE && !out.contains(&h)
            && unsafe { GetHandleInformation(h, &mut flags) } != 0 && flags & HANDLE_FLAG_INHERIT != 0 {
            out.push(h);
        }
    }
    out
}

/// The job's control event, from the agent's OARBANK_CONTROL_EVENT (none for a doctor, a service or a probe).
fn control_event() -> HANDLE {
    std::env::var(crate::sys::CONTROL_EVENT_ENV).ok().and_then(|v| v.parse::<usize>().ok()).unwrap_or(0) as HANDLE
}

fn die(code: i32, msg: &str) -> ! {
    eprintln!("sandbox launch: {msg}");
    std::process::exit(code)
}

mod ffi {
    use super::*;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
                                                      GRANT_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W};
    use windows_sys::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SUB_CONTAINERS_AND_OBJECTS_INHERIT};
    use windows_sys::Win32::Security::Isolation::{CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName};

    /// The profile's SID, creating the profile on first use.
    pub fn container_sid(name: &str) -> Result<PSID, String> {
        let n = wide(name);
        let display = wide("Oarbank module");
        let mut sid: PSID = std::ptr::null_mut();
        let hr = unsafe { CreateAppContainerProfile(n.as_ptr(), display.as_ptr(), display.as_ptr(), std::ptr::null(), 0, &mut sid) };
        if hr >= 0 {
            return Ok(sid);
        }
        let hr2 = unsafe { DeriveAppContainerSidFromAppContainerName(n.as_ptr(), &mut sid) };
        if hr2 >= 0 { Ok(sid) } else { Err(format!("AppContainer profile {name}: 0x{:08x}", hr as u32)) }
    }

    /// Let the container read the window station and desktop it inherits. Without it user32 fails to initialise
    /// (ERROR_DLL_INIT_FAILED), and so does everything that loads it: COM (ole32), ctypes, Python's platform module
    /// (WMI). Read access is what that takes (WINSTA_READATTRIBUTES, DESKTOP_READOBJECTS): no clipboard, global
    /// atoms, hooks, journal or new windows on what may be the user's interactive desktop. A private window station
    /// does not work for an AppContainer (user32 still fails), so it is the inherited one. Granting again for the
    /// same container merges into its existing entry.
    pub fn open_desktop(sid: PSID) -> Result<(), String> {
        use windows_sys::Win32::System::StationsAndDesktops::{GetProcessWindowStation, GetThreadDesktop};
        use windows_sys::Win32::System::Threading::GetCurrentThreadId;
        const WINSTA_READATTRIBUTES: u32 = 0x0002;
        const DESKTOP_READOBJECTS: u32 = 0x0001;
        let (ws, desk) = unsafe { (GetProcessWindowStation(), GetThreadDesktop(GetCurrentThreadId())) };
        grant_object(ws as HANDLE, sid, WINSTA_READATTRIBUTES).map_err(|e| format!("window station: {e}"))?;
        grant_object(desk as HANDLE, sid, DESKTOP_READOBJECTS).map_err(|e| format!("desktop: {e}"))
    }

    /// Add an allow entry for `sid` to a window station's or desktop's DACL.
    fn grant_object(h: HANDLE, sid: PSID, mask: u32) -> Result<(), String> {
        use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SetSecurityInfo, SE_WINDOW_OBJECT};
        use windows_sys::Win32::Security::NO_INHERITANCE;
        unsafe {
            let mut old: *mut ACL = std::ptr::null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let e = GetSecurityInfo(h, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(),
                                    &mut old, std::ptr::null_mut(), &mut sd);
            if e != 0 {
                return Err(format!("reading its ACL failed ({e})"));
            }
            let ea = EXPLICIT_ACCESS_W {
                grfAccessPermissions: mask, grfAccessMode: GRANT_ACCESS, grfInheritance: NO_INHERITANCE,
                Trustee: TRUSTEE_W { pMultipleTrustee: std::ptr::null_mut(), MultipleTrusteeOperation: 0, TrusteeForm: TRUSTEE_IS_SID,
                                     TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP, ptstrName: sid as *mut u16 },
            };
            let mut new: *mut ACL = std::ptr::null_mut();
            let e = SetEntriesInAclW(1, &ea, old, &mut new);
            LocalFree(sd as _);
            if e != 0 {
                return Err(format!("building its ACL failed ({e})"));
            }
            let e = SetSecurityInfo(h, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), new,
                                    std::ptr::null());
            LocalFree(new as _);
            if e != 0 {
                return Err(format!("setting its ACL failed ({e})"));
            }
        }
        Ok(())
    }

    /// The machine's lock on ACL edits by shims (a named mutex in this session, which every shim of one agent shares),
    /// held until dropped. A shim that dies holding it abandons it, and the next one takes it.
    pub struct AclLock(HANDLE);

    impl AclLock {
        pub fn take() -> AclLock {
            use windows_sys::Win32::System::Threading::{CreateMutexW, WaitForSingleObject, INFINITE};
            let name = wide("Local\\oarbank-sandbox-acl");
            let m = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
            if m.is_null() {
                die(70, &format!("the ACL lock: {}", std::io::Error::last_os_error()));
            }
            unsafe { WaitForSingleObject(m, INFINITE) };
            AclLock(m)
        }
    }

    impl Drop for AclLock {
        fn drop(&mut self) {
            use windows_sys::Win32::System::Threading::ReleaseMutex;
            unsafe {
                ReleaseMutex(self.0);
                CloseHandle(self.0);
            }
        }
    }

    /// Whether `acl` already allows `sid` at least `mask`, inherited by files and folders below.
    unsafe fn allows(acl: *const ACL, sid: PSID, mask: u32) -> bool {
        use windows_sys::Win32::Security::{EqualSid, GetAce, ACCESS_ALLOWED_ACE, CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};
        const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
        if acl.is_null() {
            return false;
        }
        for i in 0..(*acl).AceCount as u32 {
            let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
            if GetAce(acl, i, &mut ace) == 0 {
                continue;
            }
            let a = &*(ace as *const ACCESS_ALLOWED_ACE);
            let inherit = (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8;
            if a.Header.AceType == ACCESS_ALLOWED_ACE_TYPE && a.Header.AceFlags & inherit == inherit && a.Mask & mask == mask
                && EqualSid(&a.SidStart as *const u32 as PSID, sid) != 0 {
                return true;
            }
        }
        false
    }

    /// Add an inheritable allow entry for `sid` to `path`'s DACL, unless it has one already (writing it again would
    /// walk the whole tree below to propagate it).
    pub fn grant(path: &str, sid: PSID, mask: u32) -> Result<(), String> {
        let p = wide(path);
        unsafe {
            let mut old: *mut ACL = std::ptr::null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let e = GetNamedSecurityInfoW(p.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(),
                                          &mut old, std::ptr::null_mut(), &mut sd);
            if e != 0 {
                return Err(format!("{path}: reading its ACL failed ({e})"));
            }
            if allows(old, sid, mask) {
                LocalFree(sd as _);
                return Ok(());
            }
            let ea = EXPLICIT_ACCESS_W {
                grfAccessPermissions: mask, grfAccessMode: GRANT_ACCESS, grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                Trustee: TRUSTEE_W { pMultipleTrustee: std::ptr::null_mut(), MultipleTrusteeOperation: 0, TrusteeForm: TRUSTEE_IS_SID,
                                     TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP, ptstrName: sid as *mut u16 },
            };
            let mut new: *mut ACL = std::ptr::null_mut();
            let e = SetEntriesInAclW(1, &ea, old, &mut new);
            if e != 0 {
                LocalFree(sd as _);
                return Err(format!("{path}: building its ACL failed ({e})"));
            }
            let e = SetNamedSecurityInfoW(p.as_ptr() as *mut u16, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(),
                                          std::ptr::null_mut(), new, std::ptr::null());
            LocalFree(new as _);
            LocalFree(sd as _);
            if e != 0 {
                return Err(format!("{path}: setting its ACL failed ({e})"));
            }
        }
        Ok(())
    }
}

/// The `sandbox-exec` subcommand on Windows: start argv in the module's AppContainer, wait, exit with its code.
pub fn exec(args: &[String]) -> ! {
    use windows_sys::Win32::Security::{CreateWellKnownSid, WinCapabilityInternetClientSid, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES};
    const SE_GROUP_ENABLED: u32 = 0x0000_0004;
    use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
    use windows_sys::Win32::System::Threading::{CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
                                                InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
                                                CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST,
                                                PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                                STARTF_USESTDHANDLES, STARTUPINFOEXW};
    // taken first, so the runner's environment does not name it
    let launcher = crate::sandbox::Launcher::take();
    let Some(sep) = args.iter().position(|a| a == "--") else { die(64, "usage: sandbox-exec POLICY.json -- argv") };
    if sep != 1 || args.len() <= sep + 1 {
        die(64, "needs a policy file and argv");
    }
    let pol: Policy = match std::fs::read(&args[0]).map_err(|e| e.to_string()).and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string())) {
        Ok(p) => p,
        Err(e) => die(70, &format!("policy {}: {e}", args[0])),
    };
    let name = container_name(&pol.module);
    let sid = match ffi::container_sid(&name) {
        Ok(s) => s,
        Err(e) => die(70, &e),
    };
    // the allowlist: the helper opens loopback for this container to the proxy's port only, for this job
    let proxy = match (pol.net.as_str(), pol.proxy_port) {
        ("egress-allowlist", Some(port)) => {
            if let Err(e) = helper(&json!({"op": "allow", "container": name, "port": port})) {
                die(70, &e);
            }
            Some(port)
        }
        ("egress-allowlist", None) => die(70, "an egress allowlist without the proxy port"),
        _ => None,
    };
    let ro = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    // one shim at a time edits ACLs: an edit reads the ACL and writes it back with its entry, so two shims granting the
    // same path (the runtime's Python, a tool) at once could each drop the other's entry
    let acl_lock = ffi::AclLock::take();
    // read-only roots the agent does not own (a Python under Program Files) cannot take a new entry, and every
    // AppContainer can already read the system's: a failed read grant only means the module may not read that path
    for p in pol.ro.iter().chain(pol.exe.iter()) {
        if let Err(e) = ffi::grant(p, sid, ro) {
            eprintln!("sandbox launch: {e} (left as it is)");
        }
    }
    for p in &pol.rw {
        if let Err(e) = ffi::grant(p, sid, FILE_ALL_ACCESS) {
            die(70, &e);
        }
    }
    // user32 (and with it COM, ctypes, Python's platform module) initialises only if the container can read the window
    // station and desktop it starts on
    if let Err(e) = ffi::open_desktop(sid) {
        eprintln!("sandbox launch: {e} (user32, COM and ctypes will not load)");
    }
    drop(acl_lock);
    // capabilities: internetClient for egress-any only
    let mut cap_sid = [0u8; 68];
    let mut caps: Vec<SID_AND_ATTRIBUTES> = vec![];
    if pol.net == "egress-any" {
        let mut n = cap_sid.len() as u32;
        if unsafe { CreateWellKnownSid(WinCapabilityInternetClientSid, std::ptr::null_mut(), cap_sid.as_mut_ptr() as _, &mut n) } == 0 {
            die(70, "internetClient capability SID");
        }
        caps.push(SID_AND_ATTRIBUTES { Sid: cap_sid.as_mut_ptr() as _, Attributes: SE_GROUP_ENABLED });
    }
    let sc = SECURITY_CAPABILITIES { AppContainerSid: sid, Capabilities: if caps.is_empty() { std::ptr::null_mut() } else { caps.as_mut_ptr() },
                                     CapabilityCount: caps.len() as u32, Reserved: 0 };
    unsafe {
        let (stdin, stdout, stderr) = (GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE), GetStdHandle(STD_ERROR_HANDLE));
        let inherit = inheritable(&[stdin, stdout, stderr, control_event()]);
        let mut size = 0usize;
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size);
        let mut buf = vec![0u8; size];
        let list = buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        if InitializeProcThreadAttributeList(list, 2, 0, &mut size) == 0
            || UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize, &sc as *const _ as *const _,
                                         std::mem::size_of::<SECURITY_CAPABILITIES>(), std::ptr::null_mut(), std::ptr::null()) == 0
            || (!inherit.is_empty()
                && UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize, inherit.as_ptr() as *const _,
                                             std::mem::size_of_val(inherit.as_slice()), std::ptr::null_mut(), std::ptr::null()) == 0) {
            die(70, &format!("attribute list: {}", std::io::Error::last_os_error()));
        }
        let mut si: STARTUPINFOEXW = std::mem::zeroed();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = stdin;
        si.StartupInfo.hStdOutput = stdout;
        si.StartupInfo.hStdError = stderr;
        si.lpAttributeList = list;
        let mut cmd = wide(&args[sep + 1..].iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" "));
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let ok = CreateProcessW(std::ptr::null(), cmd.as_mut_ptr(), std::ptr::null(), std::ptr::null(), (!inherit.is_empty()).into(),
                                // a console without a window: its host runs in the runner's AppContainer, and the
                                // runner's console children share it (with none, each would get a host of its own,
                                // which fails to start in the AppContainer and takes the child down, 0xC0000142)
                                EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, std::ptr::null(), std::ptr::null(), &si.StartupInfo, &mut pi);
        DeleteProcThreadAttributeList(list);
        if ok == 0 {
            die(71, &format!("start {}: {}", args[sep + 1], std::io::Error::last_os_error()));
        }
        // the runner exists, in the AppContainer and in this shim's job (born there: the agent put the shim in it
        // before it ran)
        if let Some(l) = launcher {
            l.confined();
        }
        CloseHandle(pi.hThread);
        WaitForSingleObject(pi.hProcess, INFINITE);
        let mut code = 1u32;
        GetExitCodeProcess(pi.hProcess, &mut code);
        CloseHandle(pi.hProcess);
        if let Some(port) = proxy {
            let _ = helper(&json!({"op": "release", "container": name, "port": port}));
        }
        std::process::exit(code as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_quoting() {
        assert_eq!(container_name("dev.example.render frames"), "Oarbank.dev.example.render-frames");
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg(r"C:\Program Files\x"), r#""C:\Program Files\x""#);
        assert_eq!(quote_arg(r#"a "b" c\"#), r#""a \"b\" c\\""#);
        assert_eq!(quote_arg(""), r#""""#);
    }

    /// The test binary answers `sandbox-exec` itself, as the agent's main does (sandbox_linux.rs and services.rs do
    /// the same on Linux and macOS): a C runtime initialiser, run before the test harness starts.
    #[used]
    #[unsafe(link_section = ".CRT$XCU")]
    static LAUNCHER: extern "C" fn() = {
        extern "C" fn launcher() {
            let raw: Vec<String> = std::env::args().collect();
            if raw.get(1).map(String::as_str) == Some("sandbox-exec") {
                super::exec(&raw[2..]);
            }
        }
        launcher
    };

    fn python() -> (std::path::PathBuf, String) {
        let py = std::env::var("OARBANK_TEST_PYTHON").map(std::path::PathBuf::from).ok()
            .or_else(|| crate::runtime::which("python")).expect("a Python (OARBANK_TEST_PYTHON or on PATH)");
        let real = std::fs::canonicalize(&py).unwrap().display().to_string();
        let home = std::path::Path::new(real.strip_prefix(r"\\?\").unwrap_or(&real)).parent().unwrap().display().to_string();
        (py, home)
    }

    /// A Python runner through the shim, contained as the agent contains it: (the shim, its work directory, its stderr
    /// file). `script` gets the work directory as argv[1].
    fn runner(tag: &str, script: &str) -> (std::process::Child, std::path::PathBuf) {
        use crate::sandbox::{Came, ConfinedSignal, CONFINE_GUARD};
        let (py, home) = python();
        let d = std::env::temp_dir().join(format!("oarbank-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mut pol = Policy::new(format!("dev.test.{tag}"));
        pol.ro = vec![home];
        pol.rw = vec![d.display().to_string()];
        pol.exe = Some(py.display().to_string());
        let pf = d.with_extension("policy.json");
        std::fs::write(&pf, serde_json::to_vec(&pol).unwrap()).unwrap();
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.arg("sandbox-exec").arg(&pf).arg("--").arg(&py).args(["-I", "-c", script]).arg(&d).current_dir(&d)
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null())
            .stderr(std::fs::File::create(d.join("stderr")).unwrap());
        let signal = ConfinedSignal::new().unwrap();
        signal.prepare(&mut cmd);
        let shim = crate::sys::spawn_contained(&mut cmd, false).unwrap();
        assert_eq!(signal.wait(shim.id(), CONFINE_GUARD), Came::Confined);
        (shim, d)
    }

    /// The runner's `name` file, once written (up to 120 s on a loaded host), or None if the shim ended first.
    fn read(shim: &mut std::process::Child, d: &std::path::Path, name: &str) -> Option<String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while std::time::Instant::now() < deadline {
            if let Ok(s) = std::fs::read_to_string(d.join(name)) {
                return Some(s);
            }
            if shim.try_wait().unwrap().is_some() {
                return std::fs::read_to_string(d.join(name)).ok();
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        None
    }

    fn end(mut shim: std::process::Child, d: &std::path::Path) -> String {
        let pid = shim.id() as i32;
        crate::sys::signal_group(pid, crate::sys::Sig::Kill);
        let _ = shim.wait();
        crate::sys::release(pid);
        let err = std::fs::read_to_string(d.join("stderr")).unwrap_or_default();
        let _ = std::fs::remove_dir_all(d);
        let _ = std::fs::remove_file(d.with_extension("policy.json"));
        err
    }

    /// A runner whose first statement starts 20 processes (plain console ones, as a module would): the runner and
    /// every one of them are in the job the agent made for the shim, all alive and in the AppContainer, with the
    /// runner's one windowless console host besides them (the shim is in the job before it runs, so all it starts is
    /// born there).
    #[test]
    fn a_runner_and_everything_it_starts_at_once_are_in_its_job() {
        let script = "import subprocess, sys\n\
                      ps = [subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']) for _ in range(20)]\n\
                      import os, time\n\
                      time.sleep(1)\n\
                      open(sys.argv[1] + '/pids.tmp', 'w').write(' '.join([str(os.getpid())] + [str(p.pid) for p in ps if p.poll() is None]))\n\
                      os.replace(sys.argv[1] + '/pids.tmp', sys.argv[1] + '/pids')\n\
                      time.sleep(120)";
        let (mut shim, d) = runner("born", script);
        let shim_pid = shim.id() as i32;
        let started: Vec<i32> = read(&mut shim, &d, "pids").unwrap_or_default().split_whitespace().filter_map(|p| p.parse().ok()).collect();
        let members = crate::sys::group_pids(shim_pid);
        let hosts: Vec<i32> = members.iter().copied().filter(|p| image_of(*p as u32).is_some_and(|i| i.to_ascii_lowercase().ends_with(r"\system32\conhost.exe")))
            .collect();
        let ever = crate::sys::processes_ever(shim_pid);
        let escaped = escape(shim_pid);
        let err = end(shim, &d);
        assert_eq!(started.len(), 21, "the runner and its 20 children, alive a second later: {started:?}\n{err}");
        let outside: Vec<&i32> = started.iter().filter(|p| !members.contains(p)).collect();
        assert!(outside.is_empty(), "outside the job: {outside:?} (members {members:?})");
        assert!(hosts.len() <= 1, "one console host at most, the runner's: {hosts:?}");
        assert_eq!(ever, Some(22 + hosts.len() as u32), "members {members:?}, started {started:?}");
        assert_eq!(escaped, None);
    }

    /// What a runner may do with consoles and processes keeps it confined: console children run (sharing the runner's
    /// console), AllocConsole is refused (it has one), breaking away from the job is refused, and the escape watch
    /// sees nothing outside the AppContainer while they run.
    #[test]
    fn console_children_allocconsole_and_breakaway_stay_confined() {
        let script = r#"
import ctypes, subprocess, sys, time
k = ctypes.WinDLL("kernel32", use_last_error=True)
r = {}
c = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
cmd = subprocess.Popen(r'C:\Windows\System32\cmd.exe /c ""%s" -c "import time; time.sleep(120)""' % sys.executable, cwd=sys.argv[1])
time.sleep(1)
r["console_child"] = c.poll()
r["cmd_child"] = cmd.poll()
r["alloc"] = k.AllocConsole()
try:
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"], creationflags=0x01000000)
    r["breakaway"] = "started"
except OSError as e:
    r["breakaway"] = e.winerror
open(sys.argv[1] + "/r.tmp", "w").write(repr(r))
import os
os.replace(sys.argv[1] + "/r.tmp", sys.argv[1] + "/r")
time.sleep(120)
"#;
        let (mut shim, d) = runner("consoles", script);
        let shim_pid = shim.id() as i32;
        let got = read(&mut shim, &d, "r");
        let mut escapes = vec![];
        for _ in 0..20 {
            escapes.extend(escape(shim_pid));
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let members: Vec<(i32, bool)> = crate::sys::group_pids(shim_pid).into_iter().filter(|p| *p != shim_pid)
            .map(|p| (p, is_app_container(p as u32))).collect();
        let err = end(shim, &d);
        assert_eq!(got.as_deref(), Some("{'console_child': None, 'cmd_child': None, 'alloc': 0, 'breakaway': 5}"), "{err}");
        assert!(escapes.is_empty(), "{escapes:?}");
        assert!(members.len() >= 4 && members.iter().all(|(_, ac)| *ac), "{members:?}");
    }

    /// Anything in the job outside the AppContainer is an escape: here a plain process the test puts there itself.
    #[test]
    fn a_member_outside_the_appcontainer_is_an_escape() {
        let (mut shim, d) = runner("intruder", "import sys, time\nopen(sys.argv[1] + '/up', 'w').write('1')\ntime.sleep(120)");
        let shim_pid = shim.id() as i32;
        assert!(read(&mut shim, &d, "up").is_some());
        assert_eq!(escape(shim_pid), None);
        let ping = format!(r"{}\System32\PING.EXE", std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()));
        let mut intruder = std::process::Command::new(ping).args(["-n", "120", "127.0.0.1"]).stdout(std::process::Stdio::null()).spawn().unwrap();
        crate::sys::join(shim_pid, intruder.id()).unwrap();
        let seen = escape(shim_pid);
        let _ = intruder.kill();
        let _ = intruder.wait();
        end(shim, &d);
        let seen = seen.expect("the intruder is seen");
        assert!(seen.contains(&intruder.id().to_string()) && seen.to_ascii_lowercase().contains("ping.exe"), "{seen}");
    }
}
