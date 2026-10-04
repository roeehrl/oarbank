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

fn is_app_container(pid: u32) -> bool {
    unsafe {
        let p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if p.is_null() {
            return false;
        }
        let mut tok: HANDLE = std::ptr::null_mut();
        let ok = OpenProcessToken(p, TOKEN_QUERY, &mut tok);
        CloseHandle(p);
        if ok == 0 {
            return false;
        }
        let mut v: u32 = 0;
        let mut len = 0u32;
        let got = GetTokenInformation(tok, TokenIsAppContainer, &mut v as *mut u32 as *mut _, 4, &mut len);
        CloseHandle(tok);
        got != 0 && v != 0
    }
}

/// `pid` is the shim: confined when every other member of its job runs in an AppContainer (and there is one).
pub fn is_confined(pid: i32) -> bool {
    let others: Vec<i32> = crate::sys::group_pids(pid).into_iter().filter(|p| *p != pid).collect();
    !others.is_empty() && others.iter().all(|p| is_app_container(*p as u32))
}

/// No member of the shim's job besides the shim is outside an AppContainer (after the shim said its runner started:
/// the runner may have ended since).
pub fn holds(pid: i32) -> bool {
    crate::sys::group_pids(pid).into_iter().filter(|p| *p != pid).all(|p| is_app_container(p as u32))
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

    /// Add an inheritable allow entry for `sid` to `path`'s DACL.
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
                                                DETACHED_PROCESS, EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST,
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
        // kept open until the job exits: the window station goes away with its last handle
        // user32 (and with it COM, ctypes, Python's platform module) initialises only if the container can read the
        // window station and desktop it starts on
        if let Err(e) = ffi::open_desktop(sid) {
            eprintln!("sandbox launch: {e} (user32, COM and ctypes will not load)");
        }
        let mut cmd = wide(&args[sep + 1..].iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" "));
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let ok = CreateProcessW(std::ptr::null(), cmd.as_mut_ptr(), std::ptr::null(), std::ptr::null(), (!inherit.is_empty()).into(),
                                // no console of its own (the shim has none to share): a console host would join
                                // the job outside the AppContainer
                                EXTENDED_STARTUPINFO_PRESENT | DETACHED_PROCESS, std::ptr::null(), std::ptr::null(), &si.StartupInfo, &mut pi);
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
}
