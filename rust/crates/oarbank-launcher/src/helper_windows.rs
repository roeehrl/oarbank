//! The elevated helper for enforced egress allowlists on Windows (PLAN D30). An AppContainer cannot reach loopback,
//! where the agent's egress proxy listens. The helper, a LocalSystem service the MSI installs (`oarbank-launcher
//! helper-main`), lets one module container reach exactly its job's proxy port:
//!
//! - `{"op": "allow", "container": "Oarbank.<module>", "port": P}`: a loopback exemption for that AppContainer, and
//!   Windows Filtering Platform filters that block its TCP connections to every loopback port but P;
//! - `{"op": "release", "container": …, "port": P}`: the filters go, and the exemption when no job still needs it;
//! - `{"op": "sessions"}`: the sessions WTS lists (helper_sessions.rs), which host protection needs and the agent's
//!   virtual account may not read itself.
//!
//! Only `Oarbank.*` containers are served. The pipe `\\.\pipe\oarbank-helper` admits SYSTEM, administrators, the
//! agent's service account and interactive users. The filters live in a dynamic WFP session (they end with the
//! helper), and the exemptions the helper added are listed in a state file and removed when it starts again.
//!
//! It also keeps a session helper (`oarbank-agent.exe session-helper`, the agent binary installed beside it) running
//! in each person's session, started with that person's token and no window: the agent's system service, in session
//! 0, cannot see a session's foreground window, last input or (another account's) command lines, and the session
//! helper tells it. Only a LocalSystem service may start a process in another session (WTSQueryUserToken).

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::FromRawHandle;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::NetworkManagement::WindowsFirewall::{NetworkIsolationGetAppContainerConfig, NetworkIsolationSetAppContainerConfig};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                                                  ConvertStringSidToSidW};
use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows_sys::Win32::Security::{GetLengthSid, LookupAccountNameW, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SID,
                                   SID_AND_ATTRIBUTES};
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapFree};
use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
                                        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT};

pub const PIPE: &str = r"\\.\pipe\oarbank-helper";
/// The helper's service name (deploy/windows/oarbank-agent.wxs installs it).
pub const SERVICE: &str = "OarbankHelper";
const PIPE_ACCESS_DUPLEX: u32 = 3;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn state_file() -> PathBuf {
    std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Oarbank").join("helper-exemptions.json")
}

/// A SID as owned bytes, from a container name.
fn container_sid(name: &str) -> Result<Vec<u8>> {
    if !name.starts_with("Oarbank.") || name.len() > 64 || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        bail!("not an Oarbank container: {name:?}");
    }
    let n = wide(name);
    let mut sid: PSID = std::ptr::null_mut();
    let hr = unsafe { DeriveAppContainerSidFromAppContainerName(n.as_ptr(), &mut sid) };
    if hr < 0 {
        bail!("no AppContainer {name} (0x{:08x})", hr as u32);
    }
    let bytes = unsafe { std::slice::from_raw_parts(sid as *const u8, GetLengthSid(sid) as usize).to_vec() };
    unsafe { windows_sys::Win32::Security::FreeSid(sid) };
    Ok(bytes)
}

fn sid_string(sid: &[u8]) -> String {
    let mut s: windows_sys::core::PWSTR = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid.as_ptr() as PSID, &mut s) } == 0 {
        return String::new();
    }
    let len = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
    let out = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(s, len) });
    unsafe { LocalFree(s as _) };
    out
}

fn sid_from_string(s: &str) -> Option<Vec<u8>> {
    let w = wide(s);
    let mut sid: PSID = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut sid) } == 0 {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(sid as *const u8, GetLengthSid(sid) as usize).to_vec() };
    unsafe { LocalFree(sid as _) };
    Some(bytes)
}

/// The loopback exemptions now in force, as SID bytes.
fn exemptions() -> Vec<Vec<u8>> {
    let (mut n, mut arr): (u32, *mut SID_AND_ATTRIBUTES) = (0, std::ptr::null_mut());
    if unsafe { NetworkIsolationGetAppContainerConfig(&mut n, &mut arr) } != 0 || arr.is_null() {
        return vec![];
    }
    let mut out = vec![];
    unsafe {
        for i in 0..n as usize {
            let sa = &*arr.add(i);
            out.push(std::slice::from_raw_parts(sa.Sid as *const u8, GetLengthSid(sa.Sid) as usize).to_vec());
            HeapFree(GetProcessHeap(), 0, sa.Sid as _);
        }
        HeapFree(GetProcessHeap(), 0, arr as _);
    }
    out
}

fn set_exemptions(list: &[Vec<u8>]) -> Result<()> {
    let mut v: Vec<SID_AND_ATTRIBUTES> = list.iter().map(|s| SID_AND_ATTRIBUTES { Sid: s.as_ptr() as PSID, Attributes: 0 }).collect();
    let e = unsafe { NetworkIsolationSetAppContainerConfig(v.len() as u32, v.as_mut_ptr()) };
    if e != 0 {
        bail!("setting loopback exemptions failed ({e})");
    }
    Ok(())
}

fn save_added(added: &[Vec<u8>]) {
    let list: Vec<String> = added.iter().map(|s| sid_string(s)).collect();
    if let Some(d) = state_file().parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(state_file(), serde_json::to_vec(&list).unwrap_or_default());
}

struct Helper {
    engine: HANDLE,
    /// (container SID, port) → filter ids
    filters: HashMap<(Vec<u8>, u16), Vec<u64>>,
    /// exemptions this helper added (removed again when no filter needs them)
    added: Vec<Vec<u8>>,
}

impl Helper {
    fn open() -> Result<Helper> {
        let mut name = wide("Oarbank helper");
        let session = FWPM_SESSION0 { flags: FWPM_SESSION_FLAG_DYNAMIC, displayData: FWPM_DISPLAY_DATA0 { name: name.as_mut_ptr(), description: std::ptr::null_mut() },
                                      ..Default::default() };
        let mut engine: HANDLE = std::ptr::null_mut();
        let e = unsafe { FwpmEngineOpen0(std::ptr::null(), 0xFFFF_FFFF, std::ptr::null(), &session, &mut engine) };
        if e != 0 {
            bail!("opening the filtering engine failed ({e})");
        }
        // exemptions a previous run added and could not take back
        if let Some(prev) = std::fs::read(state_file()).ok().and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok()) {
            let stale: Vec<Vec<u8>> = prev.iter().filter_map(|s| sid_from_string(s)).collect();
            let keep: Vec<Vec<u8>> = exemptions().into_iter().filter(|s| !stale.contains(s)).collect();
            let _ = set_exemptions(&keep);
        }
        save_added(&[]);
        Ok(Helper { engine, filters: HashMap::new(), added: vec![] })
    }

    /// Block the container's TCP connections to loopback (IPv4 127/8 and ::1) on every port but `port`.
    fn add_filters(&self, sid: &[u8], port: u16) -> Result<Vec<u64>> {
        let mut ids = vec![];
        let mut v4 = FWP_V4_ADDR_AND_MASK { addr: 0x7F00_0000, mask: 0xFF00_0000 };
        let mut v6 = FWP_BYTE_ARRAY16 { byteArray16: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] };
        let mut name = wide("Oarbank: a module reaches only its egress proxy on loopback");
        for (layer, addr) in [(FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                               FWP_CONDITION_VALUE0 { r#type: FWP_V4_ADDR_MASK, Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: &mut v4 } }),
                              (FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                               FWP_CONDITION_VALUE0 { r#type: FWP_BYTE_ARRAY16_TYPE, Anonymous: FWP_CONDITION_VALUE0_0 { byteArray16: &mut v6 } })] {
            let mut conds = [
                FWPM_FILTER_CONDITION0 { fieldKey: FWPM_CONDITION_ALE_PACKAGE_ID, matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 { r#type: FWP_SID, Anonymous: FWP_CONDITION_VALUE0_0 { sid: sid.as_ptr() as *mut SID } } },
                FWPM_FILTER_CONDITION0 { fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS, matchType: FWP_MATCH_EQUAL, conditionValue: addr },
                FWPM_FILTER_CONDITION0 { fieldKey: FWPM_CONDITION_IP_REMOTE_PORT, matchType: FWP_MATCH_NOT_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 { r#type: FWP_UINT16, Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port } } },
            ];
            let mut f = FWPM_FILTER0::default();
            f.displayData.name = name.as_mut_ptr();
            f.layerKey = layer;
            f.weight = FWP_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_VALUE0_0 { uint8: 15 } };
            f.numFilterConditions = conds.len() as u32;
            f.filterCondition = conds.as_mut_ptr();
            f.action.r#type = FWP_ACTION_BLOCK;
            let mut id = 0u64;
            let e = unsafe { FwpmFilterAdd0(self.engine, &f, std::ptr::null_mut(), &mut id) };
            if e != 0 {
                for i in &ids {
                    unsafe { FwpmFilterDeleteById0(self.engine, *i) };
                }
                bail!("adding a loopback filter failed ({e})");
            }
            ids.push(id);
        }
        Ok(ids)
    }

    fn handle(&mut self, req: &Value) -> Result<Value> {
        if req["op"].as_str() == Some("sessions") {
            return Ok(crate::helper_sessions::reply(crate::helper_sessions::read().as_deref()));
        }
        let name = req["container"].as_str().context("no container")?;
        let port = req["port"].as_u64().filter(|p| (1024..=65535).contains(p)).context("no port in 1024-65535")? as u16;
        let sid = container_sid(name)?;
        match req["op"].as_str() {
            Some("allow") => {
                if !self.filters.contains_key(&(sid.clone(), port)) {
                    let ids = self.add_filters(&sid, port)?;           // filters first: never an exemption without them
                    self.filters.insert((sid.clone(), port), ids);
                }
                let mut now = exemptions();
                if !now.contains(&sid) {
                    now.push(sid.clone());
                    set_exemptions(&now)?;
                    self.added.push(sid);
                    save_added(&self.added);
                }
                Ok(json!({"ok": true}))
            }
            Some("release") => {
                if let Some(ids) = self.filters.remove(&(sid.clone(), port)) {
                    for i in ids {
                        unsafe { FwpmFilterDeleteById0(self.engine, i) };
                    }
                }
                if self.added.contains(&sid) && !self.filters.keys().any(|(s, _)| *s == sid) {
                    let keep: Vec<Vec<u8>> = exemptions().into_iter().filter(|s| *s != sid).collect();
                    set_exemptions(&keep)?;
                    self.added.retain(|s| *s != sid);
                    save_added(&self.added);
                }
                Ok(json!({"ok": true}))
            }
            other => bail!("unknown op {other:?}"),
        }
    }
}

/// SDDL for the pipe: full access for SYSTEM and administrators, read and write for interactive users and, when it
/// exists, the agent's service account.
fn pipe_sddl() -> String {
    let mut sddl = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)");
    let acct = wide(&format!(r"NT SERVICE\{}", crate::LABEL));
    let mut sid = [0u8; 68];
    let (mut sid_len, mut dom_len, mut use_) = (sid.len() as u32, 64u32, 0i32);
    let mut dom = [0u16; 64];
    if unsafe { LookupAccountNameW(std::ptr::null(), acct.as_ptr(), sid.as_mut_ptr() as PSID, &mut sid_len, dom.as_mut_ptr(), &mut dom_len, &mut use_) } != 0 {
        sddl += &format!("(A;;GRGW;;;{})", sid_string(&sid[..sid_len as usize]));
    }
    sddl
}

/// A session helper started in one session.
struct SessionHelper {
    process: HANDLE,
    started: std::time::Instant,
}

/// Start `exe args` in a person's session, as that person, with no window (the agent's session helper).
fn start_in_session(exe: &std::path::Path, args: &str, session: u32) -> Option<HANDLE> {
    use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows_sys::Win32::System::RemoteDesktop::WTSQueryUserToken;
    use windows_sys::Win32::System::Threading::{CreateProcessAsUserW, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW,
                                                CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW};
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: LocalSystem may ask for a session's user token; nothing is held on failure.
    if unsafe { WTSQueryUserToken(session, &mut token) } == 0 {
        return None;
    }
    let mut env: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: a live token; the block is destroyed below.
    let have_env = unsafe { CreateEnvironmentBlock(&mut env, token, 0) } != 0;
    let app = wide(&exe.display().to_string());
    let mut cmd = wide(&format!("\"{}\" {args}", exe.display()));
    let mut desktop = wide(r"winsta0\default");
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.lpDesktop = desktop.as_mut_ptr();
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: NUL-terminated strings that outlive the call, a live token, and the environment block (or none).
    let ok = unsafe {
        CreateProcessAsUserW(token, app.as_ptr(), cmd.as_mut_ptr(), std::ptr::null(), std::ptr::null(), 0,
                             CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP,
                             if have_env { env } else { std::ptr::null_mut() }, std::ptr::null(), &si, &mut pi)
    } != 0;
    unsafe {
        if have_env {
            DestroyEnvironmentBlock(env);
        }
        CloseHandle(token);
    }
    if !ok {
        return None;
    }
    unsafe { CloseHandle(pi.hThread) };
    Some(pi.hProcess)
}

fn running(h: HANDLE) -> bool {
    use windows_sys::Win32::Foundation::STILL_ACTIVE;
    use windows_sys::Win32::System::Threading::GetExitCodeProcess;
    let mut code = 0u32;
    unsafe { GetExitCodeProcess(h, &mut code) != 0 && code == STILL_ACTIVE as u32 }
}

/// Keep a session helper in every session a person is logged on to: started when the session appears and again
/// when it exits (no sooner than a minute after the previous start), ended when the service stops.
fn keep_session_helpers(agent: PathBuf) {
    use windows_sys::Win32::System::RemoteDesktop::WTSActive;
    use windows_sys::Win32::System::Threading::TerminateProcess;
    let mut helpers: HashMap<u32, SessionHelper> = HashMap::new();
    while !crate::STOP.load(std::sync::atomic::Ordering::SeqCst) {
        let active: Vec<u32> = crate::helper_sessions::read().unwrap_or_default().iter()
            .filter(|s| s.id != 0 && s.state == WTSActive as u32).map(|s| s.id).collect();
        helpers.retain(|id, h| {
            let keep = active.contains(id) && (running(h.process) || h.started.elapsed().as_secs() < 60);
            if !keep {
                unsafe { CloseHandle(h.process) };
            }
            keep
        });
        for id in active {
            if !helpers.contains_key(&id) && agent.exists() {
                if let Some(process) = start_in_session(&agent, "session-helper", id) {
                    helpers.insert(id, SessionHelper { process, started: std::time::Instant::now() });
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    for h in helpers.into_values() {
        unsafe {
            TerminateProcess(h.process, 0);
            CloseHandle(h.process);
        }
    }
}

/// Serve requests until the service stops, one connection at a time, and keep the session helpers on a thread of
/// their own. The service process ends when this returns, so it first waits for that thread to end the session
/// helpers: otherwise every stop or upgrade would leave them running beside the next helper's.
pub fn serve() -> Result<()> {
    // the agent binary installed beside this launcher (Program Files: administrators' only)
    let agent = std::env::current_exe()?.with_file_name("oarbank-agent.exe");
    let keeper = std::thread::spawn(move || keep_session_helpers(agent));
    let r = serve_requests();
    crate::stop_now();
    let _ = keeper.join();
    r
}

fn serve_requests() -> Result<()> {
    let mut h = Helper::open()?;
    let sddl = wide(&pipe_sddl());
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut sd, std::ptr::null_mut()) } == 0 {
        bail!("pipe security descriptor: {}", std::io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
    serve_pipe(PIPE, Some(&sa), &|| crate::STOP.load(std::sync::atomic::Ordering::SeqCst), |req| h.handle(req))
}

/// Answer one request a connection, a line of JSON each way, until `stop()`. The reply is flushed before the pipe is
/// disconnected: DisconnectNamedPipe throws away whatever the client has not read yet, so without the flush a client
/// that reads a moment later gets nothing.
fn serve_pipe(name: &str, sa: Option<&SECURITY_ATTRIBUTES>, stop: &dyn Fn() -> bool,
              mut handle: impl FnMut(&Value) -> Result<Value>) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::FlushFileBuffers;
    let name = wide(name);
    loop {
        if stop() {
            return Ok(());
        }
        let pipe = unsafe { CreateNamedPipeW(name.as_ptr(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                             PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0,
                                             sa.map_or(std::ptr::null(), |sa| sa as *const SECURITY_ATTRIBUTES)) };
        if pipe == INVALID_HANDLE_VALUE {
            bail!("creating the pipe: {}", std::io::Error::last_os_error());
        }
        let connected = unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) } != 0
            || std::io::Error::last_os_error().raw_os_error() == Some(535);        // ERROR_PIPE_CONNECTED
        if !connected {
            unsafe { CloseHandle(pipe) };
            continue;
        }
        let file = unsafe { std::fs::File::from_raw_handle(pipe as _) };
        let mut line = String::new();
        let mut r = BufReader::new(&file);
        let reply = match r.read_line(&mut line).map_err(anyhow::Error::from)
            .and_then(|_| serde_json::from_str::<Value>(&line).map_err(anyhow::Error::from)).and_then(|req| handle(&req)) {
            Ok(v) => v,
            Err(e) => json!({"ok": false, "error": format!("{e:#}")}),
        };
        if (&file).write_all(format!("{reply}\n").as_bytes()).is_ok() {
            unsafe { FlushFileBuffers(pipe) };                               // until the client has read the reply
        }
        unsafe { DisconnectNamedPipe(pipe) };
        drop(file);                                                          // closes the handle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every reply reaches its client, also one that reads only after the helper has written and moved on (the
    /// helper used to disconnect right after writing, which drops an unread reply: the client read nothing).
    #[test]
    fn every_reply_reaches_its_client() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let name = format!(r"\\.\pipe\oarbank-helper-test-{}", std::process::id());
        let stop = Arc::new(AtomicBool::new(false));
        let (n, s) = (name.clone(), stop.clone());
        let server = std::thread::spawn(move || {
            serve_pipe(&n, None, &|| s.load(Ordering::SeqCst), |req| Ok(json!({"ok": true, "pad": "x".repeat(3000), "req": req})))
        });
        let open = || {
            for _ in 0..400 {
                match std::fs::OpenOptions::new().read(true).write(true).open(&name) {
                    Ok(f) => return f,
                    Err(e) if matches!(e.raw_os_error(), Some(2) | Some(231)) => std::thread::sleep(std::time::Duration::from_millis(5)),
                    Err(e) => panic!("{e}"),
                }
            }
            panic!("the test pipe never opened");
        };
        for i in 0..100 {
            let mut f = open();
            f.write_all(format!("{{\"i\": {i}}}\n").as_bytes()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));     // the helper has written by now
            let mut line = String::new();
            BufReader::new(&f).read_line(&mut line).unwrap();
            let v: Value = serde_json::from_str(&line).unwrap_or_else(|e| panic!("reply {i}: {e} in {line:?}"));
            assert_eq!(v["req"]["i"], json!(i));
        }
        stop.store(true, Ordering::SeqCst);
        let _ = std::fs::OpenOptions::new().read(true).write(true).open(&name);
        server.join().unwrap().unwrap();
    }

    /// As LocalSystem (a scheduled task run as SYSTEM): the agent's session helper runs in every session a person is
    /// logged on to, in that session and with no window, and ends with the service.
    #[test]
    #[ignore = "needs LocalSystem and a person logged on"]
    fn keeps_a_session_helper_in_each_person_s_session() {
        use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
        let agent = std::env::var_os("OARBANK_TEST_AGENT").map(PathBuf::from).expect("OARBANK_TEST_AGENT: an oarbank-agent.exe");
        let keeper = std::thread::spawn(move || keep_session_helpers(agent));
        let helpers = || -> Vec<(u32, u32)> {
            let out = std::process::Command::new("tasklist").args(["/FI", "IMAGENAME eq oarbank-agent.exe", "/FO", "CSV", "/NH"])
                .output().unwrap();
            String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| {
                let pid: u32 = l.split(',').nth(1)?.trim_matches('"').parse().ok()?;
                let mut s = 0u32;
                (unsafe { ProcessIdToSessionId(pid, &mut s) } != 0).then_some((pid, s))
            }).collect()
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !helpers().iter().any(|h| h.1 != 0) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        // (an installed agent's own service runs in session 0)
        let running: Vec<(u32, u32)> = helpers().into_iter().filter(|h| h.1 != 0).collect();
        eprintln!("session helpers (pid, session): {running:?}");
        assert!(!running.is_empty(), "a helper runs in a person's session");
        crate::STOP.store(true, std::sync::atomic::Ordering::SeqCst);
        keeper.join().unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(!helpers().iter().any(|h| running.contains(h)), "the helpers end with the service");
    }

    /// As LocalSystem, with no OarbankHelper service running and an oarbank-agent.exe beside the test binary (what
    /// `serve` starts): the whole service loop, stopped the way the service manager stops it (the stop flag and a
    /// connection of its own). `serve` returns only once its session helpers have ended, since the service process
    /// exits right after.
    #[test]
    #[ignore = "needs LocalSystem and a person logged on, and the OarbankHelper service stopped"]
    fn a_stopped_helper_leaves_no_session_helper_behind() {
        use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
        let in_sessions = || -> usize {
            let out = std::process::Command::new("tasklist").args(["/FI", "IMAGENAME eq oarbank-agent.exe", "/FO", "CSV", "/NH"])
                .output().unwrap();
            String::from_utf8_lossy(&out.stdout).lines().filter(|l| {
                let pid: Option<u32> = l.split(',').nth(1).and_then(|p| p.trim_matches('"').parse().ok());
                let mut s = 0u32;
                pid.is_some_and(|pid| unsafe { ProcessIdToSessionId(pid, &mut s) } != 0 && s != 0)
            }).count()
        };
        assert_eq!(in_sessions(), 0, "stop the OarbankHelper service first (its session helpers end with it)");
        let server = std::thread::spawn(serve);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while in_sessions() == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        assert!(in_sessions() > 0, "a session helper runs in a person's session");
        crate::stop_now();
        let _ = std::fs::OpenOptions::new().read(true).write(true).open(PIPE);
        server.join().unwrap().unwrap();
        assert_eq!(in_sessions(), 0, "serve returned with its session helpers ended");
    }
}
