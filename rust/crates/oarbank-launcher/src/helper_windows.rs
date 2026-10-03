//! The elevated helper for enforced egress allowlists on Windows (PLAN D30). An AppContainer cannot reach loopback,
//! where the agent's egress proxy listens. The helper, a LocalSystem service the MSI installs (`oarbank-launcher
//! helper-main`), lets one module container reach exactly its job's proxy port:
//!
//! - `{"op": "allow", "container": "Oarbank.<module>", "port": P}`: a loopback exemption for that AppContainer, and
//!   Windows Filtering Platform filters that block its TCP connections to every loopback port but P;
//! - `{"op": "release", "container": …, "port": P}`: the filters go, and the exemption when no job still needs it.
//!
//! Only `Oarbank.*` containers are served. The pipe `\\.\pipe\oarbank-helper` admits SYSTEM, administrators, the
//! agent's service account and interactive users. The filters live in a dynamic WFP session (they end with the
//! helper), and the exemptions the helper added are listed in a state file and removed when it starts again.

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

/// Serve requests forever, one connection at a time.
pub fn serve() -> Result<()> {
    let mut h = Helper::open()?;
    let sddl = wide(&pipe_sddl());
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut sd, std::ptr::null_mut()) } == 0 {
        bail!("pipe security descriptor: {}", std::io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
    let name = wide(PIPE);
    loop {
        if crate::STOP.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        let pipe = unsafe { CreateNamedPipeW(name.as_ptr(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                             PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, &sa) };
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
            .and_then(|_| serde_json::from_str::<Value>(&line).map_err(anyhow::Error::from)).and_then(|req| h.handle(&req)) {
            Ok(v) => v,
            Err(e) => json!({"ok": false, "error": format!("{e:#}")}),
        };
        let _ = (&file).write_all(format!("{reply}\n").as_bytes());
        let _ = (&file).flush();
        unsafe { DisconnectNamedPipe(pipe) };
        drop(file);                                                          // closes the handle
    }
}
