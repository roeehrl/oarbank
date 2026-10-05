//! The elevated helper for enforced egress allowlists on Windows (PLAN D30). An AppContainer cannot reach loopback,
//! where the agent's egress proxy listens. The helper, a LocalSystem service the MSI installs (`oarbank-launcher
//! helper-main`), lets one module container reach its jobs' proxy ports:
//!
//! - `{"op": "allow", "container": "Oarbank.<module>", "port": P}`: an opening for as long as the process that asks
//!   runs (the pipe's client as Windows names it, never as it says: the job's sandbox shim). An opening is a loopback
//!   exemption for that AppContainer, Windows Filtering Platform filters that block its TCP connections to loopback,
//!   and filters of higher weight that permit port P. It ends when that process ends, however it ends (a job killed
//!   with its shim included): the helper waits on the process's handle;
//! - `{"op": "sessions"}`: the sessions WTS lists (helper_sessions.rs), which host protection needs and the agent's
//!   virtual account may not read itself.
//!
//! Only `Oarbank.*` containers are served. The pipe `\\.\pipe\oarbank-helper` admits SYSTEM, administrators, the
//! agent's service account and interactive users. The filters are persistent, under the helper's own WFP provider and
//! sublayer, and a permit filter records its owner (process id and creation time); the exemptions the helper added are
//! listed in a state file. When the helper starts it keeps the openings whose owner still runs and removes the others
//! with their exemptions, so an exemption is never in force without its block filters, also while the helper is
//! stopped or after it crashed, and a restart or an upgrade keeps running jobs' openings. `oarbank-launcher
//! helper-clear` (the MSI's uninstall) removes everything the helper installed.
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
use std::sync::{Arc, Condvar, Mutex};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
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
/// The helper's WFP provider and the sublayer its filters live in.
const PROVIDER: GUID = GUID::from_u128(0x6f61_7262_616e_6b00_9a41_2f6c_6f6f_7062);
const SUBLAYER: GUID = GUID::from_u128(0x6f61_7262_616e_6b01_9a41_2f6c_6f6f_7062);
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
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
    let bytes = unsafe { sid_bytes(sid) };
    unsafe { windows_sys::Win32::Security::FreeSid(sid) };
    Ok(bytes)
}

fn same(a: &GUID, b: &GUID) -> bool {
    (a.data1, a.data2, a.data3, a.data4) == (b.data1, b.data2, b.data3, b.data4)
}

/// SAFETY: `sid` points at a valid SID.
unsafe fn sid_bytes(sid: PSID) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(sid as *const u8, GetLengthSid(sid) as usize).to_vec() }
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
    let bytes = unsafe { sid_bytes(sid) };
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
            out.push(sid_bytes(sa.Sid));
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

/// Where the helper keeps what it installs: its WFP provider and sublayer, and the file listing the exemptions it added.
/// The service has one; a test takes its own, so it never touches the service's.
#[derive(Clone)]
pub struct Store {
    provider: GUID,
    sublayer: GUID,
    state: PathBuf,
}

impl Store {
    pub fn service() -> Store {
        let state = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("Oarbank").join("helper-exemptions.json");
        Store { provider: PROVIDER, sublayer: SUBLAYER, state }
    }

    fn added(&self) -> Vec<Vec<u8>> {
        std::fs::read(&self.state).ok().and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok()).unwrap_or_default()
            .iter().filter_map(|s| sid_from_string(s)).collect()
    }

    fn save_added(&self, added: &[Vec<u8>]) {
        let list: Vec<String> = added.iter().map(|s| sid_string(s)).collect();
        if let Some(d) = self.state.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::write(&self.state, serde_json::to_vec(&list).unwrap_or_default());
    }
}

/// A filtering engine session (not dynamic: the helper's filters outlive it).
struct Engine(HANDLE);

// the handle is only used under the helper's lock
unsafe impl Send for Engine {}

impl Engine {
    fn open() -> Result<Engine> {
        let mut engine: HANDLE = std::ptr::null_mut();
        // RPC_C_AUTHN_DEFAULT
        let e = unsafe { FwpmEngineOpen0(std::ptr::null(), 0xFFFF_FFFF, std::ptr::null(), std::ptr::null(), &mut engine) };
        if e != 0 {
            bail!("opening the filtering engine failed ({e:#x})");
        }
        Ok(Engine(engine))
    }

    /// The helper's provider and sublayer, persistent, added when missing. The provider names no service, so the
    /// filtering engine restores its filters at every boot (it leaves out those of a provider whose named service does
    /// not start automatically) and an exemption is never in force without them.
    fn provide(&self, store: &Store) -> Result<()> {
        let (mut pname, mut sname) = (wide("Oarbank helper"), wide("Oarbank: a module reaches only its egress proxies on loopback"));
        let provider = FWPM_PROVIDER0 { providerKey: store.provider, flags: FWPM_PROVIDER_FLAG_PERSISTENT,
                                        displayData: FWPM_DISPLAY_DATA0 { name: pname.as_mut_ptr(), description: std::ptr::null_mut() },
                                        ..Default::default() };
        let e = unsafe { FwpmProviderAdd0(self.0, &provider, std::ptr::null_mut()) };
        if e != 0 && e != FWP_E_ALREADY_EXISTS {
            bail!("adding the helper's filtering provider failed ({e:#x})");
        }
        let mut pkey = store.provider;
        let sublayer = FWPM_SUBLAYER0 { subLayerKey: store.sublayer, flags: FWPM_SUBLAYER_FLAG_PERSISTENT, providerKey: &mut pkey,
                                        displayData: FWPM_DISPLAY_DATA0 { name: sname.as_mut_ptr(), description: std::ptr::null_mut() },
                                        weight: 0x8000, ..Default::default() };
        let e = unsafe { FwpmSubLayerAdd0(self.0, &sublayer, std::ptr::null_mut()) };
        if e != 0 && e != FWP_E_ALREADY_EXISTS {
            bail!("adding the helper's filtering sublayer failed ({e:#x})");
        }
        Ok(())
    }

    /// Filters for the container's TCP connections to loopback (IPv4 127/8 and ::1), one per IP version: a block, or
    /// with `port` a permit of higher weight for that port that records its owner (`owner`).
    fn add(&self, store: &Store, sid: &[u8], port: Option<u16>, owner: &[u8]) -> Result<Vec<u64>> {
        let mut ids = vec![];
        let mut v4 = FWP_V4_ADDR_AND_MASK { addr: 0x7F00_0000, mask: 0xFF00_0000 };
        let mut v6 = FWP_BYTE_ARRAY16 { byteArray16: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] };
        let mut name = wide(if port.is_some() { "Oarbank: a module reaches its egress proxy" } else { "Oarbank: a module reaches nothing else on loopback" });
        let (mut pkey, mut data) = (store.provider, owner.to_vec());
        for (layer, addr) in [(FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                               FWP_CONDITION_VALUE0 { r#type: FWP_V4_ADDR_MASK, Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: &mut v4 } }),
                              (FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                               FWP_CONDITION_VALUE0 { r#type: FWP_BYTE_ARRAY16_TYPE, Anonymous: FWP_CONDITION_VALUE0_0 { byteArray16: &mut v6 } })] {
            let mut conds = vec![
                FWPM_FILTER_CONDITION0 { fieldKey: FWPM_CONDITION_ALE_PACKAGE_ID, matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 { r#type: FWP_SID, Anonymous: FWP_CONDITION_VALUE0_0 { sid: sid.as_ptr() as *mut SID } } },
                FWPM_FILTER_CONDITION0 { fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS, matchType: FWP_MATCH_EQUAL, conditionValue: addr },
            ];
            if let Some(p) = port {
                conds.push(FWPM_FILTER_CONDITION0 { fieldKey: FWPM_CONDITION_IP_REMOTE_PORT, matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 { r#type: FWP_UINT16, Anonymous: FWP_CONDITION_VALUE0_0 { uint16: p } } });
            }
            let mut f = FWPM_FILTER0::default();
            f.displayData.name = name.as_mut_ptr();
            f.flags = FWPM_FILTER_FLAG_PERSISTENT;
            f.providerKey = &mut pkey;
            if !data.is_empty() {
                f.providerData = FWP_BYTE_BLOB { size: data.len() as u32, data: data.as_mut_ptr() };
            }
            f.layerKey = layer;
            f.subLayerKey = store.sublayer;
            // the permits come first in the sublayer: the block takes only what no permit took
            f.weight = FWP_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_VALUE0_0 { uint8: if port.is_some() { 15 } else { 1 } } };
            f.numFilterConditions = conds.len() as u32;
            f.filterCondition = conds.as_mut_ptr();
            f.action.r#type = if port.is_some() { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK };
            let mut id = 0u64;
            let e = unsafe { FwpmFilterAdd0(self.0, &f, std::ptr::null_mut(), &mut id) };
            if e != 0 {
                self.delete(&ids);
                bail!("adding a loopback filter failed ({e:#x})");
            }
            ids.push(id);
        }
        Ok(ids)
    }

    fn delete(&self, ids: &[u64]) {
        for i in ids {
            unsafe { FwpmFilterDeleteById0(self.0, *i) };
        }
    }

    /// The filters under the store's provider.
    fn filters(&self, store: &Store) -> Vec<Installed> {
        let mut out = vec![];
        for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
            let mut pkey = store.provider;
            let t = FWPM_FILTER_ENUM_TEMPLATE0 { providerKey: &mut pkey, layerKey: layer, enumType: FWP_FILTER_ENUM_OVERLAPPING,
                                                 actionMask: 0xFFFF_FFFF, ..Default::default() };
            let mut h: HANDLE = std::ptr::null_mut();
            if unsafe { FwpmFilterCreateEnumHandle0(self.0, &t, &mut h) } != 0 {
                continue;
            }
            loop {
                let (mut entries, mut n): (*mut *mut FWPM_FILTER0, u32) = (std::ptr::null_mut(), 0);
                if unsafe { FwpmFilterEnum0(self.0, h, 256, &mut entries, &mut n) } != 0 || n == 0 {
                    break;
                }
                for i in 0..n as usize {
                    // SAFETY: the engine returned `n` filters; their conditions and data live until FwpmFreeMemory0
                    let f = unsafe { &**entries.add(i) };
                    let conds = unsafe { std::slice::from_raw_parts(f.filterCondition, f.numFilterConditions as usize) };
                    let sid = conds.iter().find(|c| same(&c.fieldKey, &FWPM_CONDITION_ALE_PACKAGE_ID))
                        .map(|c| unsafe { sid_bytes(c.conditionValue.Anonymous.sid as PSID) }).unwrap_or_default();
                    let port = conds.iter().find(|c| same(&c.fieldKey, &FWPM_CONDITION_IP_REMOTE_PORT))
                        .map(|c| unsafe { c.conditionValue.Anonymous.uint16 });
                    let data = if f.providerData.data.is_null() { vec![] }
                               else { unsafe { std::slice::from_raw_parts(f.providerData.data, f.providerData.size as usize).to_vec() } };
                    out.push(Installed { id: f.filterId, container: sid, port, owner: data });
                }
                unsafe { FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut core::ffi::c_void) };
            }
            unsafe { FwpmFilterDestroyEnumHandle0(self.0, h) };
        }
        out
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe { FwpmEngineClose0(self.0) };
    }
}

/// A filter the helper installed: a block (no port) or a permit for a port and its owner's record.
struct Installed {
    id: u64,
    container: Vec<u8>,
    port: Option<u16>,
    owner: Vec<u8>,
}

/// The process an opening lasts for: its handle (waited on), and its id and creation time, which its permit filters
/// record so a later helper finds it again.
struct Owner {
    process: HANDLE,
    pid: u32,
    created: u64,
}

// a process handle may be waited on and closed from any thread
unsafe impl Send for Owner {}

impl Owner {
    fn open(pid: u32) -> Option<Owner> {
        use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE};
        let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return None;
        }
        let mut t = [FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 }; 4];
        let [c, e, k, u] = &mut t;
        if unsafe { GetProcessTimes(process, c, e, k, u) } == 0 {
            unsafe { CloseHandle(process) };
            return None;
        }
        Some(Owner { process, pid, created: (t[0].dwHighDateTime as u64) << 32 | t[0].dwLowDateTime as u64 })
    }

    /// The process at the other end of a pipe instance. It is checked to be still connected once its handle is open,
    /// so the handle is that process's: a process id is not reused while its process runs.
    fn of_client(pipe: HANDLE) -> Result<Owner> {
        use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, PeekNamedPipe};
        let mut pid = 0u32;
        if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 {
            bail!("the requesting process: {}", std::io::Error::last_os_error());
        }
        let owner = Owner::open(pid).context("the requesting process ended")?;
        let mut avail = 0u32;
        if unsafe { PeekNamedPipe(pipe, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut()) } == 0 {
            bail!("the requesting process left");
        }
        Ok(owner)
    }

    /// The running process an earlier helper recorded, if it still runs.
    fn find(record: &[u8]) -> Option<Owner> {
        let pid = u32::from_le_bytes(record.get(..4)?.try_into().ok()?);
        let created = u64::from_le_bytes(record.get(4..12)?.try_into().ok()?);
        Owner::open(pid).filter(|o| o.created == created && o.running())
    }

    fn record(&self) -> Vec<u8> {
        [self.pid.to_le_bytes().as_slice(), &self.created.to_le_bytes()].concat()
    }

    fn wait(&self) {
        use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};
        unsafe { WaitForSingleObject(self.process, INFINITE) };
    }

    fn running(&self) -> bool {
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        unsafe { WaitForSingleObject(self.process, 0) != 0 }        // WAIT_OBJECT_0: it has ended
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.process) };
    }
}

/// One opening: its container and its permit filters.
struct Opening {
    container: Vec<u8>,
    permits: Vec<u64>,
}

struct State {
    engine: Engine,
    store: Store,
    /// container SID → its block filters, there while it has an opening
    blocks: HashMap<Vec<u8>, Vec<u64>>,
    openings: HashMap<u64, Opening>,
    /// exemptions this helper added (removed again when no opening needs them)
    added: Vec<Vec<u8>>,
    next: u64,
}

impl State {
    /// The container's block filters and its exemption, when it has none yet (the filters first: never an exemption
    /// without them).
    fn guard(&mut self, sid: &[u8]) -> Result<()> {
        if !self.blocks.contains_key(sid) {
            let ids = self.engine.add(&self.store, sid, None, &[])?;
            self.blocks.insert(sid.to_vec(), ids);
        }
        let mut now = exemptions();
        if !now.iter().any(|s| s == sid) {
            now.push(sid.to_vec());
            set_exemptions(&now)?;
            self.added.push(sid.to_vec());
            self.store.save_added(&self.added);
        }
        Ok(())
    }

    /// What a container with no opening left keeps: nothing the helper added (the exemption before the filters).
    fn unguard(&mut self, sid: &[u8]) {
        if self.openings.values().any(|o| o.container == sid) {
            return;
        }
        if self.added.iter().any(|s| s == sid) {
            let keep: Vec<Vec<u8>> = exemptions().into_iter().filter(|s| s != sid).collect();
            if let Err(e) = set_exemptions(&keep) {
                eprintln!("oarbank-launcher helper: {e:#}");
                return;                                           // its filters stay with it
            }
            self.added.retain(|s| s != sid);
            self.store.save_added(&self.added);
        }
        if let Some(ids) = self.blocks.remove(sid) {
            self.engine.delete(&ids);
        }
    }
}

/// The openings the helper holds, each ended by its owner's end.
pub struct Helper {
    state: Mutex<State>,
    /// notified after an opening ended
    closed: Condvar,
}

impl Helper {
    /// Open the filtering engine, and keep what an earlier helper installed only for owners that still run.
    pub fn open(store: Store) -> Result<Arc<Helper>> {
        let engine = Engine::open()?;
        engine.provide(&store)?;
        let added = store.added();
        let helper = Arc::new(Helper {
            state: Mutex::new(State { engine, store, blocks: HashMap::new(), openings: HashMap::new(), added, next: 1 }),
            closed: Condvar::new(),
        });
        let mut owners = vec![];
        {
            let mut st = helper.state.lock().unwrap();
            let mut permits: HashMap<(Vec<u8>, Vec<u8>), Vec<u64>> = HashMap::new();
            let mut blocks: HashMap<Vec<u8>, Vec<u64>> = HashMap::new();
            for f in st.engine.filters(&st.store) {
                match f.port {
                    Some(_) => permits.entry((f.container, f.owner)).or_default().push(f.id),
                    None => blocks.entry(f.container).or_default().push(f.id),
                }
            }
            st.blocks = blocks;
            for ((sid, record), ids) in permits {
                match Owner::find(&record) {
                    Some(owner) => {
                        let id = st.next;
                        st.next += 1;
                        st.openings.insert(id, Opening { container: sid, permits: ids });
                        owners.push((id, owner));
                    }
                    None => st.engine.delete(&ids),
                }
            }
            let containers: Vec<Vec<u8>> = st.blocks.keys().chain(st.added.iter()).cloned().collect();
            for sid in containers {
                st.unguard(&sid);
            }
            let kept: Vec<Vec<u8>> = st.openings.values().map(|o| o.container.clone()).collect();
            for sid in kept {
                st.guard(&sid)?;
            }
            st.store.save_added(&st.added);
        }
        for (id, owner) in owners {
            helper.watch(id, owner);
        }
        Ok(helper)
    }

    /// Open loopback for the container to `port` for as long as `owner` runs.
    fn allow(self: &Arc<Self>, container: &[u8], port: u16, owner: Owner) -> Result<()> {
        let id = {
            let mut st = self.state.lock().unwrap();
            st.guard(container)?;
            let permits = match st.engine.add(&st.store, container, Some(port), &owner.record()) {
                Ok(p) => p,
                Err(e) => {
                    st.unguard(container);
                    return Err(e);
                }
            };
            let id = st.next;
            st.next += 1;
            st.openings.insert(id, Opening { container: container.to_vec(), permits });
            id
        };
        self.watch(id, owner);
        Ok(())
    }

    /// End the opening when its owner ends.
    fn watch(self: &Arc<Self>, id: u64, owner: Owner) {
        let h = self.clone();
        let spawned = std::thread::Builder::new().name(format!("opening {id}")).spawn(move || {
            owner.wait();
            h.close(id);
        });
        if spawned.is_err() {
            self.close(id);
        }
    }

    fn close(&self, id: u64) {
        let mut st = self.state.lock().unwrap();
        if let Some(o) = st.openings.remove(&id) {
            st.engine.delete(&o.permits);
            st.unguard(&o.container);
        }
        drop(st);
        self.closed.notify_all();
    }

    fn handle(self: &Arc<Self>, req: &Value, pipe: HANDLE) -> Result<Value> {
        match req["op"].as_str() {
            Some("sessions") => Ok(crate::helper_sessions::reply(crate::helper_sessions::read().as_deref())),
            Some("allow") => {
                let name = req["container"].as_str().context("no container")?;
                let port = req["port"].as_u64().filter(|p| (1024..=65535).contains(p)).context("no port in 1024-65535")? as u16;
                self.allow(&container_sid(name)?, port, Owner::of_client(pipe)?)?;
                Ok(json!({"ok": true}))
            }
            other => bail!("unknown op {other:?}"),
        }
    }
}

/// `helper-clear`: remove everything the helper installed (its filters, sublayer and provider, and the exemptions it
/// added), as the MSI's uninstall does once the service has stopped.
pub fn clear(store: &Store) -> Result<()> {
    let engine = Engine::open()?;
    let ids: Vec<u64> = engine.filters(store).into_iter().map(|f| f.id).collect();
    engine.delete(&ids);
    unsafe {
        FwpmSubLayerDeleteByKey0(engine.0, &store.sublayer);
        FwpmProviderDeleteByKey0(engine.0, &store.provider);
    }
    let added = store.added();
    let keep: Vec<Vec<u8>> = exemptions().into_iter().filter(|s| !added.contains(s)).collect();
    set_exemptions(&keep)?;
    let _ = std::fs::remove_file(&store.state);
    Ok(())
}

pub fn helper_clear() -> Result<()> {
    clear(&Store::service())
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
    let h = Helper::open(Store::service())?;
    let sddl = wide(&pipe_sddl());
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut sd, std::ptr::null_mut()) } == 0 {
        bail!("pipe security descriptor: {}", std::io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
    serve_pipe(PIPE, Some(&sa), &|| crate::STOP.load(std::sync::atomic::Ordering::SeqCst), |req, pipe| h.handle(req, pipe))
}

/// Answer one request a connection, a line of JSON each way, until `stop()`; `handle` gets the request and the pipe
/// instance it came on (whose client process it may ask for). A stop is a flag and then a connection of the stopper's
/// own (svc_windows.rs `control`), so `stop()` is asked once the next pipe instance exists: a connection made after the
/// flag then always reaches it, or finds the flag already seen. Asked before the instance exists, a stop landing
/// between the two found no pipe to connect to, and ConnectNamedPipe waited for ever. The reply is flushed before the
/// pipe is disconnected: DisconnectNamedPipe throws away whatever the client has not read yet, so without the flush a
/// client that reads a moment later gets nothing.
fn serve_pipe(name: &str, sa: Option<&SECURITY_ATTRIBUTES>, stop: &dyn Fn() -> bool,
              mut handle: impl FnMut(&Value, HANDLE) -> Result<Value>) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::FlushFileBuffers;
    let name = wide(name);
    loop {
        let pipe = unsafe { CreateNamedPipeW(name.as_ptr(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                             PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0,
                                             sa.map_or(std::ptr::null(), |sa| sa as *const SECURITY_ATTRIBUTES)) };
        if pipe == INVALID_HANDLE_VALUE {
            bail!("creating the pipe: {}", std::io::Error::last_os_error());
        }
        if stop() {
            unsafe { CloseHandle(pipe) };
            return Ok(());
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
            .and_then(|_| serde_json::from_str::<Value>(&line).map_err(anyhow::Error::from)).and_then(|req| handle(&req, pipe)) {
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
            serve_pipe(&n, None, &|| s.load(Ordering::SeqCst), |req, _| Ok(json!({"ok": true, "pad": "x".repeat(3000), "req": req})))
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

    /// A stop that arrives right after the server last asked (the flag, then the stopper's own connection, both before
    /// the next pipe instance exists, if the server asks first) still ends it: here the stop is asked for from inside
    /// the server's first check, as if it had come a moment after it.
    #[test]
    fn a_stop_right_after_the_check_ends_the_server() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let name = format!(r"\\.\pipe\oarbank-helper-stop-{}", std::process::id());
        let (stopped, n) = (Arc::new(AtomicBool::new(false)), name.clone());
        let (done, ended) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let stop = || {
                if stopped.load(Ordering::SeqCst) {
                    return true;
                }
                stopped.store(true, Ordering::SeqCst);
                let _ = std::fs::OpenOptions::new().read(true).write(true).open(&n);
                false
            };
            let _ = done.send(serve_pipe(&n, None, &stop, |_, _| Ok(json!({"ok": true}))).is_ok());
        });
        assert_eq!(ended.recv_timeout(std::time::Duration::from_secs(20)).ok(), Some(true), "the server still waits for a connection");
    }

    // ---- openings (as an administrator, as CI runs the tests: the filtering engine and the exemptions need one)

    /// Tests of openings change the machine's exemption list (read, change, write): one at a time.
    static MACHINE: Mutex<()> = Mutex::new(());

    /// A store of the test's own (provider, sublayer, state file) and an AppContainer name; whatever the test leaves in
    /// them is cleared when it goes.
    struct Scratch {
        seed: u128,
        store: Store,
        name: String,
        sid: Vec<u8>,
        _one: std::sync::MutexGuard<'static, ()>,
    }

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let one = MACHINE.lock().unwrap_or_else(|e| e.into_inner());
            let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let seed = (std::process::id() as u128) << 96 ^ nanos;
            let store = Store { provider: GUID::from_u128(seed), sublayer: GUID::from_u128(seed ^ 1),
                                state: std::env::temp_dir().join(format!("oarbank-helper-{tag}-{seed:x}.json")) };
            let name = format!("Oarbank.test-{tag}-{}", std::process::id());
            let sid = container_sid(&name).unwrap();
            Scratch { seed, store, name, sid, _one: one }
        }

        /// (block filters, permitted ports) under the store's provider, for the container.
        fn filters(&self) -> (usize, Vec<u16>) {
            let all = Engine::open().unwrap().filters(&self.store);
            let mine: Vec<_> = all.into_iter().filter(|f| f.container == self.sid).collect();
            let mut ports: Vec<u16> = mine.iter().filter_map(|f| f.port).collect();
            ports.sort();
            (mine.iter().filter(|f| f.port.is_none()).count(), ports)
        }

        fn exempt(&self) -> bool {
            exemptions().contains(&self.sid)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = clear(&self.store);
        }
    }

    /// Wait (on the helper's notification, up to 30 s) until it holds `n` openings.
    fn openings(h: &Helper, n: usize) -> bool {
        let st = h.state.lock().unwrap();
        let (st, _) = h.closed.wait_timeout_while(st, std::time::Duration::from_secs(30), |st| st.openings.len() != n).unwrap();
        st.openings.len() == n
    }

    /// A process to own openings, ended by the test.
    fn owner_process() -> std::process::Child {
        std::process::Command::new("ping").args(["-n", "600", "127.0.0.1"]).stdout(std::process::Stdio::null()).spawn().unwrap()
    }

    /// The helper's own record of an opening ends with the process that asked for it, however that process ends: the
    /// shim of a killed job never asks for anything again. (The helper kept a killed shim's filters and exemption until it
    /// restarted, and a later job of the module, with its own proxy port, could reach none.)
    #[test]
    fn an_opening_ends_with_the_process_that_asked_for_it() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let t = Scratch::new("owner");
        let helper = Helper::open(t.store.clone()).unwrap();
        let pipe = format!(r"\\.\pipe\oarbank-helper-owner-{}", std::process::id());
        let stop = Arc::new(AtomicBool::new(false));
        let (h, n, s) = (helper.clone(), pipe.clone(), stop.clone());
        let server = std::thread::spawn(move || serve_pipe(&n, None, &|| s.load(Ordering::SeqCst), |req, p| h.handle(req, p)));
        // a client of its own, as the job's shim is: it asks, reads the answer and waits to be killed
        let script = format!("$p = New-Object IO.Pipes.NamedPipeClientStream('.', '{}', 'InOut'); $p.Connect(30000); \
                              $w = New-Object IO.StreamWriter($p); $w.WriteLine('{{\"op\": \"allow\", \"container\": \"{}\", \"port\": 45101}}'); \
                              $w.Flush(); [Console]::Out.WriteLine((New-Object IO.StreamReader($p)).ReadLine()); [Console]::Out.Flush(); \
                              Start-Sleep 600", pipe.trim_start_matches(r"\\.\pipe\"), t.name);
        let mut client = std::process::Command::new("powershell").args(["-NoProfile", "-Command", &script])
            .stdout(std::process::Stdio::piped()).spawn().unwrap();
        let mut reply = String::new();
        BufReader::new(client.stdout.take().unwrap()).read_line(&mut reply).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&reply).ok(), Some(json!({"ok": true})), "{reply}");
        assert_eq!(t.filters(), (2, vec![45101, 45101]), "a block and a permit per IP version");
        assert!(t.exempt());
        client.kill().unwrap();
        client.wait().unwrap();
        assert!(openings(&helper, 0), "the opening ended with its owner");
        assert_eq!(t.filters(), (0, vec![]));
        assert!(!t.exempt(), "the exemption went with the opening");
        stop.store(true, Ordering::SeqCst);
        let _ = std::fs::OpenOptions::new().read(true).write(true).open(&pipe);
        server.join().unwrap().unwrap();
    }

    /// `curl` in the AppContainer `name` asking 127.0.0.1:`port`: its exit code (0: answered; 7: refused; 28: no answer
    /// in time; 23: it could not write what it got).
    fn curl(name: &str, port: u16) -> u32 {
        use windows_sys::Win32::Security::Isolation::CreateAppContainerProfile;
        use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
        use windows_sys::Win32::System::Threading::*;
        let n = wide(name);
        let mut sid: PSID = std::ptr::null_mut();
        if unsafe { CreateAppContainerProfile(n.as_ptr(), n.as_ptr(), n.as_ptr(), std::ptr::null(), 0, &mut sid) } < 0 {
            assert!(unsafe { DeriveAppContainerSidFromAppContainerName(n.as_ptr(), &mut sid) } >= 0);
        }
        let sc = SECURITY_CAPABILITIES { AppContainerSid: sid, Capabilities: std::ptr::null_mut(), CapabilityCount: 0, Reserved: 0 };
        let mut size = 0usize;
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
        let mut buf = vec![0u8; size];
        let list = buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = list;
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        // the answer has no body, so curl writes nothing: an AppContainer may not open NUL on some builds (Windows
        // Server 2025 refuses it), and `-o NUL` failed every answered request there (exit 23, a write error)
        let mut cmd = wide(&format!(r"{root}\System32\curl.exe -s --max-time 10 http://127.0.0.1:{port}/"));
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let code = unsafe {
            assert!(InitializeProcThreadAttributeList(list, 1, 0, &mut size) != 0);
            assert!(UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize, &sc as *const _ as *const _,
                                              std::mem::size_of::<SECURITY_CAPABILITIES>(), std::ptr::null_mut(), std::ptr::null()) != 0);
            assert!(CreateProcessW(std::ptr::null(), cmd.as_mut_ptr(), std::ptr::null(), std::ptr::null(), 0,
                                   EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, std::ptr::null(), std::ptr::null(), &si.StartupInfo,
                                   &mut pi) != 0, "curl in {name}: {}", std::io::Error::last_os_error());
            DeleteProcThreadAttributeList(list);
            WaitForSingleObject(pi.hProcess, INFINITE);
            let mut code = 1u32;
            GetExitCodeProcess(pi.hProcess, &mut code);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            windows_sys::Win32::Security::FreeSid(sid);
            code
        };
        code
    }

    /// A loopback listener that answers every connection with an empty HTTP response; its port.
    fn answering() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut c in l.incoming().flatten() {
                // the request first: a connection closed with it unread is reset, and curl reports no answer
                let mut req = String::new();
                let mut r = BufReader::new(&c);
                while r.read_line(&mut req).is_ok_and(|n| n > 2) {
                    req.clear();
                }
                let _ = c.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
            }
        });
        port
    }

    /// Two jobs of one module at once, each with its own proxy port, reach each their port and nothing else on
    /// loopback; each opening ends with its own owner. (Each job's filter used to block every port but its own, so with
    /// two jobs neither reached its proxy.)
    #[test]
    fn two_openings_of_one_container_reach_their_ports_and_end_one_by_one() {
        let t = Scratch::new("ports");
        let helper = Helper::open(t.store.clone()).unwrap();
        let (p1, p2, other) = (answering(), answering(), answering());
        assert_ne!(curl(&t.name, p1), 0, "an AppContainer reaches no loopback port by itself");
        let (mut a, mut b) = (owner_process(), owner_process());
        helper.allow(&t.sid, p1, Owner::open(a.id()).unwrap()).unwrap();
        helper.allow(&t.sid, p2, Owner::open(b.id()).unwrap()).unwrap();
        let codes = (curl(&t.name, p1), curl(&t.name, p2), curl(&t.name, other));
        assert!(codes.0 == 0 && codes.1 == 0 && codes.2 != 0, "curl's exit codes {codes:?}; the helper's filters {:?}", t.filters());
        a.kill().unwrap();
        a.wait().unwrap();
        assert!(openings(&helper, 1));
        let codes = (curl(&t.name, p1), curl(&t.name, p2));
        assert!(codes.0 != 0 && codes.1 == 0, "only the ended job's port closed: curl's exit codes {codes:?}");
        assert!(t.exempt());
        b.kill().unwrap();
        b.wait().unwrap();
        assert!(openings(&helper, 0));
        assert_ne!(curl(&t.name, p2), 0);
        assert_eq!(t.filters(), (0, vec![]));
        assert!(!t.exempt());
        unsafe { windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile(wide(&t.name).as_ptr()) };
    }

    /// A helper that crashed (here a child process running one, killed): its openings stay closed off by their block
    /// filters while it is gone, and the next helper keeps the ones whose owner still runs, removes the others, and
    /// ends the kept ones with their owners.
    #[test]
    fn a_restarted_helper_keeps_the_openings_of_running_owners_only() {
        let t = Scratch::new("restart");
        let (mut a, mut b) = (owner_process(), owner_process());
        let (pa, pb) = (45201u16, 45202u16);
        let mut first = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "helper_windows::tests::a_helper_to_crash", "--ignored", "--nocapture"])
            .env("OARBANK_TEST_HELPER", json!({"seed": format!("{:x}", t.seed), "state": t.store.state, "sid": sid_string(&t.sid),
                                               "owners": [[a.id(), pa], [b.id(), pb]]}).to_string())
            .stdout(std::process::Stdio::piped()).spawn().unwrap();
        let mut out = BufReader::new(first.stdout.take().unwrap());
        let mut line = String::new();
        while !line.contains("openings ready") {
            line.clear();
            assert!(out.read_line(&mut line).unwrap() > 0, "the first helper ended before its openings were made");
        }
        first.kill().unwrap();
        first.wait().unwrap();
        assert_eq!(t.filters(), (2, vec![pa, pa, pb, pb]), "the openings outlive the crashed helper");
        assert!(t.exempt());
        b.kill().unwrap();
        b.wait().unwrap();
        let helper = Helper::open(t.store.clone()).unwrap();
        assert_eq!(helper.state.lock().unwrap().openings.len(), 1);
        assert_eq!(t.filters(), (2, vec![pa, pa]), "the ended owner's opening was removed");
        assert!(t.exempt());
        a.kill().unwrap();
        a.wait().unwrap();
        assert!(openings(&helper, 0), "the kept opening ends with its owner");
        assert_eq!(t.filters(), (0, vec![]));
        assert!(!t.exempt());
    }

    /// `helper-clear` (an uninstall) removes everything the helper installed, also an opening whose owner still runs.
    #[test]
    fn clearing_removes_everything_the_helper_installed() {
        let t = Scratch::new("clear");
        let helper = Helper::open(t.store.clone()).unwrap();
        let mut owner = owner_process();
        helper.allow(&t.sid, 45301, Owner::open(owner.id()).unwrap()).unwrap();
        assert!(t.exempt() && t.store.state.exists());
        clear(&t.store).unwrap();
        assert_eq!(t.filters(), (0, vec![]));
        assert!(!t.exempt() && !t.store.state.exists());
        owner.kill().unwrap();
        owner.wait().unwrap();
    }

    #[test]
    #[ignore = "the helper a_restarted_helper_keeps_the_openings_of_running_owners_only runs and kills"]
    fn a_helper_to_crash() {
        let v: Value = serde_json::from_str(&std::env::var("OARBANK_TEST_HELPER").unwrap()).unwrap();
        let seed = u128::from_str_radix(v["seed"].as_str().unwrap(), 16).unwrap();
        let store = Store { provider: GUID::from_u128(seed), sublayer: GUID::from_u128(seed ^ 1),
                            state: PathBuf::from(v["state"].as_str().unwrap()) };
        let sid = sid_from_string(v["sid"].as_str().unwrap()).unwrap();
        let helper = Helper::open(store).unwrap();
        for o in v["owners"].as_array().unwrap() {
            helper.allow(&sid, o[1].as_u64().unwrap() as u16, Owner::open(o[0].as_u64().unwrap() as u32).unwrap()).unwrap();
        }
        println!("openings ready");
        std::thread::sleep(std::time::Duration::from_secs(600));
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
