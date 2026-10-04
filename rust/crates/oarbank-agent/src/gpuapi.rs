//! The GPU APIs this node provides (docs/design/gpu-placement.md), on the host and inside its containers, for the doctor
//! report (`gpu_apis`) and `oarbank-agent gpu-apis`.
//!
//! An API counts only when its own runtime enumerates a device that is a GPU: a software rasteriser, a CPU device or
//! Windows' Basic Render Driver does not. The probes load drivers into the process, so the agent runs them in a child
//! (`probe`): a driver that crashes or hangs never takes the agent with it. The SDK's `oarbank_sdk.gpu` runs the same
//! probes, and the parity test (tests/rust/test_gpu_apis.py) holds the two to one answer on each host.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::ffi::{c_char, c_void, CStr};
use std::path::Path;
use std::time::Duration;

/// How long the child may take: loading a GPU driver can be slow, never this slow.
const PROBE_LIMIT: Duration = Duration::from_secs(60);

type Probe = fn() -> Result<Vec<String>, String>;

/// A dynamically loaded library, never unloaded (drivers do not like it, and the probe's process is short-lived).
struct Lib(*mut c_void);

impl Lib {
    fn open(names: &[&str]) -> Result<Lib, String> {
        names.iter().find_map(|n| os::open(n).map(Lib)).ok_or_else(|| format!("no {}", names.join(" or ")))
    }

    /// The function `name` as `T` (an `extern "system" fn` type of the right signature).
    unsafe fn sym<T: Copy>(&self, name: &str) -> Result<T, String> {
        assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<*mut c_void>());
        let p = os::sym(self.0, name).ok_or_else(|| format!("no {name}"))?;
        Ok(unsafe { std::mem::transmute_copy(&p) })
    }
}

#[cfg(unix)]
mod os {
    use std::ffi::{c_void, CString};

    pub fn open(name: &str) -> Option<*mut c_void> {
        let c = CString::new(name).ok()?;
        let h = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        (!h.is_null()).then_some(h)
    }

    pub fn sym(lib: *mut c_void, name: &str) -> Option<*mut c_void> {
        let c = CString::new(name).ok()?;
        let p = unsafe { libc::dlsym(lib, c.as_ptr()) };
        (!p.is_null()).then_some(p)
    }
}

#[cfg(windows)]
mod os {
    use std::ffi::c_void;
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
                                                    LOAD_LIBRARY_SEARCH_DEFAULT_DIRS};

    /// System32 and the default directories only, never the current directory.
    pub fn open(name: &str) -> Option<*mut c_void> {
        let w: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let h = unsafe { LoadLibraryExW(w.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) };
        (!h.is_null()).then_some(h as *mut c_void)
    }

    pub fn sym(lib: *mut c_void, name: &str) -> Option<*mut c_void> {
        let c = std::ffi::CString::new(name).ok()?;
        unsafe { GetProcAddress(lib as _, c.as_ptr() as *const u8) }.map(|f| f as *mut c_void)
    }
}

fn cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).trim().to_string()
}

/// Windows' Basic Render Driver (WARP), which the D3D12 mapping layers (OpenCLOn12, Dozen) expose as a GPU.
fn software(name: &str) -> bool {
    name.to_ascii_lowercase().contains("basic render driver")
}

// MARK: metal

/// `MTLCopyAllDevices` works without a window server, so a LaunchDaemon sees the GPU too.
#[cfg(target_os = "macos")]
fn metal() -> Result<Vec<String>, String> {
    type Copy = extern "C" fn() -> *const c_void;
    type Count = extern "C" fn(*const c_void) -> isize;
    type At = extern "C" fn(*const c_void, isize) -> *const c_void;
    type Release = extern "C" fn(*const c_void);
    type Sel = extern "C" fn(*const c_char) -> *const c_void;
    type Send = extern "C" fn(*const c_void, *const c_void) -> *const c_void;
    let mtl = Lib::open(&["/System/Library/Frameworks/Metal.framework/Metal"])?;
    let cf = Lib::open(&["/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"])?;
    let objc = Lib::open(&["/usr/lib/libobjc.A.dylib"])?;
    unsafe {
        let devices = mtl.sym::<Copy>("MTLCopyAllDevices")?();
        if devices.is_null() {
            return Err("MTLCopyAllDevices returned no devices".into());
        }
        let (count, at, release) = (cf.sym::<Count>("CFArrayGetCount")?, cf.sym::<At>("CFArrayGetValueAtIndex")?,
                                    cf.sym::<Release>("CFRelease")?);
        let (sel, send) = (objc.sym::<Sel>("sel_registerName")?, objc.sym::<Send>("objc_msgSend")?);
        let (name_sel, utf8_sel) = (sel(c"name".as_ptr()), sel(c"UTF8String".as_ptr()));
        let names: Vec<String> = (0..count(devices)).map(|i| {
            let name = send(at(devices, i), name_sel);
            let s = if name.is_null() { std::ptr::null() } else { send(name, utf8_sel) as *const c_char };
            if s.is_null() { "a Metal device".to_string() } else { CStr::from_ptr(s).to_string_lossy().to_string() }
        }).collect();
        release(devices);
        if names.is_empty() { Err("MTLCopyAllDevices returned no devices".into()) } else { Ok(names) }
    }
}

#[cfg(not(target_os = "macos"))]
fn metal() -> Result<Vec<String>, String> {
    Err("Metal is macOS only".into())
}

// MARK: vulkan

#[cfg(target_os = "macos")]
const VK_LOADERS: &[&str] = &["libvulkan.1.dylib", "/opt/homebrew/lib/libvulkan.1.dylib", "/usr/local/lib/libvulkan.1.dylib"];
#[cfg(windows)]
const VK_LOADERS: &[&str] = &["vulkan-1.dll"];
#[cfg(not(any(target_os = "macos", windows)))]
const VK_LOADERS: &[&str] = &["libvulkan.so.1"];

#[repr(C)]
struct VkAppInfo {
    s_type: u32,
    p_next: *const c_void,
    app_name: *const c_char,
    app_version: u32,
    engine_name: *const c_char,
    engine_version: u32,
    api_version: u32,
}

#[repr(C)]
struct VkInstanceInfo {
    s_type: u32,
    p_next: *const c_void,
    flags: u32,
    app_info: *const VkAppInfo,
    layer_count: u32,
    layers: *const *const c_char,
    extension_count: u32,
    extensions: *const *const c_char,
}

const VK_PORTABILITY: &CStr = c"VK_KHR_portability_enumeration";
const VK_CPU: u32 = 4;
const VK_COMPUTE: u32 = 0x2;

fn vk_type(t: u32) -> String {
    match t {
        0 => "other".into(),
        1 => "integrated".into(),
        2 => "discrete".into(),
        3 => "virtual".into(),
        4 => "cpu".into(),
        n => n.to_string(),
    }
}

/// The loader lists a physical device that is not a CPU device and has a compute queue. MoltenVK is a portability driver,
/// listed only when the instance asks for portability enumeration.
fn vulkan() -> Result<Vec<String>, String> {
    type EnumExt = extern "system" fn(*const c_char, *mut u32, *mut u8) -> i32;
    type Create = extern "system" fn(*const VkInstanceInfo, *const c_void, *mut *mut c_void) -> i32;
    type Destroy = extern "system" fn(*mut c_void, *const c_void);
    type EnumDev = extern "system" fn(*mut c_void, *mut u32, *mut *mut c_void) -> i32;
    type Props = extern "system" fn(*mut c_void, *mut u8);
    type Queues = extern "system" fn(*mut c_void, *mut u32, *mut u32);
    let vk = Lib::open(VK_LOADERS)?;
    unsafe {
        let exts = vk.sym::<EnumExt>("vkEnumerateInstanceExtensionProperties")?;
        let mut n = 0u32;
        exts(std::ptr::null(), &mut n, std::ptr::null_mut());
        let mut props = vec![0u8; 260 * n.max(1) as usize];               // VkExtensionProperties: name[256], version
        exts(std::ptr::null(), &mut n, props.as_mut_ptr());
        let portable = (0..n as usize).any(|i| cstr(&props[i * 260..i * 260 + 256]).as_bytes() == VK_PORTABILITY.to_bytes());
        let app = VkAppInfo { s_type: 0, p_next: std::ptr::null(), app_name: c"oarbank-gpu-probe".as_ptr(), app_version: 1,
                              engine_name: c"oarbank".as_ptr(), engine_version: 1, api_version: 1 << 22 };
        let names = [VK_PORTABILITY.as_ptr()];
        let info = VkInstanceInfo { s_type: 1, p_next: std::ptr::null(), flags: portable as u32, app_info: &app, layer_count: 0,
                                    layers: std::ptr::null(), extension_count: portable as u32,
                                    extensions: if portable { names.as_ptr() } else { std::ptr::null() } };
        let mut inst = std::ptr::null_mut();
        let r = vk.sym::<Create>("vkCreateInstance")?(&info, std::ptr::null(), &mut inst);
        if r != 0 {
            return Err(format!("vkCreateInstance failed ({r})"));
        }
        let (devs, props, queues) = (vk.sym::<EnumDev>("vkEnumeratePhysicalDevices")?, vk.sym::<Props>("vkGetPhysicalDeviceProperties")?,
                                     vk.sym::<Queues>("vkGetPhysicalDeviceQueueFamilyProperties")?);
        let mut n = 0u32;
        devs(inst, &mut n, std::ptr::null_mut());
        let mut handles = vec![std::ptr::null_mut(); n.max(1) as usize];
        devs(inst, &mut n, handles.as_mut_ptr());
        let (mut out, mut skipped) = (vec![], vec![]);
        for h in handles.iter().take(n as usize) {
            let mut buf = [0u8; 2048];                      // VkPhysicalDeviceProperties: deviceType at 16, deviceName at 20
            props(*h, buf.as_mut_ptr());
            let kind = u32::from_ne_bytes(buf[16..20].try_into().expect("4 bytes"));
            let name = cstr(&buf[20..276]);
            let mut q = 0u32;
            queues(*h, &mut q, std::ptr::null_mut());
            let mut fams = vec![0u32; 6 * q.max(1) as usize];  // VkQueueFamilyProperties: 6 words, queueFlags first
            queues(*h, &mut q, fams.as_mut_ptr());
            let compute = (0..q as usize).any(|k| fams[6 * k] & VK_COMPUTE != 0);
            if kind == VK_CPU || !compute {
                skipped.push(format!("{name} ({}{})", vk_type(kind), if compute { "" } else { ", no compute queue" }));
            } else {
                out.push(format!("{name} ({})", vk_type(kind)));
            }
        }
        vk.sym::<Destroy>("vkDestroyInstance")?(inst, std::ptr::null());
        if out.is_empty() {
            let only = if skipped.is_empty() { String::new() } else { format!(" (only {})", skipped.join(", ")) };
            return Err(format!("no Vulkan GPU device{only}"));
        }
        Ok(out)
    }
}

// MARK: cuda, rocm

fn cuda() -> Result<Vec<String>, String> {
    if cfg!(target_os = "macos") {
        return Err("CUDA does not run on macOS".into());
    }
    type Init = extern "system" fn(u32) -> i32;
    type Count = extern "system" fn(*mut i32) -> i32;
    type Get = extern "system" fn(*mut i32, i32) -> i32;
    type Name = extern "system" fn(*mut c_char, i32, i32) -> i32;
    let cu = Lib::open(if cfg!(windows) { &["nvcuda.dll"] } else { &["libcuda.so.1"] })?;
    unsafe {
        let r = cu.sym::<Init>("cuInit")?(0);
        if r != 0 {
            return Err(format!("cuInit failed ({r})"));
        }
        let mut n = 0;
        let r = cu.sym::<Count>("cuDeviceGetCount")?(&mut n);
        if r != 0 || n <= 0 {
            return Err(format!("no CUDA device ({r})"));
        }
        let (get, name) = (cu.sym::<Get>("cuDeviceGet")?, cu.sym::<Name>("cuDeviceGetName")?);
        Ok((0..n).map(|i| {
            let (mut d, mut buf) = (0, [0u8; 256]);
            if get(&mut d, i) == 0 && name(buf.as_mut_ptr() as *mut c_char, 256, d) == 0 { cstr(&buf) } else { format!("CUDA device {i}") }
        }).collect())
    }
}

fn rocm() -> Result<Vec<String>, String> {
    if cfg!(target_os = "macos") {
        return Err("ROCm does not run on macOS".into());
    }
    type Count = extern "system" fn(*mut i32) -> i32;
    type Name = extern "system" fn(*mut c_char, i32, i32) -> i32;
    let hip = Lib::open(if cfg!(windows) { &["amdhip64_7.dll", "amdhip64_6.dll", "amdhip64.dll"] }
                        else { &["libamdhip64.so", "libamdhip64.so.7", "libamdhip64.so.6", "/opt/rocm/lib/libamdhip64.so"] })?;
    unsafe {
        let mut n = 0;
        let r = hip.sym::<Count>("hipGetDeviceCount")?(&mut n);
        if r != 0 || n <= 0 {
            return Err(format!("no HIP device ({r})"));
        }
        let name = hip.sym::<Name>("hipDeviceGetName")?;
        Ok((0..n).map(|i| {
            let mut buf = [0u8; 256];
            if name(buf.as_mut_ptr() as *mut c_char, 256, i) == 0 { cstr(&buf) } else { format!("HIP device {i}") }
        }).collect())
    }
}

// MARK: opencl

const CL_GPU_OR_ACCELERATOR: u64 = 4 | 8;
const CL_DEVICE_NAME: u32 = 0x102B;

fn opencl() -> Result<Vec<String>, String> {
    type Platforms = extern "system" fn(u32, *mut *mut c_void, *mut u32) -> i32;
    type Devices = extern "system" fn(*mut c_void, u64, u32, *mut *mut c_void, *mut u32) -> i32;
    type Info = extern "system" fn(*mut c_void, u32, usize, *mut c_void, *mut usize) -> i32;
    let cl = Lib::open(if cfg!(target_os = "macos") { &["/System/Library/Frameworks/OpenCL.framework/OpenCL"] }
                       else if cfg!(windows) { &["OpenCL.dll"] } else { &["libOpenCL.so.1"] })?;
    unsafe {
        let plats = cl.sym::<Platforms>("clGetPlatformIDs")?;
        let mut n = 0u32;
        let r = plats(0, std::ptr::null_mut(), &mut n);
        if r != 0 || n == 0 {
            return Err(format!("no OpenCL platform ({r})"));
        }
        let mut ids = vec![std::ptr::null_mut(); n as usize];
        plats(n, ids.as_mut_ptr(), std::ptr::null_mut());
        let (devs, info) = (cl.sym::<Devices>("clGetDeviceIDs")?, cl.sym::<Info>("clGetDeviceInfo")?);
        let mut out = vec![];
        for p in ids {
            let mut nd = 0u32;
            if devs(p, CL_GPU_OR_ACCELERATOR, 0, std::ptr::null_mut(), &mut nd) != 0 || nd == 0 {
                continue;                                    // CL_DEVICE_NOT_FOUND: this platform has CPU devices only
            }
            let mut hs = vec![std::ptr::null_mut(); nd as usize];
            devs(p, CL_GPU_OR_ACCELERATOR, nd, hs.as_mut_ptr(), std::ptr::null_mut());
            for h in hs {
                let mut buf = [0u8; 256];
                let name = if info(h, CL_DEVICE_NAME, 256, buf.as_mut_ptr() as *mut c_void, std::ptr::null_mut()) == 0 { cstr(&buf) }
                           else { "an OpenCL device".to_string() };
                if !software(&name) {
                    out.push(name);
                }
            }
        }
        if out.is_empty() { Err("no OpenCL GPU or accelerator device".into()) } else { Ok(out) }
    }
}

// MARK: directml

/// DirectML runs on any Direct3D 12 hardware adapter at feature level 11_0; `D3D12CreateDevice` with no output pointer
/// answers S_FALSE when the adapter could create one, without creating it.
#[cfg(windows)]
fn directml() -> Result<Vec<String>, String> {
    #[repr(C)]
    struct Guid(u32, u16, u16, [u8; 8]);
    type CreateFactory = extern "system" fn(*const Guid, *mut *mut c_void) -> i32;
    type CreateDevice = extern "system" fn(*mut c_void, i32, *const Guid, *mut *mut c_void) -> i32;
    type EnumAdapters1 = extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
    type GetDesc1 = extern "system" fn(*mut c_void, *mut u8) -> i32;
    type Release = extern "system" fn(*mut c_void) -> u32;
    const IID_FACTORY1: Guid = Guid(0x770A_AE78, 0xF26F, 0x4DBA, [0xA8, 0x29, 0x25, 0x3C, 0x83, 0xD1, 0xB3, 0x87]);
    const IID_DEVICE: Guid = Guid(0x1898_19F1, 0x1DB6, 0x4B57, [0xBE, 0x54, 0x18, 0x21, 0x33, 0x9B, 0x85, 0xF7]);
    /// The `index`th entry of a COM object's vtable.
    unsafe fn method<T: Copy>(obj: *mut c_void, index: usize) -> T {
        let table = unsafe { *(obj as *const *const *mut c_void) };
        unsafe { std::mem::transmute_copy(&*table.add(index)) }
    }
    Lib::open(&["DirectML.dll"])?;
    let (dxgi, d3d12) = (Lib::open(&["dxgi.dll"])?, Lib::open(&["d3d12.dll"])?);
    unsafe {
        let mut factory = std::ptr::null_mut();
        if dxgi.sym::<CreateFactory>("CreateDXGIFactory1")?(&IID_FACTORY1, &mut factory) < 0 {
            return Err("CreateDXGIFactory1 failed".into());
        }
        let create = d3d12.sym::<CreateDevice>("D3D12CreateDevice")?;
        let (mut out, mut skipped) = (vec![], vec![]);
        for i in 0.. {
            let mut adapter = std::ptr::null_mut();
            if method::<EnumAdapters1>(factory, 12)(factory, i, &mut adapter) < 0 {
                break;                                       // DXGI_ERROR_NOT_FOUND: no more adapters
            }
            let mut desc = [0u8; 512];                       // DXGI_ADAPTER_DESC1
            method::<GetDesc1>(adapter, 10)(adapter, desc.as_mut_ptr());
            let wide: Vec<u16> = desc[..256].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|c| *c != 0).collect();
            let name = String::from_utf16_lossy(&wide);
            let off = 256 + 16 + 3 * std::mem::size_of::<usize>() + 8;
            let flags = u32::from_le_bytes(desc[off..off + 4].try_into().expect("4 bytes"));
            let ok = flags & 2 == 0 && create(adapter, 0xB000, &IID_DEVICE, std::ptr::null_mut()) >= 0;   // not SOFTWARE; 11_0
            if ok { out.push(name) } else { skipped.push(name) }
            method::<Release>(adapter, 2)(adapter);
        }
        method::<Release>(factory, 2)(factory);
        if out.is_empty() {
            let only = if skipped.is_empty() { String::new() } else { format!(" (only {})", skipped.join(", ")) };
            return Err(format!("no Direct3D 12 hardware adapter{only}"));
        }
        Ok(out)
    }
}

#[cfg(not(windows))]
fn directml() -> Result<Vec<String>, String> {
    Err("DirectML is Windows only".into())
}

/// The APIs a core detects (the SDK's `gpu.KNOWN_APIS`, pinned by a test), each with its probe; the set modules name is
/// open.
const PROBES: [(&str, Probe); 6] = [("cuda", cuda), ("directml", directml), ("metal", metal), ("opencl", opencl), ("rocm", rocm),
                                    ("vulkan", vulkan)];

/// How this node's containers get the GPU: (the API list, the evidence), from the container runtime.
#[cfg(unix)]
fn containers() -> (Vec<String>, String) {
    match crate::container_runtime::gpu_passthrough() {
        Some(p) => (p.apis, p.evidence),
        None if cfg!(target_os = "macos") => (vec![], "no GPU in containers: krunkit is not installed".into()),
        None => (vec![], "no GPU in containers: no container engine with a CDI spec for a GPU".into()),
    }
}

#[cfg(windows)]
fn containers() -> (Vec<String>, String) {
    (vec![], "no GPU in containers: no agent container runtime on Windows yet".into())
}

/// Every probe, in this process: `{host, containers, evidence}` (sorted lists; per API the devices found or why not, and
/// `containers` for the container mechanism).
pub fn detect() -> Value {
    let (mut host, mut evidence) = (vec![], BTreeMap::new());
    for (api, probe) in PROBES {
        match probe() {
            Ok(devices) => {
                host.push(api);
                evidence.insert(api.to_string(), devices.join(", "));
            }
            Err(why) => {
                evidence.insert(api.to_string(), why);
            }
        }
    }
    let (mut cont, why) = containers();
    cont.sort();
    evidence.insert("containers".into(), why);
    json!({"host": host, "containers": cont, "evidence": evidence})
}

/// `detect` in a child (`<exe> --home <home> gpu-apis`, which ends itself after a minute: `watchdog`): what the doctor
/// report carries. A child that fails leaves every API absent, with why.
pub fn probe(exe: &Path, home: &Path) -> Value {
    let out = std::process::Command::new(exe).arg("--home").arg(home).arg("gpu-apis").env("OARBANK_LOG", "error")
        .stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null()).output();
    parse_probe(match out {
        Ok(o) if o.status.success() => Ok(o.stdout),
        Ok(o) => Err(format!("the GPU probe failed ({}){}", o.status,
                             if o.status.code() == Some(WATCHDOG_EXIT) { format!(": still running after {} s", PROBE_LIMIT.as_secs()) }
                             else { String::new() })),
        Err(e) => Err(format!("cannot start the GPU probe: {e}")),
    })
}

/// The exit code of a probe its watchdog ended.
pub const WATCHDOG_EXIT: i32 = 124;

/// End this process after `limit`, however stuck a driver call is: the probe's own time limit, so its parent only waits
/// for it. `_exit` (no atexit handlers, which a driver may have registered and be blocked in).
pub fn watchdog(limit: Duration) {
    std::thread::spawn(move || {
        std::thread::sleep(limit);
        #[cfg(unix)]
        unsafe { libc::_exit(WATCHDOG_EXIT) };
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(windows_sys::Win32::System::Threading::GetCurrentProcess(),
                                                                    WATCHDOG_EXIT as u32)
        };
    });
}

/// The probe's limit, for `oarbank-agent gpu-apis`.
pub fn limit() -> Duration {
    PROBE_LIMIT
}

fn parse_probe(out: Result<Vec<u8>, String>) -> Value {
    let absent = |why: String| json!({"host": [], "containers": [], "evidence": {"probe": why}});
    match out {
        Err(why) => absent(why),
        Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) if v["host"].is_array() && v["containers"].is_array() =>
                json!({"host": v["host"], "containers": v["containers"], "evidence": v["evidence"]}),
            _ => absent(format!("the GPU probe printed no report: {}", String::from_utf8_lossy(&bytes).chars().take(300).collect::<String>())),
        },
    }
}

/// The node's host APIs in a report.
pub fn host(report: &Value) -> Vec<String> {
    report["host"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

/// Does a node with `have` meet a need for any of `any_of`? (An empty need is always met.)
pub fn fits(any_of: &[String], have: &[String]) -> bool {
    any_of.is_empty() || any_of.iter().any(|a| have.contains(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every known API is probed and has evidence; a Mac with Apple silicon always has Metal, and nothing else does.
    #[test]
    fn detection_names_every_api_with_its_evidence() {
        let r = detect();
        let host = host(&r);
        let mut sorted = host.clone();
        sorted.sort();
        assert_eq!(host, sorted);
        for (api, _) in PROBES {
            assert!(r["evidence"][api].as_str().is_some_and(|e| !e.is_empty()), "{api}: {r}");
        }
        assert!(r["evidence"]["containers"].is_string());
        assert_eq!(host.contains(&"metal".to_string()), cfg!(all(target_os = "macos", target_arch = "aarch64")), "{r}");
        if cfg!(not(target_os = "macos")) {
            assert_eq!(r["evidence"]["metal"], "Metal is macOS only");
        }
    }

    /// The agent detects exactly the APIs the SDK names (`KNOWN_APIS` in vendor/oarbank-sdk's gpu.py).
    #[test]
    fn the_apis_are_the_sdks() {
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../vendor/oarbank-sdk/src/oarbank_sdk/gpu.py"))
            .expect("the SDK's gpu.py");
        let line = src.lines().find(|l| l.starts_with("KNOWN_APIS = (")).expect("KNOWN_APIS in gpu.py");
        let sdk: Vec<&str> = line.split('"').skip(1).step_by(2).collect();
        assert_eq!(sdk, PROBES.map(|(a, _)| a));
    }

    #[test]
    fn fits_any_of() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(fits(&[], &[]) && fits(&s(&["cuda", "vulkan"]), &s(&["metal", "vulkan"])) && !fits(&s(&["cuda"]), &s(&["metal"])));
    }

    /// A probe that hangs ends itself at its limit (here the test binary in the role of `gpu-apis`, stuck after arming its
    /// watchdog), and one that fails or prints nothing leaves every API absent, with why: the agent itself never runs a
    /// driver.
    #[test]
    fn a_probe_that_hangs_or_fails_leaves_every_api_absent() {
        let t = std::time::Instant::now();
        let st = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["gpuapi::tests::stuck_probe_role", "--exact", "--ignored", "--quiet"]).env("OARBANK_TEST_STUCK_PROBE", "1")
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().unwrap();
        assert_eq!(st.code(), Some(WATCHDOG_EXIT));
        assert!(t.elapsed() < Duration::from_secs(20), "{:?}", t.elapsed());
        let r = probe(Path::new("/nonexistent/oarbank-agent"), Path::new("/nonexistent"));
        assert_eq!(r["host"], json!([]));
        assert!(r["evidence"]["probe"].as_str().unwrap().starts_with("cannot start the GPU probe"), "{r}");
        let r = parse_probe(Err("the GPU probe failed (signal: 11)".into()));
        assert_eq!(r, json!({"host": [], "containers": [], "evidence": {"probe": "the GPU probe failed (signal: 11)"}}));
        let r = parse_probe(Ok(b"not json".to_vec()));
        assert!(r["evidence"]["probe"].as_str().unwrap().starts_with("the GPU probe printed no report: not json"), "{r}");
        let r = parse_probe(Ok(br#"{"host": ["metal"], "containers": [], "evidence": {"metal": "M"}, "extra": 1}"#.to_vec()));
        assert_eq!(r, json!({"host": ["metal"], "containers": [], "evidence": {"metal": "M"}}));
    }

    #[test]
    #[ignore]
    fn stuck_probe_role() {
        if std::env::var("OARBANK_TEST_STUCK_PROBE").is_ok() {
            watchdog(Duration::from_millis(300));
            std::thread::sleep(Duration::from_secs(60));
        }
    }
}
