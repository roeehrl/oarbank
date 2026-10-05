//! Finding coordinators on the local network (docs/design/architecture.md, "Network and access"): a hint, never trust.
//! A URL found this way is only where to enroll; the owner still approves the node (or a join code carries the CA pin).
//!
//! macOS browses through the system responder's API in this process (`DNSServiceBrowse`, then `DNSServiceResolve` for
//! each instance), so Local Network privacy attributes the request to this program, whose embedded Info.plist says what
//! it is for, and a refusal (`kDNSServiceErr_PolicyDenied`) is reported as such (docs/design/architecture.md, "Local
//! Network privacy"). Linux browses through Avahi (`avahi-browse -rpt`) when it is installed, Windows through its own
//! DNS-SD API (`DnsServiceBrowse`, Windows 10 1809 and later). `OARBANK_DISCOVERY_TYPE` changes the service type
//! (tests).

use serde_json::{json, Value};
use std::process::Command;

pub fn service_type() -> String {
    std::env::var("OARBANK_DISCOVERY_TYPE").unwrap_or_else(|_| "_oarbank._tcp".into())
}

fn txt_map(line: &str) -> serde_json::Map<String, Value> {
    line.split_whitespace().filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_string(), json!(v))).collect()
}

/// The coordinators announcing themselves: `[{name, url, fleet_id, ca_prefix}]`. An error says why there could be no
/// answer at all (macOS refusing this program local network access).
#[cfg_attr(not(any(target_os = "macos", windows)), allow(unused_variables))]     // avahi-browse -t ends on its own
pub fn browse(secs: f64) -> Result<Vec<Value>, String> {
    let ty = service_type();
    let mut found = vec![];
    if cfg!(target_os = "macos") {
        #[cfg(target_os = "macos")]
        found.extend(mac::browse(&ty, secs).map_err(mac::explain)?);
    } else if cfg!(windows) {
        #[cfg(windows)]
        found.extend(win::browse(&ty, secs));
    } else if let Ok(out) = Command::new("avahi-browse").args(["-rpt", &ty]).output() {
        // =;eth0;IPv4;Oarbank abcd;_oarbank._tcp;local;host.local;192.168.1.5;7443;"fleet=…" "ca=…" "v=1"
        for l in String::from_utf8_lossy(&out.stdout).lines().filter(|l| l.starts_with('=')) {
            let f: Vec<&str> = l.splitn(10, ';').collect();
            if f.len() == 10 {
                let txt = txt_map(&f[9].replace('"', " "));
                let url = format!("https://{}:{}", f[6], f[8]);
                if !found.iter().any(|x: &Value| x["url"] == url) {
                    found.push(json!({"name": f[3], "url": url, "fleet_id": txt.get("fleet"), "ca_prefix": txt.get("ca")}));
                }
            }
        }
    }
    Ok(found)
}

#[cfg(target_os = "macos")]
mod mac {
    use serde_json::{json, Value};
    use std::ffi::{c_char, c_void, CStr, CString};
    use std::time::{Duration, Instant};

    pub type Ref = *mut c_void;
    type BrowseReply = extern "C" fn(Ref, u32, u32, i32, *const c_char, *const c_char, *const c_char, *mut c_void);
    type ResolveReply = extern "C" fn(Ref, u32, u32, i32, *const c_char, *const c_char, u16, u16, *const u8, *mut c_void);

    // dns_sd.h, in libSystem
    unsafe extern "C" {
        fn DNSServiceBrowse(r: *mut Ref, flags: u32, iface: u32, regtype: *const c_char, domain: *const c_char, cb: BrowseReply,
                            ctx: *mut c_void) -> i32;
        fn DNSServiceResolve(r: *mut Ref, flags: u32, iface: u32, name: *const c_char, regtype: *const c_char,
                             domain: *const c_char, cb: ResolveReply, ctx: *mut c_void) -> i32;
        pub fn DNSServiceRefSockFD(r: Ref) -> i32;
        pub fn DNSServiceProcessResult(r: Ref) -> i32;
        pub fn DNSServiceRefDeallocate(r: Ref);
    }

    /// kDNSServiceErr_PolicyDenied: macOS refused the request (Local Network privacy)
    pub const POLICY_DENIED: i32 = -65570;
    const FLAG_ADD: u32 = 0x2;

    pub fn explain(e: i32) -> String {
        if e == POLICY_DENIED {
            "macOS refuses this program local network access, so it cannot look for coordinators: allow it in System Settings, \
             Privacy & Security, Local Network, or give --coordinator <url> or --join <code>".into()
        } else {
            format!("looking for coordinators failed (DNS-SD error {e})")
        }
    }

    /// Handle the replies on `r` as they arrive, waiting on its socket, until `stop()` or `deadline`; a failed reply
    /// processing is returned.
    pub fn pump(r: Ref, deadline: Instant, stop: &dyn Fn() -> bool) -> Result<(), i32> {
        let fd = unsafe { DNSServiceRefSockFD(r) };
        while !stop() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            let n = unsafe { libc::poll(&mut p, 1, left.as_millis().clamp(1, i32::MAX as u128) as i32) };
            if n > 0 {
                let e = unsafe { DNSServiceProcessResult(r) };
                if e != 0 {
                    return Err(e);
                }
            } else if n < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
        Ok(())
    }

    #[derive(Default)]
    struct Browsing {
        names: Vec<(String, String)>,            // (instance, domain)
        error: i32,
    }

    extern "C" fn on_browse(_: Ref, flags: u32, _iface: u32, err: i32, name: *const c_char, _ty: *const c_char,
                            domain: *const c_char, ctx: *mut c_void) {
        // SAFETY: ctx is the Browsing that `browse` keeps alive while it processes this reference's replies
        let b = unsafe { &mut *(ctx as *mut Browsing) };
        if err != 0 {
            b.error = err;
            return;
        }
        let (n, d) = unsafe { (CStr::from_ptr(name).to_string_lossy().into_owned(), CStr::from_ptr(domain).to_string_lossy().into_owned()) };
        if flags & FLAG_ADD == 0 {
            b.names.retain(|x| x.0 != n);
        } else if !b.names.iter().any(|x| x.0 == n) {
            b.names.push((n, d));
        }
    }

    /// A resolved instance: host, port and TXT record.
    type Instance = (String, u16, serde_json::Map<String, Value>);

    #[derive(Default)]
    struct Resolving {
        found: Option<Instance>,
        error: i32,
    }

    extern "C" fn on_resolve(_: Ref, _flags: u32, _iface: u32, err: i32, _full: *const c_char, host: *const c_char, port: u16,
                             txt_len: u16, txt: *const u8, ctx: *mut c_void) {
        // SAFETY: ctx is the Resolving that `resolve` keeps alive while it processes this reference's replies
        let r = unsafe { &mut *(ctx as *mut Resolving) };
        if err != 0 {
            r.error = err;
            return;
        }
        let host = unsafe { CStr::from_ptr(host).to_string_lossy() }.trim_end_matches('.').to_string();
        let record = if txt.is_null() { &[][..] } else { unsafe { std::slice::from_raw_parts(txt, txt_len as usize) } };
        r.found = Some((host, u16::from_be(port), txt_record(record)));
    }

    /// A TXT record's `key=value` strings (each preceded by its length byte).
    pub fn txt_record(mut b: &[u8]) -> serde_json::Map<String, Value> {
        let mut out = serde_json::Map::new();
        while let Some((&n, rest)) = b.split_first() {
            let (s, tail) = rest.split_at((n as usize).min(rest.len()));
            if let Some((k, v)) = String::from_utf8_lossy(s).split_once('=') {
                out.insert(k.to_string(), json!(v));
            }
            b = tail;
        }
        out
    }

    pub fn browse(ty: &str, secs: f64) -> Result<Vec<Value>, i32> {
        let cty = CString::new(ty).map_err(|_| -65540)?;                              // kDNSServiceErr_BadParam
        let st = Box::into_raw(Box::<Browsing>::default());
        let mut r: Ref = std::ptr::null_mut();
        let e = unsafe { DNSServiceBrowse(&mut r, 0, 0, cty.as_ptr(), std::ptr::null(), on_browse, st as *mut c_void) };
        let names = if e != 0 {
            Err(e)
        } else {
            let pumped = pump(r, Instant::now() + Duration::from_secs_f64(secs), &|| unsafe { (*st).error != 0 });
            unsafe { DNSServiceRefDeallocate(r) };
            let got = unsafe { &*st };
            match (pumped, got.error) {
                (Err(e), _) | (_, e @ ..=-1) => Err(e),
                _ => Ok(got.names.clone()),
            }
        };
        drop(unsafe { Box::from_raw(st) });
        let mut found = vec![];
        for (name, domain) in names? {
            if let Some((host, port, txt)) = resolve(&name, ty, &domain)? {
                found.push(json!({"name": name, "url": format!("https://{host}:{port}"), "fleet_id": txt.get("fleet"),
                                  "ca_prefix": txt.get("ca")}));
            }
        }
        Ok(found)
    }

    fn resolve(name: &str, ty: &str, domain: &str) -> Result<Option<Instance>, i32> {
        let (cn, ct, cd) = (CString::new(name).map_err(|_| -65540)?, CString::new(ty).map_err(|_| -65540)?,
                            CString::new(domain).map_err(|_| -65540)?);
        let st = Box::into_raw(Box::<Resolving>::default());
        let mut r: Ref = std::ptr::null_mut();
        let e = unsafe { DNSServiceResolve(&mut r, 0, 0, cn.as_ptr(), ct.as_ptr(), cd.as_ptr(), on_resolve, st as *mut c_void) };
        let out = if e != 0 {
            Err(e)
        } else {
            let pumped = pump(r, Instant::now() + Duration::from_millis(1500),
                              &|| unsafe { (*st).found.is_some() || (*st).error != 0 });
            unsafe { DNSServiceRefDeallocate(r) };
            let got = unsafe { &mut *st };
            match (pumped, got.error) {
                (Err(e), _) | (_, e @ ..=-1) => Err(e),
                _ => Ok(got.found.take()),
            }
        };
        drop(unsafe { Box::from_raw(st) });
        out
    }
}

#[cfg(windows)]
mod win {
    use serde_json::{json, Value};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::NetworkManagement::Dns::{DnsFree, DnsFreeRecordList, DnsServiceBrowse, DnsServiceBrowseCancel,
                                                     DnsServiceFreeInstance, DnsServiceResolve, DnsServiceResolveCancel,
                                                     DNS_QUERY_REQUEST_VERSION1, DNS_RECORDW, DNS_SERVICE_BROWSE_REQUEST,
                                                     DNS_SERVICE_BROWSE_REQUEST_0, DNS_SERVICE_CANCEL, DNS_SERVICE_INSTANCE,
                                                     DNS_SERVICE_RESOLVE_REQUEST, DNS_TYPE_PTR};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe fn pwstr(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
    }

    unsafe extern "system" fn on_browse(_status: u32, ctx: *const core::ffi::c_void, rec: *const DNS_RECORDW) {
        let names = unsafe { &*(ctx as *const Mutex<Vec<String>>) };
        let mut r = rec;
        while !r.is_null() {
            let x = unsafe { &*r };
            if x.wType == DNS_TYPE_PTR {
                let n = unsafe { pwstr(x.Data.PTR.pNameHost) };
                let mut v = names.lock().unwrap();
                if !n.is_empty() && !v.contains(&n) {
                    v.push(n);
                }
            }
            r = x.pNext;
        }
        if !rec.is_null() {
            unsafe { DnsFree(rec as _, DnsFreeRecordList) };
        }
    }

    unsafe extern "system" fn on_resolve(_status: u32, ctx: *const core::ffi::c_void, inst: *const DNS_SERVICE_INSTANCE) {
        let out = unsafe { &*(ctx as *const Mutex<Option<Value>>) };
        if inst.is_null() {
            return;
        }
        let i = unsafe { &*inst };
        let mut txt = serde_json::Map::new();
        for k in 0..i.dwPropertyCount as usize {
            let (key, val) = unsafe { (pwstr(*i.keys.add(k)), pwstr(*i.values.add(k))) };
            txt.insert(key, json!(val));
        }
        let host = unsafe { pwstr(i.pszHostName) };
        *out.lock().unwrap() = Some(json!({"host": host.trim_end_matches('.'), "port": i.wPort, "txt": txt}));
        unsafe { DnsServiceFreeInstance(inst) };
    }

    pub fn browse(ty: &str, secs: f64) -> Vec<Value> {
        // the callbacks may fire until cancelled: their contexts are leaked rather than risk a use after free
        let names: &'static Mutex<Vec<String>> = Box::leak(Box::new(Mutex::new(vec![])));
        let q = wide(&format!("{ty}.local"));
        let req = DNS_SERVICE_BROWSE_REQUEST { Version: DNS_QUERY_REQUEST_VERSION1, InterfaceIndex: 0, QueryName: q.as_ptr(),
            Anonymous: DNS_SERVICE_BROWSE_REQUEST_0 { pBrowseCallback: Some(on_browse) }, pQueryContext: names as *const _ as *mut _ };
        let mut cancel = DNS_SERVICE_CANCEL { reserved: std::ptr::null_mut() };
        if unsafe { DnsServiceBrowse(&req, &mut cancel) } != 9506 {            // DNS_REQUEST_PENDING
            return vec![];
        }
        std::thread::sleep(Duration::from_secs_f64(secs));
        unsafe { DnsServiceBrowseCancel(&cancel) };
        let mut found = vec![];
        for name in names.lock().unwrap().clone() {
            let slot: &'static Mutex<Option<Value>> = Box::leak(Box::new(Mutex::new(None)));
            let mut n = wide(&name);
            let req = DNS_SERVICE_RESOLVE_REQUEST { Version: DNS_QUERY_REQUEST_VERSION1, InterfaceIndex: 0, QueryName: n.as_mut_ptr(),
                pResolveCompletionCallback: Some(on_resolve), pQueryContext: slot as *const _ as *mut _ };
            let mut c = DNS_SERVICE_CANCEL { reserved: std::ptr::null_mut() };
            if unsafe { DnsServiceResolve(&req, &mut c) } != 9506 {
                continue;
            }
            let deadline = Instant::now() + Duration::from_millis(1500);
            while slot.lock().unwrap().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            unsafe { DnsServiceResolveCancel(&c) };
            if let Some(r) = slot.lock().unwrap().clone() {
                let label = name.split("._").next().unwrap_or(&name).to_string();
                found.push(json!({"name": label, "url": format!("https://{}:{}", r["host"].as_str().unwrap_or(""), r["port"]),
                                  "fleet_id": r["txt"]["fleet"], "ca_prefix": r["txt"]["ca"]}));
            }
        }
        found
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    unsafe extern "C" {
        fn DNSServiceRegister(r: *mut mac::Ref, flags: u32, iface: u32, name: *const std::ffi::c_char,
                              regtype: *const std::ffi::c_char, domain: *const std::ffi::c_char, host: *const std::ffi::c_char,
                              port: u16, txt_len: u16, txt: *const u8,
                              cb: Option<extern "C" fn(mac::Ref, u32, i32, *const std::ffi::c_char, *const std::ffi::c_char,
                                                       *const std::ffi::c_char, *mut std::ffi::c_void)>,
                              ctx: *mut std::ffi::c_void) -> i32;
    }

    /// The agent finds a coordinator announced on this Mac through the responder's API, URL and TXT record included.
    #[test]
    fn finds_an_announced_coordinator() {
        let ty = format!("_oarbt{:x}._tcp", std::process::id() as u64 * 7919 % 0xffffff);
        let txt: Vec<u8> = ["fleet=fleet_ab12cd34", "ca=0011223344556677", "v=1"].iter()
            .flat_map(|kv| std::iter::once(kv.len() as u8).chain(kv.bytes())).collect();
        let (name, cty) = (std::ffi::CString::new("Oarbank ab12cd34").unwrap(), std::ffi::CString::new(ty.clone()).unwrap());
        let mut r: mac::Ref = std::ptr::null_mut();
        let e = unsafe { DNSServiceRegister(&mut r, 0, 0, name.as_ptr(), cty.as_ptr(), std::ptr::null(), std::ptr::null(),
                                            7443u16.to_be(), txt.len() as u16, txt.as_ptr(), None, std::ptr::null_mut()) };
        assert_eq!(e, 0);
        let found = mac::browse(&ty, 3.0).unwrap();
        unsafe { mac::DNSServiceRefDeallocate(r) };
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0]["name"], "Oarbank ab12cd34");
        assert!(found[0]["url"].as_str().unwrap().ends_with(":7443"), "{found:?}");
        assert_eq!((found[0]["fleet_id"].as_str(), found[0]["ca_prefix"].as_str()), (Some("fleet_ab12cd34"), Some("0011223344556677")));
    }

    #[test]
    fn reads_a_txt_record_and_explains_a_refusal() {
        let m = mac::txt_record(b"\x0bfleet=f_abc\x03v=1\x04flag");
        assert_eq!((m["fleet"].as_str(), m["v"].as_str(), m.len()), (Some("f_abc"), Some("1"), 2));
        assert!(mac::explain(mac::POLICY_DENIED).contains("Local Network"));
    }
}
