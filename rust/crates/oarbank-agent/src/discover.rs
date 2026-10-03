//! Finding coordinators on the local network (docs/design/architecture.md, "Network and access"): a hint, never trust.
//! A URL found this way is only where to enroll; the owner still approves the node (or a join code carries the CA pin).
//!
//! macOS browses through the system responder (`dns-sd -B`, then `-L` for each instance), Linux through Avahi
//! (`avahi-browse -rpt`) when it is installed, Windows through its own DNS-SD API (`DnsServiceBrowse`, Windows 10
//! 1809 and later). `OARBANK_DISCOVERY_TYPE` changes the service type (tests).

use serde_json::{json, Value};
use std::process::{Command, Stdio};
use std::time::Duration;

pub fn service_type() -> String {
    std::env::var("OARBANK_DISCOVERY_TYPE").unwrap_or_else(|_| "_oarbank._tcp".into())
}

/// Run a browsing command for `secs`, then stop it and return what it printed.
fn collect(argv: &[&str], secs: f64) -> String {
    let Ok(mut child) = Command::new(argv[0]).args(&argv[1..]).stdin(Stdio::null()).stdout(Stdio::piped())
        .stderr(Stdio::null()).spawn() else { return String::new() };
    std::thread::sleep(Duration::from_secs_f64(secs));
    let _ = child.kill();
    child.wait_with_output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default()
}

fn txt_map(line: &str) -> serde_json::Map<String, Value> {
    line.split_whitespace().filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_string(), json!(v))).collect()
}

/// `dns-sd -B` lines: the instance name is everything after the sixth column of an `Add` row.
pub fn parse_browse(out: &str) -> Vec<String> {
    let mut names: Vec<String> = vec![];
    for l in out.lines() {
        let cols: Vec<&str> = l.split_whitespace().collect();
        if cols.len() >= 7 && cols[1] == "Add" {
            let name = cols[6..].join(" ");
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

/// `dns-sd -L` output: "… can be reached at <host>.:<port> (interface N)" and the TXT record on the next line.
pub fn parse_lookup(out: &str) -> Option<(String, u16, serde_json::Map<String, Value>)> {
    let lines: Vec<&str> = out.lines().collect();
    for (i, l) in lines.iter().enumerate() {
        if let Some(rest) = l.split(" can be reached at ").nth(1) {
            let hp = rest.split_whitespace().next()?;
            let (host, port) = hp.rsplit_once(':')?;
            let txt = lines.get(i + 1).map(|t| txt_map(t)).unwrap_or_default();
            return Some((host.trim_end_matches('.').to_string(), port.parse().ok()?, txt));
        }
    }
    None
}

/// The coordinators announcing themselves: `[{name, url, fleet_id, ca_prefix}]`.
pub fn browse(secs: f64) -> Vec<Value> {
    let ty = service_type();
    let mut found = vec![];
    if cfg!(target_os = "macos") && std::path::Path::new("/usr/bin/dns-sd").exists() {
        for name in parse_browse(&collect(&["/usr/bin/dns-sd", "-B", &ty, "local."], secs)) {
            if let Some((host, port, txt)) = parse_lookup(&collect(&["/usr/bin/dns-sd", "-L", &name, &ty, "local."], 1.5)) {
                found.push(json!({"name": name, "url": format!("https://{host}:{port}"), "fleet_id": txt.get("fleet"),
                                  "ca_prefix": txt.get("ca")}));
            }
        }
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
    found
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_system_responder() {
        let b = "Browsing for _oarbank._tcp.local.\nTimestamp     A/R    Flags  if Domain               Service Type         Instance Name\n \
                 4:14:55.068  Add        3   1 local.               _oarbank._tcp.   Oarbank ab12cd34\n \
                 4:14:55.068  Add        2  27 local.               _oarbank._tcp.   Oarbank ab12cd34\n";
        assert_eq!(parse_browse(b), vec!["Oarbank ab12cd34".to_string()]);
        let l = "Lookup Oarbank ab12cd34._oarbank._tcp.local.\n 4:14:57.079  Oarbank\\032ab12cd34._oarbank._tcp.local. can be \
                 reached at coordinator.local.:7443 (interface 27) Flags: 1\n fleet=f_ab12cd34 ca=0011223344556677 v=1\n";
        let (h, p, t) = parse_lookup(l).unwrap();
        assert_eq!((h.as_str(), p, t["fleet"].as_str()), ("coordinator.local", 7443, Some("f_ab12cd34")));
    }
}
