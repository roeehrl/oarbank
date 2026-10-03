//! The macOS Seatbelt goldens (spec/sandbox/backends/macos-golden) and the path handling of `render`.

use std::path::PathBuf;

use oarbank_core::sandbox::{self, Policy};
use serde_json::Value;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../vendor/oarbank-sdk/spec/sandbox/backends/macos-golden")
}

/// A fresh directory under the system temp dir, resolved (macOS's /var is a symlink to /private/var).
#[cfg(unix)]
fn scratch(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().canonicalize().unwrap();
    let d = base.join(format!("oarbank-core-{tag}-{}-{:?}", std::process::id(), std::thread::current().id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[cfg(unix)]
fn s(p: &std::path::Path) -> String {
    p.to_str().unwrap().to_string()
}

#[test]
fn golden_profiles_are_reproduced() {
    let cases: Value = serde_json::from_str(&std::fs::read_to_string(golden_dir().join("cases.json")).unwrap()).unwrap();
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let want = std::fs::read_to_string(golden_dir().join(format!("{name}.sb"))).unwrap();
        let n = |k: &str| c[k].as_u64().unwrap() as usize;
        let got = sandbox::render_text(
            c["kind"].as_str().unwrap(),
            n("ro"),
            n("rw"),
            n("links"),
            c["net"].as_str().unwrap(),
            c["broker"].as_bool().unwrap(),
            c["gpu"].as_bool().unwrap(),
            c.get("proxy_port").and_then(Value::as_u64).map(|p| p as u16),
            c.get("exec_rw").and_then(Value::as_bool).unwrap_or(false),
        )
        .unwrap();
        assert_eq!(got, want, "{name}");
    }
}

#[cfg(unix)]
#[test]
fn paths_are_parameters_resolved_with_their_links() {
    let t = scratch("links");
    let real = t.join("real");
    std::fs::create_dir_all(real.join("bin")).unwrap();
    std::os::unix::fs::symlink(&real, t.join("link")).unwrap();
    let mut pol = Policy::new("dev.x.y");
    pol.ro = vec![s(&t.join("link").join("bin"))];
    pol.rw = vec![s(&t.join("w"))]; // does not exist: kept as written
    let (text, params) = sandbox::render(&pol).unwrap();
    let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    assert_eq!(params[0], ("MODULE_ID".to_string(), "dev.x.y".to_string()));
    assert_eq!(get("RO_0").unwrap(), s(&real.join("bin")));
    assert_eq!(get("RW_0").unwrap(), s(&t.join("w")));
    assert_eq!(get("LINK_0").unwrap(), s(&t.join("link")));
    assert!(get("LINK_1").is_none());
    assert!(!text.contains(t.to_str().unwrap()), "paths never enter the text");
    assert_eq!(text, sandbox::render_text("runner", 1, 1, 1, "none", false, false, None, false).unwrap());
    std::fs::remove_dir_all(&t).unwrap();
}

#[cfg(unix)]
#[test]
fn links_are_followed_hop_by_hop_and_deduplicated() {
    use std::os::unix::fs::symlink;
    let t = scratch("hops");
    std::fs::create_dir_all(t.join("c/d")).unwrap();
    symlink("c", t.join("b")).unwrap(); // relative target
    symlink(t.join("b"), t.join("a")).unwrap(); // absolute target, to another link
    symlink("../c/d", t.join("c/up")).unwrap(); // relative with ..
    assert_eq!(sandbox::links_of(&s(&t.join("a/d"))).unwrap(), vec![s(&t.join("a")), s(&t.join("b"))]);
    assert_eq!(sandbox::links_of(&s(&t.join("c/up/x"))).unwrap(), vec![s(&t.join("c/up"))]);
    assert!(sandbox::links_of(&s(&t.join("c/d/missing/deeper"))).unwrap().is_empty());
    assert_eq!(sandbox::realpath(&s(&t.join("a/d/../up"))).unwrap(), s(&t.join("c/d")));
    symlink("loop2", t.join("loop1")).unwrap();
    symlink("loop1", t.join("loop2")).unwrap();
    assert!(sandbox::links_of(&s(&t.join("loop1"))).unwrap_err().0.starts_with("symlink loop resolving"));
    assert_eq!(sandbox::realpath(&s(&t.join("loop1/x"))).unwrap(), s(&t.join("loop1/x")));

    let mut pol = Policy::new("m");
    pol.ro = vec![s(&t.join("a/d")), s(&t.join("c/d"))]; // the same directory twice
    pol.rw = vec![s(&t.join("b"))];
    pol.exe = Some(s(&t.join("a")));
    pol.broker_socket = Some(s(&t.join("b/broker.sock")));
    pol.net = "egress-allowlist".into();
    pol.proxy_port = Some(47001);
    let (text, params) = sandbox::render(&pol).unwrap();
    let names: Vec<&str> = params.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, ["MODULE_ID", "RO_0", "RW_0", "LINK_0", "LINK_1", "BROKER_SOCKET"]);
    assert_eq!(params[5].1, s(&t.join("c/broker.sock")));
    assert_eq!(text, sandbox::render_text("runner", 1, 1, 2, "egress-allowlist", true, false, Some(47001), false).unwrap());
    std::fs::remove_dir_all(&t).unwrap();
}

#[test]
fn unknown_network_modes_and_bad_paths_are_refused() {
    let mut pol = Policy::new("m");
    pol.net = "egress-everything".into();
    assert!(sandbox::render(&pol).is_err());
    let mut pol = Policy::new("m");
    pol.ro = vec!["/tmp/a\nb".into()];
    assert!(sandbox::render(&pol).is_err());
}
