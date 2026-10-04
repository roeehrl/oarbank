//! The module sandbox (spec/sandbox.md): the OS-neutral `Policy` and its macOS backend (Seatbelt), byte-identical to
//! the SDK's `sandbox.py` (`render_text`, `render`, `links_of`); spec/sandbox/backends/macos-golden pins the text.
//!
//! The profile text depends only on the policy's shape (counts and flags). Every path enters as a parameter
//! (`sandbox_init_with_parameters`), never as text, after `realpath`, because the kernel matches resolved paths; each
//! symlink met on the way gets a metadata rule (`LINK_i`) on itself and on the directories above it, which
//! `realpath` (CPython's startup among them) walks with lstat and readlink; reading stays limited to resolved roots.

use std::collections::{HashMap, HashSet};
use std::fs;

pub const PROFILE_VERSION: u32 = 4;
pub const BACKEND: &str = "seatbelt";
pub const NET_MODES: [&str; 3] = ["none", "egress-allowlist", "egress-any"];

/// What this backend enforces, per capability (spec/platforms.md, "What each OS enforces").
pub const ENFORCEMENT: [(&str, &str); 10] = [
    ("fs", "enforced"),
    ("ipc", "enforced"),
    ("net.none", "enforced"),
    ("net.egress-allowlist", "enforced"),
    ("net.egress-any", "enforced"),
    ("net.no-loopback", "enforced"),
    ("net.no-link-local", "unavailable"),
    ("exec_writable.deny", "enforced"),
    ("devices.gpu", "enforced"),
    ("children", "enforced"),
];

const HEAD: &str = r#"(version 1)
;; oarbank module sandbox, profile {version} ({kind})
(deny default (with message (param "MODULE_ID")))

;; process
(allow process-fork)
(allow process-exec (subpath "/bin") (subpath "/usr/bin") (subpath "/usr/libexec"))
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
(allow sysctl-read)
(allow ipc-posix-sem)
(allow ipc-posix-shm-read-data ipc-posix-shm-read-metadata (ipc-posix-name "apple.shm.notification_center"))
(allow mach-lookup
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.system.notification_center")
  (global-name "com.apple.logd")
  (global-name "com.apple.system.logger"))

;; read-only system
(allow file-read* (literal "/"))
(allow file-read-metadata (literal "/tmp") (literal "/var") (literal "/etc") (literal "/private/var/select/sh"))
(allow file-read* file-map-executable
  (subpath "/System") (subpath "/usr/lib") (subpath "/usr/share") (subpath "/Library/Apple")
  (subpath "/private/var/db/timezone") (subpath "/bin") (subpath "/usr/bin") (subpath "/usr/libexec")
  (literal "/private/etc/hosts") (literal "/private/etc/resolv.conf") (literal "/private/var/run/resolv.conf")
  (literal "/private/var/select/sh") (literal "/private/etc/services") (literal "/private/etc/protocols")
  (literal "/private/etc/localtime") (subpath "/private/etc/ssl")
  (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom")
  (literal "/dev/dtracehelper") (subpath "/dev/fd"))
(allow file-write-data (literal "/dev/null") (literal "/dev/zero") (subpath "/dev/fd"))
(allow file-ioctl (literal "/dev/dtracehelper"))
"#;
const RO: &str = r#"(allow file-read* file-map-executable process-exec (subpath (param "RO_{i}")))
(allow file-read-metadata (path-ancestors (param "RO_{i}")))
"#;
const RW: &str = r#"(allow file-read* file-write* (subpath (param "RW_{i}")))
(allow file-read-metadata (path-ancestors (param "RW_{i}")))
"#;
const RD: &str = r#"(allow file-read* (subpath (param "RD_{i}")))
(allow file-read-metadata (path-ancestors (param "RD_{i}")))
"#;
// an outbox: create regular files and directories (never links) and write them; no reading, listing, unlink or rename
const WO: &str = r#"(allow file-read-metadata (subpath (param "WO_{i}")) (path-ancestors (param "WO_{i}")))
(allow file-write-create (require-all (subpath (param "WO_{i}")) (vnode-type REGULAR-FILE DIRECTORY)))
(allow file-write-data (subpath (param "WO_{i}")))
"#;
const LINK: &str = r#"(allow file-read-metadata (literal (param "LINK_{i}")) (path-ancestors (param "LINK_{i}")))
"#;
const EGRESS_ANY: &str = r#"
;; grant: network egress-any (public addresses and DNS; never unix sockets, loopback or listening)
(allow system-socket)
(allow network-outbound (remote ip "*:*"))
(allow network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))
(allow mach-lookup (global-name "com.apple.dnssd.service"))
"#;
const EGRESS_PROXY: &str = r#"
;; grant: network egress-allowlist (only the agent's local proxy, which enforces the allowed hosts)
(allow system-socket)
(allow network-outbound (remote ip "localhost:{port}"))
"#;
const BROKER: &str = r#"
;; grant: the agent's container broker (this job's socket only)
(allow system-socket (socket-domain AF_UNIX))
(allow network-outbound (remote unix-socket (path-literal (param "BROKER_SOCKET"))))
"#;
const HARDEN: &str = r#"
;; hardening (last match wins: keep after every allow above)
(deny mach-lookup (xpc-service-name-prefix ""))
(deny system-fcntl (fcntl-command 80 110))
"#;
const NO_LOOPBACK: &str = r#"(deny network-outbound (remote ip "localhost:*"))
"#;
const RW_EXEC: &str = r#"(allow file-map-executable process-exec (subpath (param "RW_{i}")))
"#;
const GPU: &str = r#"
;; grant: GPU (Metal)
(allow iokit-open-service (iokit-registry-entry-class "IOAccelerator" "AGXAccelerator"))
(allow iokit-open-user-client (iokit-user-client-class "AGXDeviceUserClient" "IOAccelerationUserClient" "IOSurfaceRootUserClient"))
(allow iokit-get-properties)
(allow mach-lookup (global-name "com.apple.MTLCompilerService") (xpc-service-name "com.apple.MTLCompilerService"))
"#;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SandboxError(pub String);

fn fail<T>(msg: impl Into<String>) -> Result<T, SandboxError> {
    Err(SandboxError(msg.into()))
}

/// What one module process may touch. `ro`: read, map and exec (bundle, interpreter, approved host paths); `rw`: read
/// and write (data dir, job work dir, tmp); `rd`: read only, never execute (a runner's read folders); `wo`: create and
/// write, never read, list, unlink or rename (a runner's outboxes). The kind only labels the profile.
/// A module process's policy; also the JSON the Linux and Windows launchers read (`#[serde(default)]`: the SDK's
/// Python `Policy` serialises the same fields).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Policy {
    pub module: String,
    pub ro: Vec<String>,
    pub rw: Vec<String>,
    /// `none` | `egress-allowlist` (through `proxy_port`) | `egress-any`
    pub net: String,
    pub proxy_port: Option<u16>,
    pub broker_socket: Option<String>,
    pub gpu: bool,
    /// exec_writable: the rw roots may hold executables
    pub exec_rw: bool,
    pub kind: String,
    /// argv[0]: its symlink hops need metadata rules too
    pub exe: Option<String>,
    pub rd: Vec<String>,
    pub wo: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy::new("")
    }
}

impl Policy {
    pub fn new(module: impl Into<String>) -> Self {
        Policy {
            module: module.into(),
            ro: Vec::new(),
            rw: Vec::new(),
            net: "none".into(),
            proxy_port: None,
            broker_socket: None,
            gpu: false,
            exec_rw: false,
            kind: "runner".into(),
            exe: None,
            rd: Vec::new(),
            wo: Vec::new(),
        }
    }
}

/// The profile text for a policy shape (spec/sandbox/backends/macos-golden pins it).
#[allow(clippy::too_many_arguments)]
pub fn render_text(
    kind: &str,
    n_ro: usize,
    n_rw: usize,
    n_links: usize,
    net: &str,
    broker: bool,
    gpu: bool,
    proxy_port: Option<u16>,
    exec_rw: bool,
    n_rd: usize,
    n_wo: usize,
) -> Result<String, SandboxError> {
    if !NET_MODES.contains(&net) {
        return fail(format!("network mode {} is not enforceable by the {BACKEND} backend", crate::py::repr(net)));
    }
    let port = proxy_port.filter(|p| *p != 0);
    if net == "egress-allowlist" && port.is_none() {
        return fail("egress-allowlist needs the agent's proxy port");
    }
    let mut s = HEAD.replace("{version}", &PROFILE_VERSION.to_string()).replace("{kind}", kind);
    s.push_str("\n;; module grants\n");
    let idx = |t: &str, i: usize| t.replace("{i}", &i.to_string());
    for i in 0..n_ro {
        s.push_str(&idx(RO, i));
    }
    for i in 0..n_rw {
        s.push_str(&idx(RW, i));
        if exec_rw {
            s.push_str(&idx(RW_EXEC, i));
        }
    }
    for i in 0..n_rd {
        s.push_str(&idx(RD, i));
    }
    for i in 0..n_wo {
        s.push_str(&idx(WO, i));
    }
    for i in 0..n_links {
        s.push_str(&idx(LINK, i));
    }
    match net {
        "egress-any" => s.push_str(EGRESS_ANY),
        "egress-allowlist" => s.push_str(&EGRESS_PROXY.replace("{port}", &port.unwrap_or_default().to_string())),
        _ => {}
    }
    if broker {
        s.push_str(BROKER);
    }
    s.push_str(HARDEN);
    if net == "egress-any" {
        s.push_str(NO_LOOPBACK); // after the egress allow: loopback is never reachable
    }
    if gpu {
        s.push_str(GPU); // after the hardening deny: its XPC allow must win
    }
    Ok(s)
}

/// The profile text and its parameters (`MODULE_ID`, `RO_i`, `RW_i`, `LINK_i`, `BROKER_SOCKET`), every path
/// realpath'd and de-duplicated in order. The text depends only on the counts and flags.
pub fn render(policy: &Policy) -> Result<(String, Vec<(String, String)>), SandboxError> {
    let ro = unique(policy.ro.iter().map(|p| real(p)).collect::<Result<Vec<_>, _>>()?);
    let rw = unique(policy.rw.iter().map(|p| real(p)).collect::<Result<Vec<_>, _>>()?);
    let rd = unique(policy.rd.iter().map(|p| real(p)).collect::<Result<Vec<_>, _>>()?);
    let wo = unique(policy.wo.iter().map(|p| real(p)).collect::<Result<Vec<_>, _>>()?);
    let mut all_links = Vec::new();
    for p in policy.ro.iter().chain(policy.rw.iter()).chain(policy.rd.iter()).chain(policy.wo.iter()).chain(policy.exe.iter()) {
        all_links.extend(links_of(p)?);
    }
    let links = unique(all_links);
    let mut params = vec![("MODULE_ID".to_string(), policy.module.clone())];
    params.extend(ro.iter().enumerate().map(|(i, p)| (format!("RO_{i}"), p.clone())));
    params.extend(rw.iter().enumerate().map(|(i, p)| (format!("RW_{i}"), p.clone())));
    params.extend(rd.iter().enumerate().map(|(i, p)| (format!("RD_{i}"), p.clone())));
    params.extend(wo.iter().enumerate().map(|(i, p)| (format!("WO_{i}"), p.clone())));
    params.extend(links.iter().enumerate().map(|(i, p)| (format!("LINK_{i}"), p.clone())));
    let broker = policy.broker_socket.as_deref().filter(|b| !b.is_empty());
    if let Some(b) = broker {
        let (parent, name) = pure_parent_name(b);
        params.push(("BROKER_SOCKET".into(), format!("{}/{name}", real(&parent)?)));
    }
    let text = render_text(&policy.kind, ro.len(), rw.len(), links.len(), &policy.net, broker.is_some(), policy.gpu,
                           policy.proxy_port, policy.exec_rw, rd.len(), wo.len())?;
    Ok((text, params))
}

fn unique(v: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    v.into_iter().filter(|x| seen.insert(x.clone())).collect()
}

/// `os.path.realpath`, refusing results the profile cannot carry (relative, newline or NUL).
fn real(p: &str) -> Result<String, SandboxError> {
    let bad = || SandboxError(format!("bad sandbox path {}", crate::py::repr(p)));
    if p.contains('\0') {
        return Err(bad());
    }
    let r = realpath(p)?;
    if !r.starts_with('/') || r.contains('\n') || r.contains('\0') {
        return Err(bad());
    }
    Ok(r)
}

/// `PurePosixPath(p).parent` and `.name` (`a/b/` -> `a`, `b`; `sock` -> `.`, `sock`).
fn pure_parent_name(p: &str) -> (String, String) {
    let anchor = if p.starts_with("//") && !p.starts_with("///") {
        "//"
    } else if p.starts_with('/') {
        "/"
    } else {
        ""
    };
    let parts: Vec<&str> = p.split('/').filter(|s| !s.is_empty() && *s != ".").collect();
    match parts.split_last() {
        None => (if anchor.is_empty() { ".".into() } else { anchor.into() }, String::new()),
        Some((name, rest)) => {
            let parent = if rest.is_empty() {
                if anchor.is_empty() { ".".to_string() } else { anchor.to_string() }
            } else {
                format!("{anchor}{}", rest.join("/"))
            };
            (parent, name.to_string())
        }
    }
}

/// Every symlink met while resolving a path, hop by hop (each needs a metadata rule on itself and its ancestors). Touches the
/// filesystem (lstat, readlink); a path that does not exist simply has no more hops.
pub fn links_of(p: &str) -> Result<Vec<String>, SandboxError> {
    links_of_depth(p, 0)
}

fn links_of_depth(p: &str, depth: usize) -> Result<Vec<String>, SandboxError> {
    if depth > 32 {
        return fail(format!("symlink loop resolving {p}"));
    }
    let abs = abspath(p)?;
    let parts: Vec<&str> = abs.split('/').filter(|s| !s.is_empty()).collect();
    let mut out = Vec::new();
    let mut cur = "/".to_string();
    for (i, part) in parts.iter().enumerate() {
        let nxt = if cur == "/" { format!("/{part}") } else { format!("{cur}/{part}") };
        if is_symlink(&nxt) {
            out.push(nxt.clone());
            let target = readlink(&nxt)?;
            let target = if target.starts_with('/') { target } else { format!("{cur}/{target}") };
            let next = if i + 1 < parts.len() { format!("{target}/{}", parts[i + 1..].join("/")) } else { target };
            out.extend(links_of_depth(&next, depth + 1)?);
            return Ok(out);
        }
        cur = nxt;
    }
    Ok(out)
}

fn is_symlink(p: &str) -> bool {
    fs::symlink_metadata(p).map(|m| m.file_type().is_symlink()).unwrap_or(false)
}

fn readlink(p: &str) -> Result<String, SandboxError> {
    let t = fs::read_link(p).map_err(|e| SandboxError(format!("{p}: {e}")))?;
    t.into_os_string().into_string().map_err(|_| SandboxError(format!("{p}: link target is not UTF-8")))
}

fn cwd() -> Result<String, SandboxError> {
    std::env::current_dir()
        .map_err(|e| SandboxError(format!("no working directory: {e}")))?
        .into_os_string()
        .into_string()
        .map_err(|_| SandboxError("working directory is not UTF-8".into()))
}

/// `posixpath.join(a, b)`.
fn join(a: &str, b: &str) -> String {
    if b.starts_with('/') {
        b.to_string()
    } else if a.is_empty() || a.ends_with('/') {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

/// `posixpath.split(p)`.
fn split(p: &str) -> (String, String) {
    let i = p.rfind('/').map_or(0, |i| i + 1);
    let (head, tail) = (&p[..i], &p[i..]);
    let head = if !head.is_empty() && head.bytes().any(|c| c != b'/') { head.trim_end_matches('/') } else { head };
    (head.to_string(), tail.to_string())
}

/// `posixpath.normpath(p)` (lexical: `..` removes the previous component).
pub fn normpath(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let initial = if p.starts_with("//") && !p.starts_with("///") {
        2
    } else if p.starts_with('/') {
        1
    } else {
        0
    };
    let mut comps: Vec<&str> = Vec::new();
    for c in p.split('/') {
        if c.is_empty() || c == "." {
            continue;
        }
        if c != ".." || (initial == 0 && comps.is_empty()) || comps.last() == Some(&"..") {
            comps.push(c);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let s = format!("{}{}", "/".repeat(initial), comps.join("/"));
    if s.is_empty() { ".".into() } else { s }
}

/// `os.path.abspath(p)`.
pub fn abspath(p: &str) -> Result<String, SandboxError> {
    Ok(if p.starts_with('/') { normpath(p) } else { normpath(&join(&cwd()?, p)) })
}

/// `os.path.realpath(p)` (non-strict, Python 3.12): symlinks resolved component by component; missing components
/// are kept as written; a loop leaves the rest unresolved.
pub fn realpath(p: &str) -> Result<String, SandboxError> {
    let mut seen = HashMap::new();
    let (path, _) = join_realpath(String::new(), p, &mut seen)?;
    abspath(&path)
}

fn join_realpath(mut path: String, rest: &str, seen: &mut HashMap<String, Option<String>>) -> Result<(String, bool), SandboxError> {
    let mut rest = rest;
    if let Some(r) = rest.strip_prefix('/') {
        rest = r;
        path = "/".into();
    }
    while !rest.is_empty() {
        let (name, r) = rest.split_once('/').unwrap_or((rest, ""));
        rest = r;
        if name.is_empty() || name == "." {
            continue;
        }
        if name == ".." {
            if path.is_empty() {
                path = "..".into();
            } else {
                let (head, tail) = split(&path);
                path = if tail == ".." { join(&join(&head, ".."), "..") } else { head };
            }
            continue;
        }
        let newpath = join(&path, name);
        if !is_symlink(&newpath) {
            path = newpath;
            continue;
        }
        if let Some(cached) = seen.get(&newpath) {
            match cached {
                Some(resolved) => {
                    path = resolved.clone();
                    continue;
                }
                None => return Ok((join(&newpath, rest), false)), // a loop: the rest stays unresolved
            }
        }
        seen.insert(newpath.clone(), None);
        let target = readlink(&newpath)?;
        let (p, ok) = join_realpath(path, &target, seen)?;
        if !ok {
            return Ok((join(&p, rest), false));
        }
        path = p;
        seen.insert(newpath, Some(path.clone()));
    }
    Ok((path, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_depends_only_on_shape() {
        let t = render_text("runner", 1, 1, 0, "none", false, false, None, false, 0, 0).unwrap();
        assert!(t.starts_with("(version 1)\n;; oarbank module sandbox, profile 4 (runner)\n"));
        assert!(t.contains("(subpath (param \"RO_0\"))") && !t.contains("RO_1") && !t.contains("network-outbound"));
        let a = render_text("runner", 1, 1, 0, "egress-allowlist", false, false, Some(47001), false, 0, 0).unwrap();
        assert!(a.contains("(remote ip \"localhost:47001\")"));
        assert!(render_text("runner", 1, 1, 0, "egress-allowlist", false, false, None, false, 0, 0).is_err());
        assert!(render_text("runner", 1, 1, 0, "egress-allowlist", false, false, Some(0), false, 0, 0).is_err());
        let e = render_text("runner", 1, 1, 0, "open", false, false, None, false, 0, 0).unwrap_err();
        assert_eq!(e.0, "network mode 'open' is not enforceable by the seatbelt backend");
        let any = render_text("runner", 0, 0, 0, "egress-any", false, true, None, false, 0, 0).unwrap();
        let (harden, lo, gpu) = (any.find(";; hardening").unwrap(), any.find("(deny network-outbound (remote ip \"localhost:*\"))").unwrap(), any.find(";; grant: GPU").unwrap());
        assert!(harden < lo && lo < gpu);
    }

    #[test]
    fn python_path_helpers() {
        assert_eq!(normpath("/a/./b/../c//d/"), "/a/c/d");
        assert_eq!(normpath("//a"), "//a");
        assert_eq!(normpath("///a/.."), "/");
        assert_eq!(normpath("../x/../.."), "../..");
        assert_eq!(normpath(""), ".");
        assert_eq!(split("/a/b"), ("/a".into(), "b".into()));
        assert_eq!(split("/a"), ("/".into(), "a".into()));
        assert_eq!(split("a"), ("".into(), "a".into()));
        assert_eq!(join("a", "/b"), "/b");
        assert_eq!(join("a/", "b"), "a/b");
        assert_eq!(join("x", ""), "x/");
        assert_eq!(pure_parent_name("/run/a.sock"), ("/run".into(), "a.sock".into()));
        assert_eq!(pure_parent_name("a.sock"), (".".into(), "a.sock".into()));
        assert_eq!(pure_parent_name("/a.sock"), ("/".into(), "a.sock".into()));
        assert_eq!(pure_parent_name("/run//./x/"), ("/run".into(), "x".into()));
    }

    #[test]
    fn realpath_of_missing_paths_keeps_them() {
        assert_eq!(realpath("/nonexistent-oarbank/x/../y").unwrap(), "/nonexistent-oarbank/y");
        assert_eq!(realpath("/").unwrap(), "/");
        assert!(real("/a\nb").is_err() && real("/a\0b").is_err());
    }
}
