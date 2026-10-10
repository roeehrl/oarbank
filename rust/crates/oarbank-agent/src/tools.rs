//! Host tools on the node (docs/design/host-tools.md; oarbank-sdk spec/sandbox.md, "Host tools"): the node is the
//! source of truth for what is installed.
//!
//! **Definitions.** The built-in detector kinds `jdk` and `python`, each also a built-in tool of that id, come with
//! search patterns per OS (`builtin_tools.json`, pinned against the coordinator's `tools.BUILTIN` by a test). The
//! release's `tools` table adds the fleet's definitions for this OS: extra patterns for a built-in kind, and generic
//! `executable` tools with their version command and regex. A pattern is an absolute path whose components may hold
//! `*` and `?`, or `$VAR` with an optional sub-path; globs live only in patterns, never in grants.
//!
//! **Detection** runs at startup, when the release changes, when the coordinator asks (`detect_tools`), when the
//! node's statement changes and hourly. A JDK is read without running anything: its home's `release` file gives
//! `JAVA_VERSION` (a JDK 8's `1.8.0_392` is reported as `8.0.392`), `OS_ARCH` and `IMPLEMENTOR`, and `bin/java` must
//! exist. Any other tool runs its version command inside the sandbox (read and execute on that installation only, a
//! private temporary directory, no network). Candidates come from the patterns (source `detected` for built-in ones,
//! `search` for the fleet's), from the node owner's hints file `<agent home>/tool-hints.json` (`{"jdk": ["/path"]}`,
//! source `local-hint`: candidates only, verified like any other) and from the paths the node's signed statement adds
//! (source `override`), which first pass the folder rules (no roots, homes, data roots or system directories).
//!
//! **Grants.** For each module the agent resolves each approved tool request (id, version, arch) to one installation
//! with `oarbank_core::tools::resolve` (the coordinator's own rule): a pinned path from the `tool_pins` directive when it
//! names an installation found here, else the native arch first, then the highest version that satisfies the request.
//! The module's runners get exactly that installation in `OARBANK_TOOLS_FILE` and read and execute on its path (a JDK's
//! home, an executable's file, an interpreter's prefix).

use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

const BUILTIN: &str = include_str!("builtin_tools.json");
/// The node owner's extra candidates (NFD's features.d, HTCondor's JAVA): `{"<tool id>": ["/abs/path", ...]}`.
pub const HINTS_FILE: &str = "tool-hints.json";
/// The slow timer: detect again this often even when nothing asked.
pub const REDETECT_EVERY: Duration = Duration::from_secs(3600);
const MAX_PER_PATTERN: usize = 256;
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);

/// One tool as this node searches for it.
#[derive(Debug, Clone, PartialEq)]
pub struct Def {
    pub id: String,
    pub kind: String,
    /// (pattern, source): built-in patterns are `detected`, the fleet's `search`
    pub patterns: Vec<(String, &'static str)>,
    pub version_args: Vec<String>,
    pub version_regex: Option<String>,
}

/// This node's OS as the definitions key it.
pub fn os_key() -> &'static str {
    if cfg!(target_os = "macos") { "darwin" } else if cfg!(windows) { "windows" } else { "linux" }
}

/// This node's native architecture (`arm64`, `amd64`).
pub fn native_arch() -> String {
    crate::facts::platform_token().split_once('-').map(|(_, a)| a.to_string()).unwrap_or_default()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|s| s.as_str().map(str::to_string)).collect()
}

/// Set to `0` in the agent's environment, the built-in search patterns are skipped: only the fleet's search paths, the
/// hints file and the statement's added paths are candidates (a machine whose owner wants explicit paths only; tests).
pub const BUILTIN_SEARCH_ENV: &str = "OARBANK_TOOLS_BUILTIN_SEARCH";

/// The tools this node detects: the built-in ones, and the release's `tools` table (its definitions for this OS).
pub fn defs(release_tools: &Value) -> Vec<Def> {
    let builtin: Value = serde_json::from_str(BUILTIN).expect("builtin_tools.json");
    let os = os_key();
    let skip_builtin = std::env::var(BUILTIN_SEARCH_ENV).is_ok_and(|v| v == "0");
    let kind_def = |kind: &str| -> (Vec<(String, &'static str)>, Vec<String>, Option<String>) {
        let b = &builtin[kind];
        let pats = if skip_builtin { vec![] } else { strings(&b["search"][os]).into_iter().map(|p| (p, "detected")).collect() };
        (pats, strings(&b["version"]["args"]), b["version"]["regex"].as_str().map(str::to_string))
    };
    let mut out: Vec<Def> = vec![];
    let mut ids: Vec<String> = builtin.as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default();
    for id in release_tools.as_object().map(|m| m.keys().cloned().collect::<Vec<_>>()).unwrap_or_default() {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids.sort();
    for id in ids {
        let rel = &release_tools[&id];
        let kind = rel["kind"].as_str().or_else(|| builtin[&id]["kind"].as_str()).unwrap_or("executable").to_string();
        let (mut patterns, mut args, mut regex) = if builtin[&kind].is_object() { kind_def(&kind) } else { (vec![], vec![], None) };
        patterns.extend(strings(&rel["search"]).into_iter().map(|p| (p, "search")));
        if kind == "executable" {
            args = strings(&rel["version"]["args"]);
            regex = rel["version"]["regex"].as_str().map(str::to_string);
        }
        out.push(Def { id, kind, patterns, version_args: args, version_regex: regex });
    }
    out
}

// ------------------------------------------------------------------------------------------------ patterns

fn wild(name: &str, pat: &str) -> bool {
    let (n, p): (Vec<char>, Vec<char>) = if cfg!(windows) {
        (name.to_lowercase().chars().collect(), pat.to_lowercase().chars().collect())
    } else {
        (name.chars().collect(), pat.chars().collect())
    };
    let (mut i, mut j, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while i < n.len() {
        if j < p.len() && (p[j] == '?' || p[j] == n[i]) {
            i += 1;
            j += 1;
        } else if j < p.len() && p[j] == '*' {
            star = Some(j);
            mark = i;
            j += 1;
        } else if let Some(s) = star {
            j = s + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    while j < p.len() && p[j] == '*' {
        j += 1;
    }
    j == p.len()
}

/// The existing paths a search pattern names on this node, sorted (at most MAX_PER_PATTERN). `$VAR` expands from the
/// agent's environment (unset: nothing); `*` and `?` match within one component and never a leading dot.
pub fn expand(pattern: &str) -> Vec<PathBuf> {
    let mut text = pattern.trim().to_string();
    if let Some(rest) = text.strip_prefix('$') {
        let end = rest.find(['/', '\\']).unwrap_or(rest.len());
        let (name, tail) = rest.split_at(end);
        let Some(val) = std::env::var_os(name).filter(|v| !v.is_empty()) else { return vec![] };
        text = format!("{}{tail}", val.to_string_lossy());
    }
    if cfg!(windows) {
        // `/` is a separator on Windows except in a `\\?\` path (what canonicalize returns), where it would be part of a name
        text = text.replace('/', "\\");
    }
    let path = PathBuf::from(&text);
    if !path.is_absolute() {
        return vec![];
    }
    let mut cur: Vec<PathBuf> = vec![PathBuf::new()];
    for comp in path.components() {
        let c = comp.as_os_str().to_string_lossy().to_string();
        let globbed = matches!(comp, std::path::Component::Normal(_)) && (c.contains('*') || c.contains('?'));
        let mut next = vec![];
        for dir in &cur {
            if globbed {
                let Ok(rd) = std::fs::read_dir(if dir.as_os_str().is_empty() { Path::new(".") } else { dir }) else { continue };
                let mut names: Vec<String> = rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|n| (!n.starts_with('.') || c.starts_with('.')) && wild(n, &c)).collect();
                names.sort();
                next.extend(names.into_iter().map(|n| dir.join(n)));
            } else {
                next.push(dir.join(comp.as_os_str()));
            }
            if next.len() > MAX_PER_PATTERN {
                break;
            }
        }
        cur = next;
    }
    cur.retain(|p| p.exists());
    cur.truncate(MAX_PER_PATTERN);
    cur
}

// ------------------------------------------------------------------------------------------------ probes

/// What one candidate is: an installation, a tool that is broken (reported as refused), or nothing of this tool.
#[derive(Debug)]
pub enum Probe {
    Found { path: PathBuf, version: String, arch: String, vendor: String },
    Refused(String),
    NotIt,
}

fn read_release(home: &Path) -> Option<std::collections::HashMap<String, String>> {
    let text = std::fs::read_to_string(home.join("release")).ok()?;
    Some(text.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.trim().to_string(), v.trim().trim_matches('"').to_string()))
        .collect())
}

/// Java's legacy scheme read as the version it names: `1.8.0_392` is `8.0.392`.
pub fn java_version(raw: &str) -> String {
    let parts: Vec<&str> = raw.split(['.', '_']).collect();
    let legacy = parts.len() > 1 && parts[0] == "1" && parts[1].parse::<u32>().is_ok_and(|x| x <= 9);
    let joined = if legacy { parts[1..].join(".") } else { raw.to_string() };
    oarbank_core::tools::Version::parse(&joined).map(|v| v.normalized()).unwrap_or(joined)
}

/// A JDK: the candidate or a home inside it (Homebrew's libexec/openjdk.jdk/Contents/Home, a bundle's Contents/Home)
/// with a `release` file and `bin/java`. Nothing runs.
pub fn probe_jdk(dir: &Path) -> Probe {
    let java = if cfg!(windows) { "bin/java.exe" } else { "bin/java" };
    let homes = [dir.to_path_buf(), dir.join("libexec/openjdk.jdk/Contents/Home"), dir.join("Contents/Home"), dir.join("libexec")];
    let mut has_java = false;
    for h in &homes {
        if !h.join(java).is_file() {
            continue;
        }
        has_java = true;
        let Some(rel) = read_release(h) else { continue };
        let Some(v) = rel.get("JAVA_VERSION").filter(|v| !v.is_empty()) else {
            return Probe::Refused("its release file names no JAVA_VERSION".into());
        };
        let Ok(path) = std::fs::canonicalize(h) else { continue };
        return Probe::Found { path, version: java_version(v), arch: rel.get("OS_ARCH").cloned().unwrap_or_default(),
                              vendor: rel.get("IMPLEMENTOR").cloned().unwrap_or_default() };
    }
    if has_java { Probe::Refused("no release file beside bin/java (not a JDK home)".into()) } else { Probe::NotIt }
}

/// The architecture an executable was built for, from its header (ELF, Mach-O, a universal binary's native slice, PE).
pub fn binary_arch(path: &Path) -> String {
    use std::io::Read;
    let mut buf = vec![0u8; 4096];
    let n = std::fs::File::open(path).and_then(|mut f| f.read(&mut buf)).unwrap_or(0);
    let b = &buf[..n];
    let name = |m: u32| match m {
        0x0100_0007 => "x86_64",
        0x0100_000c => "aarch64",
        _ => "",
    };
    let u32le = |o: usize| b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]));
    let u32be = |o: usize| b.get(o..o + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]));
    if b.starts_with(b"\x7fELF") && b.len() > 20 {
        let m = if b[5] == 2 { u16::from_be_bytes([b[18], b[19]]) } else { u16::from_le_bytes([b[18], b[19]]) };
        return match m { 0x3e => "x86_64", 0xb7 => "aarch64", _ => "" }.into();
    }
    if u32le(0) == Some(0xfeed_facf) {
        return name(u32le(4).unwrap_or(0)).into();
    }
    if u32be(0) == Some(0xcafe_babe) {
        let count = u32be(4).unwrap_or(0).min(16) as usize;
        let archs: Vec<&str> = (0..count).filter_map(|i| u32be(8 + i * 20)).map(name).filter(|a| !a.is_empty()).collect();
        let native = if native_arch() == "arm64" { "aarch64" } else { "x86_64" };
        return archs.iter().find(|a| **a == native).or(archs.first()).map(|a| a.to_string()).unwrap_or_default();
    }
    if b.starts_with(b"MZ") {
        if let Some(off) = u32le(0x3c).map(|o| o as usize) {
            if b.get(off..off + 4) == Some(b"PE\0\0") {
                if let Some(m) = b.get(off + 4..off + 6).map(|x| u16::from_le_bytes([x[0], x[1]])) {
                    return match m { 0x8664 => "x86_64", 0xaa64 => "aarch64", _ => "" }.into();
                }
            }
        }
    }
    String::new()
}

/// What a runner of this kind is granted for an installation: a JDK's home or an executable's file as they are, an
/// interpreter's prefix (`<prefix>/bin/python3`).
pub fn grant_path(kind: &str, path: &Path) -> PathBuf {
    if kind == "python" {
        if let Some(prefix) = path.parent().and_then(Path::parent).filter(|p| p.parent().is_some()) {
            return prefix.to_path_buf();
        }
    }
    path.to_path_buf()
}

/// Runs a version command: (executable, the path the sandbox grants, args) -> its output.
pub type VersionRunner<'a> = &'a dyn Fn(&Path, &Path, &[String]) -> Result<String, String>;

/// An executable (or interpreter): its file, its header's arch, and the version its command prints.
pub fn probe_exe(cand: &Path, def: &Def, run: VersionRunner) -> Probe {
    let Ok(path) = std::fs::canonicalize(cand) else { return Probe::NotIt };
    if !path.is_file() {
        return Probe::NotIt;
    }
    let Some(rx) = def.version_regex.as_deref() else { return Probe::Refused("the definition has no version regex".into()) };
    let re = match regex::Regex::new(rx) {
        Ok(r) => r,
        Err(e) => return Probe::Refused(format!("version regex: {e}")),
    };
    let out = match run(&path, &grant_path(&def.kind, &path), &def.version_args) {
        Ok(o) => o,
        Err(e) => return Probe::Refused(format!("version command: {e}")),
    };
    let Some(caps) = re.captures(&out) else {
        return Probe::Refused(format!("the version command printed no version ({:?})", out.trim().chars().take(120).collect::<String>()));
    };
    let v = caps.get(1).or_else(|| caps.get(0)).map(|m| m.as_str().to_string()).unwrap_or_default();
    match oarbank_core::tools::Version::parse(&v) {
        Ok(ver) => Probe::Found { arch: binary_arch(&path), path, version: ver.normalized(), vendor: String::new() },
        Err(e) => Probe::Refused(e),
    }
}

/// The sandboxed version runner: the command runs confined, with read and execute on the installation's grant only,
/// a private temporary directory, no network, for at most VERSION_TIMEOUT; stdout and stderr together.
pub fn sandboxed_runner(home: &Path) -> impl Fn(&Path, &Path, &[String]) -> Result<String, String> + '_ {
    move |exe: &Path, grant: &Path, args: &[String]| {
        if !crate::sandbox::available() {
            return Err("this node cannot sandbox a version command".into());
        }
        let dir = home.join("run").join("tools-detect");
        let _ = std::fs::remove_dir_all(&dir);
        crate::fsutil::private_dir(&dir.join("tmp")).map_err(|e| e.to_string())?;
        let mut pol = oarbank_core::sandbox::Policy::new("dev.codonic.oarbank.tools");
        pol.ro = vec![grant.display().to_string()];
        if !exe.starts_with(grant) {
            pol.ro.push(exe.display().to_string());
        }
        pol.rw = vec![dir.join("tmp").display().to_string()];
        pol.kind = "probe".into();
        pol.exe = Some(exe.display().to_string());
        let mut argv = vec![exe.display().to_string()];
        argv.extend(args.iter().cloned());
        let argv = crate::sandbox::wrap(&pol, &dir.join("detect.sb"), &argv)?;
        let tmp = dir.join("tmp");
        let mut env = crate::sys::os_env(&tmp, &tmp);
        env.extend([("LANG".to_string(), "C.UTF-8".to_string()), ("LC_ALL".to_string(), "C.UTF-8".to_string())]);
        let mut child = std::process::Command::new(&argv[0]).args(&argv[1..]).env_clear().envs(env).current_dir(&tmp)
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .spawn().map_err(|e| format!("spawn: {e}"))?;
        let deadline = std::time::Instant::now() + VERSION_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() > deadline => {
                    let _ = child.kill();
                    return Err(format!("did not finish within {} s", VERSION_TIMEOUT.as_secs()));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => return Err(format!("wait: {e}")),
            }
        }
        let o = child.wait_with_output().map_err(|e| e.to_string())?;
        let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        Ok(text.chars().take(4000).collect())
    }
}

// ------------------------------------------------------------------------------------------------ refusals

/// A path the node's statement adds for a tool, before the detector sees it: absolute and existing (granted by its
/// canonical path); not a filesystem root, a home directory itself, inside or around the Oarbank data root, or a system
/// directory itself or one containing one (`/usr/lib/jvm/...` is fine; `/usr` is not).
pub fn check_override(p: &Path, data_root: &Path) -> Result<PathBuf, String> {
    if !p.is_absolute() {
        return Err("not an absolute path".into());
    }
    let c = std::fs::canonicalize(p).map_err(|_| format!("{} does not exist here", p.display()))?;
    if c.parent().is_none() {
        return Err("a filesystem root".into());
    }
    if crate::folders::homes().iter().any(|h| *h == c) {
        return Err("a home directory itself".into());
    }
    if let Some(parent) = c.parent() {
        let users = [Path::new("/Users"), Path::new("/home"), Path::new(r"C:\Users")];
        if users.iter().any(|u| std::fs::canonicalize(u).is_ok_and(|u| u == parent)) {
            return Err("a home directory itself".into());
        }
    }
    if let Ok(root) = std::fs::canonicalize(data_root) {
        if crate::folders::overlaps(&c, &root) {
            return Err("overlaps the Oarbank data directory".into());
        }
    }
    for sys in crate::folders::system_dirs() {
        if sys.starts_with(&c) {
            return Err(format!("is or contains the system directory {}", crate::folders::display(&sys)));
        }
    }
    Ok(c)
}

// ------------------------------------------------------------------------------------------------ detection

/// Detect every defined tool: `{detected_at, native_arch, tools: {id: [{path, given?, version, arch, vendor, source,
/// status, detected_at}]}}`. `hints`: the hints file's content; `added`: the statement's `tools` entries `{id, module,
/// path}`; `run`: how version commands run (sandboxed_runner in the agent).
pub fn detect(defs: &[Def], hints: &Value, added: &[Value], data_root: &Path, run: VersionRunner) -> Value {
    let now = crate::doctor::now();
    let data = std::fs::canonicalize(data_root).ok();
    let mut tools = Map::new();
    for d in defs {
        let mut cands: Vec<(PathBuf, &'static str)> = vec![];
        for a in added.iter().filter(|a| a["id"].as_str() == Some(&d.id)) {
            if let Some(p) = a["path"].as_str() {
                cands.push((PathBuf::from(p), "override"));
            }
        }
        cands.extend(strings(&hints[&d.id]).into_iter().map(|p| (PathBuf::from(p), "local-hint")));
        for (pat, src) in &d.patterns {
            cands.extend(expand(pat).into_iter().map(|p| (p, *src)));
        }
        let mut found: Vec<Value> = vec![];
        let mut seen: Vec<PathBuf> = vec![];
        for (cand, src) in cands {
            let explicit = matches!(src, "override" | "local-hint");
            let given = cand.display().to_string();
            let refused = |why: String| json!({"path": given, "given": given, "version": null, "arch": null, "vendor": null,
                                               "source": src, "status": format!("refused: {why}"), "detected_at": now});
            if src == "override" {
                if let Err(e) = check_override(&cand, data_root) {
                    found.push(refused(e));
                    continue;
                }
            } else if explicit && !cand.is_absolute() {
                found.push(refused("not an absolute path".into()));
                continue;
            }
            let probe = if d.kind == "jdk" { probe_jdk(&cand) } else { probe_exe(&cand, d, run) };
            match probe {
                Probe::Found { path, version, arch, vendor } => {
                    if data.as_ref().is_some_and(|r| crate::folders::overlaps(&path, r)) {
                        found.push(refused("overlaps the Oarbank data directory".into()));
                        continue;
                    }
                    if seen.contains(&path) {
                        continue;
                    }
                    seen.push(path.clone());
                    let p = crate::folders::display(&path);
                    let mut inst = json!({"path": p, "version": version, "arch": arch, "vendor": vendor, "source": src,
                                          "status": "ok", "detected_at": now});
                    if explicit && given != p {
                        inst["given"] = json!(given);
                    }
                    found.push(inst);
                }
                Probe::Refused(why) => found.push(refused(why)),
                Probe::NotIt if explicit => found.push(refused(format!("not a {} installation", d.id))),
                Probe::NotIt => {}
            }
        }
        tools.insert(d.id.clone(), Value::Array(found));
    }
    json!({"detected_at": now, "native_arch": native_arch(), "tools": tools})
}

/// The hints file in the agent's home (absent or unreadable: none).
pub fn hints(home: &Path) -> Value {
    std::fs::read(home.join(HINTS_FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null)
}

/// Whether two detections found the same installations (detection times aside).
pub fn same(a: &Value, b: &Value) -> bool {
    let strip = |v: &Value| {
        let mut t = v["tools"].clone();
        for list in t.as_object_mut().into_iter().flat_map(|m| m.values_mut()) {
            for i in list.as_array_mut().into_iter().flatten() {
                if let Some(o) = i.as_object_mut() {
                    o.remove("detected_at");
                }
            }
        }
        t
    };
    strip(a) == strip(b)
}

/// What one module's runners get: `{"tools": {"<tool id>": [{path, version, arch}]}, "paths": {"<tool id>": "<grant>"}}`
/// for each approved request that resolves here (`paths`: what the sandbox grants for it). `pins`: the `tool_pins`
/// directive (`{module: {tool: path}}`, `""` for every module without values of its own).
pub fn granted(report: &Value, entry: &Value, pins: &Value, defs: &[Def]) -> Value {
    let module = entry["name"].as_str().unwrap_or("");
    let mine = if pins[module].is_object() { &pins[module] } else { &pins[""] };
    let native = report["native_arch"].as_str().map(str::to_string).unwrap_or_else(native_arch);
    let (mut out, mut paths) = (Map::new(), Map::new());
    for t in entry["sandbox"]["tools"].as_array().into_iter().flatten() {
        let Some(id) = t["id"].as_str() else { continue };
        let insts = report["tools"][id].as_array().cloned().unwrap_or_default();
        let req = json!({"id": id, "version": t["version"], "arch": t["arch"].as_str().unwrap_or("any")});
        let res = oarbank_core::tools::resolve(&insts, &req, &native, mine[id].as_str());
        if res["status"] != "ok" {
            continue;
        }
        let i = &res["installation"];
        let path = i["path"].as_str().unwrap_or("").to_string();
        let kind = defs.iter().find(|d| d.id == id).map(|d| d.kind.as_str()).unwrap_or("executable");
        paths.insert(id.to_string(), json!(crate::folders::display(&grant_path(kind, Path::new(&path)))));
        out.insert(id.to_string(), json!([{"path": path, "version": i["version"], "arch": i["arch"]}]));
    }
    json!({"tools": out, "paths": paths})
}

/// Every module of a release: `{module: granted(...)}` (the agent hands it to doctors, services and runners).
pub fn grants(report: &Value, modules: &[Value], pins: &Value, defs: &[Def]) -> Value {
    Value::Object(modules.iter().filter_map(|e| Some((e["name"].as_str()?.to_string(), granted(report, e, pins, defs)))).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> (tempfile::TempDir, PathBuf) {
        let d = crate::scratch(&format!("tools-{name}"));
        let p = std::fs::canonicalize(d.path()).unwrap();
        (d, p)
    }

    /// A fake JDK home: `release` and `bin/java` (never run).
    pub fn fake_jdk(dir: &Path, version: &str, arch: &str) {
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(dir.join("bin").join(if cfg!(windows) { "java.exe" } else { "java" }), b"#!/bin/sh\nexit 1\n").unwrap();
        std::fs::write(dir.join("release"), format!("JAVA_VERSION=\"{version}\"\nOS_ARCH=\"{arch}\"\nIMPLEMENTOR=\"Test\"\n")).unwrap();
    }

    fn no_run(_: &Path, _: &Path, _: &[String]) -> Result<String, String> {
        Err("not run in this test".into())
    }

    #[test]
    fn the_builtin_table_is_the_coordinators() {
        let py = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/oarbank/coordinator/tools.py")).unwrap();
        let b: Value = serde_json::from_str(BUILTIN).unwrap();
        for (kind, d) in b.as_object().unwrap() {
            assert!(py.contains(&format!("\"{kind}\": {{\"kind\": \"{kind}\"")), "{kind} in tools.BUILTIN");
            for (_, pats) in d["search"].as_object().unwrap() {
                for p in pats.as_array().unwrap() {
                    let lit = serde_json::to_string(p).unwrap();
                    assert!(py.contains(&lit), "{lit} in tools.BUILTIN");
                }
            }
        }
    }

    #[test]
    fn patterns_match_components_never_hidden_names_and_expand_variables() {
        assert!(wild("openjdk@17", "openjdk@*") && wild("python3.12", "python3.??") && !wild("python3.12-config", "python3.??"));
        assert!(wild("x", "*") && !wild("", "?") && wild("abc", "a*c") && !wild("abd", "a*c"));
        let (_t, t) = scratch("glob");
        for d in ["opt/openjdk@17", "opt/openjdk@21", "opt/.openjdk@hidden", "opt/other"] {
            std::fs::create_dir_all(t.join(d)).unwrap();
        }
        let got = expand(&format!("{}/opt/openjdk@*", t.display()));
        assert_eq!(got, [t.join("opt/openjdk@17"), t.join("opt/openjdk@21")]);
        assert!(expand("relative/*").is_empty() && expand("$OARBANK_TOOLS_TEST_UNSET/x").is_empty());
        std::env::set_var("OARBANK_TOOLS_TEST_HOME", t.join("opt"));
        assert_eq!(expand("$OARBANK_TOOLS_TEST_HOME/other"), [t.join("opt/other")]);
    }

    #[test]
    fn a_jdk_is_read_from_its_release_file_without_running_it() {
        let (_t, t) = scratch("jdk");
        fake_jdk(&t.join("jdk-17/libexec/openjdk.jdk/Contents/Home"), "17.0.12", "aarch64");    // Homebrew's layout
        fake_jdk(&t.join("zulu-8"), "1.8.0_392", "x86_64");
        std::fs::create_dir_all(t.join("broken/bin")).unwrap();
        std::fs::write(t.join("broken/bin").join(if cfg!(windows) { "java.exe" } else { "java" }), b"").unwrap();
        std::fs::create_dir_all(t.join("empty")).unwrap();
        match probe_jdk(&t.join("jdk-17")) {
            Probe::Found { path, version, arch, vendor } => {
                assert_eq!((version.as_str(), arch.as_str(), vendor.as_str()), ("17.0.12", "aarch64", "Test"));
                assert_eq!(path, t.join("jdk-17/libexec/openjdk.jdk/Contents/Home"));
            }
            p => panic!("{p:?}"),
        }
        assert!(matches!(probe_jdk(&t.join("zulu-8")), Probe::Found { version, .. } if version == "8.0.392"));
        assert!(matches!(probe_jdk(&t.join("broken")), Probe::Refused(w) if w.contains("no release file")));
        assert!(matches!(probe_jdk(&t.join("empty")), Probe::NotIt));
        assert_eq!(java_version("21.0.4"), "21.0.4");
        assert_eq!(java_version("1.10.2"), "1.10.2");
    }

    #[test]
    fn detection_reports_found_refused_and_added_paths_and_dedupes_by_canonical_path() {
        let (_t, t) = scratch("detect");
        let data = t.join("Oarbank/agent");
        std::fs::create_dir_all(&data).unwrap();
        fake_jdk(&t.join("jvm/jdk-11"), "11.0.2", "aarch64");
        fake_jdk(&t.join("jvm/jdk-21"), "21.0.4", "aarch64");
        fake_jdk(&t.join("extra/jdk-17"), "17.0.12", "aarch64");
        fake_jdk(&data.join("jdk-inside"), "17.0.1", "aarch64");
        #[cfg(unix)]
        std::os::unix::fs::symlink(t.join("jvm/jdk-21"), t.join("jvm/default")).unwrap();
        let d = Def { id: "jdk".into(), kind: "jdk".into(), patterns: vec![(format!("{}/jvm/*", t.display()), "search")],
                      version_args: vec![], version_regex: None };
        let hints = json!({"jdk": [t.join("extra/jdk-17").display().to_string(), "relative/jdk"]});
        let added = [json!({"id": "jdk", "module": "", "path": data.join("jdk-inside").display().to_string()}),
                     json!({"id": "jdk", "module": "", "path": "/"})];
        let rep = detect(&[d], &hints, &added, &t.join("Oarbank"), &no_run);
        let insts = rep["tools"]["jdk"].as_array().unwrap();
        let mut ok: Vec<(&str, &str)> = insts.iter().filter(|i| i["status"] == "ok").map(|i| (i["version"].as_str().unwrap(), i["source"].as_str().unwrap())).collect();
        ok.sort();
        assert_eq!(ok, [("11.0.2", "search"), ("17.0.12", "local-hint"), ("21.0.4", "search")]);   // `default` is jdk-21 again
        let refused: Vec<&str> = insts.iter().filter(|i| i["status"] != "ok").map(|i| i["status"].as_str().unwrap()).collect();
        assert!(refused.iter().any(|s| s.contains("Oarbank data directory")), "{refused:?}");
        assert!(refused.iter().any(|s| s.contains("root") || s.contains("system directory")), "{refused:?}");
        assert!(refused.iter().any(|s| s.contains("absolute")), "{refused:?}");
        assert_eq!(rep["native_arch"], native_arch());
        assert!(same(&rep, &detect(&[Def { id: "jdk".into(), kind: "jdk".into(),
            patterns: vec![(format!("{}/jvm/*", t.display()), "search")], version_args: vec![], version_regex: None }],
            &hints, &added, &t.join("Oarbank"), &no_run)));
    }

    #[test]
    fn an_executable_is_versioned_by_its_command_and_its_header_names_its_arch() {
        let (_t, t) = scratch("exe");
        let exe = t.join("samtools");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        let d = Def { id: "samtools".into(), kind: "executable".into(), patterns: vec![], version_args: vec!["--version".into()],
                      version_regex: Some(r"samtools (\d+(?:\.\d+)*)".into()) };
        let fake = |e: &Path, g: &Path, a: &[String]| -> Result<String, String> {
            assert_eq!((e, a), (g, &["--version".to_string()][..]));
            Ok("samtools 1.19.2\nUsing htslib 1.19\n".into())
        };
        assert!(matches!(probe_exe(&exe, &d, &fake), Probe::Found { version, .. } if version == "1.19.2"));
        let silent = |_: &Path, _: &Path, _: &[String]| -> Result<String, String> { Ok("usage: samtools".into()) };
        assert!(matches!(probe_exe(&exe, &d, &silent), Probe::Refused(w) if w.contains("no version")));
        assert!(matches!(probe_exe(&t.join("nope"), &d, &fake), Probe::NotIt));
        let me = std::env::current_exe().unwrap();
        let want = if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" };
        assert_eq!(binary_arch(&me), want);
        assert_eq!(grant_path("python", Path::new("/opt/py/3.12/bin/python3")), Path::new("/opt/py/3.12"));
        assert_eq!(grant_path("jdk", Path::new("/opt/jdk")), Path::new("/opt/jdk"));
    }

    #[test]
    fn a_module_gets_the_installation_its_request_resolves_to_and_a_pin_only_among_what_was_found() {
        let rep = json!({"native_arch": "arm64", "tools": {"jdk": [
            {"path": "/j/11", "version": "11.0.2", "arch": "aarch64", "status": "ok", "source": "detected"},
            {"path": "/j/17", "version": "17.0.12", "arch": "aarch64", "status": "ok", "source": "detected"},
            {"path": "/j/21x", "version": "21.0.4", "arch": "x86_64", "status": "ok", "source": "detected"},
            {"path": "/j/22", "version": "22.0.1", "arch": "aarch64", "status": "ok", "source": "detected"}]}});
        let entry = json!({"name": "gatk", "sandbox": {"tools": [{"id": "jdk", "version": ">=17, <22", "arch": "any"}]}});
        let defs = defs(&Value::Null);
        let g = granted(&rep, &entry, &json!({}), &defs);
        assert_eq!(g["tools"], json!({"jdk": [{"path": "/j/17", "version": "17.0.12", "arch": "aarch64"}]}));   // native before newer
        assert_eq!(g["paths"], json!({"jdk": "/j/17"}));
        let g = granted(&rep, &entry, &json!({"": {"jdk": "/j/21x"}}), &defs);
        assert_eq!(g["tools"]["jdk"][0]["path"], "/j/21x");
        let g = granted(&rep, &entry, &json!({"": {"jdk": "/j/21x"}, "gatk": {"jdk": "/elsewhere"}}), &defs);
        assert_eq!(g["tools"], json!({}));                      // a pin that names nothing found here grants nothing
        let boot = json!({"name": "gatk", "sandbox": {"tools": []}});
        assert_eq!(granted(&rep, &boot, &json!({}), &defs)["tools"], json!({}));
    }
}
