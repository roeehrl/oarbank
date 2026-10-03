//! Doctors (docs/protocol.md, "Doctor"): each module's `doctor --json`, run under its sandbox with the protocol's
//! environment, folded into the report the heartbeat carries.

use crate::paths::Layout;
use crate::release::Release;
use crate::runtime::Runtime;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Resolve an exec (spec/manifest.md, "Exec"): `python` → the module's interpreter, `{bundle}` → its bundle.
pub fn resolve_exec(argv: &[Value], bundle: &Path, python: &Path) -> Vec<String> {
    argv.iter().enumerate().filter_map(|(i, a)| a.as_str().map(|a| (i, a))).map(|(i, a)| {
        if i == 0 && a == "python" { python.display().to_string() } else { a.replace("{bundle}", &bundle.display().to_string()) }
    }).collect()
}

/// The per-module files the protocol passes by path: tools (resolved, as the sandbox grants them) and settings.
pub fn grant_files(dir: &Path, entry: &Value, settings: &Value) -> std::io::Result<(PathBuf, PathBuf, Vec<String>)> {
    crate::fsutil::private_dir(dir)?;
    let mut tools = serde_json::Map::new();
    let mut paths = Vec::new();
    for t in entry["sandbox"]["tools"].as_array().cloned().unwrap_or_default() {
        let id = t["id"].as_str().unwrap_or("").to_string();
        let resolved: Vec<String> = t["paths"].as_array().cloned().unwrap_or_default().iter()
            .filter_map(|p| p.as_str()).filter_map(|p| std::fs::canonicalize(p).ok()).map(|p| p.display().to_string()).collect();
        paths.extend(resolved.iter().cloned());
        tools.insert(id, json!(resolved));
    }
    let tf = dir.join("tools.json");
    let sf = dir.join("settings.json");
    std::fs::write(&tf, serde_json::to_vec(&Value::Object(tools))?)?;
    std::fs::write(&sf, serde_json::to_vec(settings)?)?;
    Ok((tf, sf, paths))
}

/// Variables the agent (or the coordinator's host) sets itself: a module's env never names one (the SDK's
/// `RESERVED_ENV_PREFIX` and `RESERVED_ENV`, pinned by a test). Compared case-insensitively, as Windows compares them.
pub const RESERVED_ENV_PREFIX: &str = "OARBANK_";
pub const RESERVED_ENV: &[&str] = &["PATH", "PATHEXT", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA",
    "LOCALAPPDATA", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS", "LANG", "LC_ALL", "PYTHONUTF8", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY"];

pub fn reserved(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    up.starts_with(RESERVED_ENV_PREFIX) || RESERVED_ENV.contains(&up.as_str())
}

/// The module entry's runner env (`[runner].env` with the platform's variant merged by the coordinator), which runners
/// and doctors get after the agent's own variables. Refused whole when it names a reserved variable.
pub fn module_env(entry: &Value) -> Result<Vec<(String, String)>, String> {
    let mut env = Vec::new();
    for (k, v) in entry["runner"]["env"].as_object().into_iter().flatten() {
        if reserved(k) {
            return Err(format!("the module's env sets {k}, which the agent sets itself"));
        }
        env.push((k.clone(), v.as_str().ok_or_else(|| format!("the module's env {k} is not a string"))?.to_string()));
    }
    Ok(env)
}

pub fn base_env(module: &str, home: &Path, tmp: &Path) -> Vec<(String, String)> {
    let mut env = crate::sys::os_env(home, tmp);
    env.extend([("LANG".into(), "C.UTF-8".into()), ("LC_ALL".into(), "C.UTF-8".into()),
                ("PYTHONUTF8".into(), "1".into()), ("OARBANK_MODULE".into(), module.into()), ("OARBANK_PROTOCOL".into(), "1".into()),
                ("OARBANK_PLATFORM".into(), crate::facts::platform_token())]);
    env
}

pub fn run_one(l: &Layout, rt: &Runtime, rel: &Release, entry: &Value, settings: &Value) -> Value {
    let name = entry["name"].as_str().unwrap_or("?");
    let started = Instant::now();
    let fail = |detail: String| json!({"health": "unhealthy", "checks": [{"name": "doctor", "ok": false, "detail": detail}]});
    let bundle = rel.bundle(entry);
    let python = rt.module_python(&rel.dir, name);
    let data = l.module_data().join(name);
    let tmp = data.join("tmp");
    if crate::fsutil::private_dir(&tmp).is_err() {
        return fail("cannot create the module's data directory".into());
    }
    let grants = l.run().join(format!("doctor-{name}"));
    let (tools_file, settings_file, tool_paths) = match grant_files(&grants, entry, settings) {
        Ok(x) => x,
        Err(e) => return fail(format!("grant files: {e}")),
    };
    let mut argv = resolve_exec(entry["runner"]["exec"].as_array().map(Vec::as_slice).unwrap_or(&[]), &bundle, &python);
    if argv.is_empty() {
        return fail("the module entry has no runner exec".into());
    }
    argv.extend(["doctor".to_string(), "--json".to_string()]);
    let mut env = base_env(name, &data, &tmp);
    env.extend([("OARBANK_MODULE_DATA".into(), data.display().to_string()),
                ("OARBANK_TOOLS_FILE".into(), tools_file.display().to_string()),
                ("OARBANK_SETTINGS_FILE".into(), settings_file.display().to_string())]);
    match module_env(entry) {
        Ok(e) => env.extend(e),
        Err(e) => return fail(e),
    }
    if crate::sandbox::available() {
        let mut pol = oarbank_core::sandbox::Policy::new(entry["module_id"].as_str().unwrap_or(name));
        pol.ro = vec![bundle.display().to_string(), python.display().to_string(), grants.display().to_string()];
        let venv = rel.dir.join("venvs").join(name);
        if venv.exists() {
            pol.ro.push(venv.display().to_string());
        }
        pol.ro.extend(rt.roots.iter().cloned());
        pol.ro.extend(tool_paths);
        pol.rw = vec![data.display().to_string()];
        pol.kind = "doctor".into();
        pol.exe = Some(python.display().to_string());
        pol.gpu = entry["sandbox"]["devices"]["gpu"].as_str().is_some_and(|g| g != "none");
        argv = match crate::sandbox::wrap(&pol, &grants.join("doctor.sb"), &argv) {
            Ok(a) => a,
            Err(e) => return fail(e),
        };
    }
    let child = Command::new(&argv[0]).args(&argv[1..]).env_clear().envs(env).current_dir(&data)
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return fail(format!("spawn: {e}")),
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() > deadline => {
                let _ = child.kill();
                return fail("doctor did not finish within 60 s".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return fail(format!("wait: {e}")),
        }
    }
    let out = child.wait_with_output().map(|o| (String::from_utf8_lossy(&o.stdout).to_string(), String::from_utf8_lossy(&o.stderr).to_string()))
        .unwrap_or_default();
    let last = out.0.lines().rev().find(|l| l.trim_start().starts_with('{')).unwrap_or("");
    let Ok(d) = serde_json::from_str::<Value>(last) else {
        return fail(format!("not a DoctorOutput: {}", out.1.chars().rev().take(300).collect::<String>().chars().rev().collect::<String>()));
    };
    let health = match d["health"].as_str() {
        Some(h @ ("healthy" | "unhealthy" | "undetected")) => h.to_string(),
        _ => return fail(format!("DoctorOutput health is {}, not healthy, unhealthy or undetected", d["health"])),
    };
    json!({"health": health, "checks": d["checks"].clone(), "capabilities": d["capabilities"].clone(),
           "attrs": d["attrs"].clone(), "seconds": started.elapsed().as_secs_f64()})
}

/// Every module's doctor for the current release.
pub fn run_all(l: &Layout, rt: &Runtime, rel: &Release, policy: &Value) -> Value {
    let mut modules = serde_json::Map::new();
    for m in &rel.modules {
        let name = m["name"].as_str().unwrap_or("?").to_string();
        let mut settings = policy["module_settings"][&name].clone();
        if settings.is_null() {
            settings = json!({});
        }
        modules.insert(name.clone(), run_one(l, rt, rel, m, &settings));
    }
    json!({"at": now(), "release_id": rel.id, "modules": modules})
}

pub fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The quoted names in one tuple assignment of the SDK's manifest.py, e.g. `RESERVED_ENV = ("PATH", ...)`.
    fn sdk_names(assignment: &str) -> Vec<String> {
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../vendor/oarbank-sdk/src/oarbank_sdk/manifest.py"))
            .expect("the SDK's manifest.py (vendor/oarbank-sdk)");
        let start = src.find(&format!("\n{assignment} = ")).unwrap_or_else(|| panic!("{assignment} in manifest.py")) + 1;
        let line_end = src[start..].find('\n').unwrap() + start;
        let end = if src[start..line_end].contains('(') { src[start..].find(')').unwrap() + start } else { line_end };
        src[start..end].split('"').skip(1).step_by(2).map(str::to_string).collect()
    }

    #[test]
    fn reserved_env_is_the_sdks() {
        assert_eq!(sdk_names("RESERVED_ENV"), RESERVED_ENV);
        assert_eq!(sdk_names("RESERVED_ENV_PREFIX"), [RESERVED_ENV_PREFIX]);
    }

    /// Everything the agent sets for a runner or doctor on this OS is reserved, so a module's env cannot shadow it.
    #[test]
    fn every_variable_the_agent_sets_is_reserved() {
        let dir = std::env::temp_dir();
        let mut names: Vec<String> = base_env("m", &dir, &dir).into_iter().map(|(k, _)| k).collect();
        names.extend(["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "OARBANK_WORKDIR"].map(String::from));
        let open: Vec<&String> = names.iter().filter(|k| !reserved(k)).collect();
        assert!(open.is_empty(), "set by the agent but not reserved: {open:?}");
    }

    #[test]
    fn a_modules_env_is_applied_unless_it_names_a_reserved_variable() {
        let entry = json!({"runner": {"env": {"OMP_NUM_THREADS": "1", "MKL_CBWR": "COMPATIBLE"}}});
        let mut env = module_env(&entry).unwrap();
        env.sort();
        assert_eq!(env, [("MKL_CBWR".to_string(), "COMPATIBLE".to_string()), ("OMP_NUM_THREADS".to_string(), "1".to_string())]);
        assert_eq!(module_env(&json!({"runner": {}})).unwrap(), []);
        for name in ["Path", "systemdrive", "OARBANK_PLATFORM", "oarbank_x", "TMPDIR"] {
            let e = module_env(&json!({"runner": {"env": {name: "x"}}})).unwrap_err();
            assert!(e.contains(name) && e.contains("sets itself"), "{e}");
        }
    }
}
