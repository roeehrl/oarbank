//! Module cleanup (docs/protocol.md, "Module cleanup"): when a module leaves this node, everything it put here goes. A
//! module's processes write only to its data directory, their work directories, the dataset cache (cache.rs) and the
//! container runtime, so the agent deletes all of it without the module's help:
//!
//! - turned off here (`modules_disabled`): after `module_retention_days` (0: at once); turning it back on in that time
//!   keeps everything;
//! - no longer in the node's release, or the node was retired: after at most a day (sooner when the retention is
//!   shorter);
//! - purged by the owner (`module_purge`, never while it is enabled here): at once.
//!
//! Before it deletes, the agent runs the module's cleanup stage, if it declares one (the SDK's spec/manifest.md,
//! "Cleanup stage"): best effort, within the stage's timeout (at most STAGE_LIMIT), from the release that still holds
//! the module's bundle (release.rs keeps it until then). What it deleted, and how the stage went, goes to the
//! coordinator in the heartbeat's `module_cleanup` until it is acknowledged. The state is `state/module-cleanup.json`.

use crate::paths::Layout;
use crate::release::Release;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// A module no longer in the node's release goes after at most this long.
pub const GONE_GRACE_S: f64 = 86400.0;
/// The longest a cleanup stage runs.
pub const STAGE_LIMIT: Duration = Duration::from_secs(600);
/// How often the agent looks for what is due, measures what modules keep and collects the cache.
pub const SWEEP_EVERY: Duration = Duration::from_secs(300);
/// The default `module_retention_days` (the settings registry's), until the coordinator sends one.
pub const RETENTION_DAYS: f64 = oarbank_protection::settings_table::MODULE_RETENTION_DAYS;
/// An image removal the runtime keeps refusing is given up after this many tries.
const IMAGE_TRIES: u32 = 5;
/// The deletions reported at most, oldest dropped.
const DONE_MAX: usize = 50;

/// A module waiting for its deletion here.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct Pending {
    /// Since when it is turned off on this node (still in its release).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_since: Option<f64>,
    /// Since when it is no longer in the node's release (or the node was retired).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_since: Option<f64>,
    /// The owner purged it: it goes at once.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub purge: bool,
    /// The release that holds its bundle, kept until it is deleted (its cleanup stage runs from it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
}

/// A container image a module's jobs pulled or ran.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Image {
    pub image: String,
    #[serde(default)]
    pub platform: String,
    /// It is on the GPU runtime (macOS: the krunkit VM).
    #[serde(default)]
    pub gpu: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Removal attempts the runtime refused (a removal waiting for the runtime).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub tries: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct State {
    /// The coordinator answered that this node was retired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<f64>,
    /// The `module_retention_days` the coordinator last sent (a retired node keeps it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<f64>,
    #[serde(default)]
    pub pending: BTreeMap<String, Pending>,
    /// The images each module's jobs pulled or ran.
    #[serde(default)]
    pub images: BTreeMap<String, Vec<Image>>,
    /// Images of deleted modules still to remove (their runtime was not running, or refused).
    #[serde(default)]
    pub unremoved: Vec<Image>,
    /// Deletions the coordinator has not acknowledged yet (`module_cleanup` in heartbeats).
    #[serde(default)]
    pub done: Vec<Value>,
}

fn state_path(l: &Layout) -> PathBuf {
    l.state().join("module-cleanup.json")
}

fn lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

pub fn load(l: &Layout) -> State {
    std::fs::read(state_path(l)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save(l: &Layout, st: &State) {
    if let Err(e) = serde_json::to_vec(st).map_err(std::io::Error::other).and_then(|b| crate::fsutil::write_private(&state_path(l), &b)) {
        warn!(error = %e, "cannot keep the module cleanup state");
    }
}

/// Load, change and save the state, one writer at a time.
pub fn update<T>(l: &Layout, f: impl FnOnce(&mut State) -> T) -> T {
    let _one = lock();
    let mut st = load(l);
    let out = f(&mut st);
    save(l, &st);
    out
}

/// The releases pending deletions still need (release.rs never prunes them).
pub fn kept_releases(l: &Layout) -> BTreeSet<String> {
    load(l).pending.values().filter_map(|p| p.release.clone()).collect()
}

/// A module's jobs pulled or ran `image` on this node (the GPU runtime's when `gpu`).
pub fn record_image(l: &Layout, module: &str, image: &str, platform: &str, gpu: bool, bytes: impl FnOnce() -> Option<u64>) {
    if load(l).images.get(module).is_some_and(|v| v.iter().any(|i| i.image == image && i.gpu == gpu)) {
        return;
    }
    let bytes = bytes();
    update(l, |st| {
        let v = st.images.entry(module.to_string()).or_default();
        if !v.iter().any(|i| i.image == image && i.gpu == gpu) {
            v.push(Image { image: image.to_string(), platform: platform.to_string(), gpu, bytes, tries: 0 });
        }
    });
}

/// The coordinator acknowledged these deletions.
pub fn ack(l: &Layout, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    update(l, |st| st.done.retain(|d| !d["id"].as_str().is_some_and(|i| ids.iter().any(|x| x == i))));
}

/// When a pending module is deleted (Unix seconds): a purge at once; turned off, after the retention; no longer in the
/// release, after the retention or GONE_GRACE_S, the shorter.
pub fn delete_at(p: &Pending, retention_days: f64) -> f64 {
    if p.purge {
        return 0.0;
    }
    let keep = retention_days.max(0.0) * 86400.0;
    let mut t = f64::INFINITY;
    if let Some(s) = p.disabled_since {
        t = t.min(s + keep);
    }
    if let Some(s) = p.removed_since {
        t = t.min(s + keep.min(GONE_GRACE_S));
    }
    t
}

/// Why a pending module goes: `purge`, `retired`, `removed` or `disabled` (the cleanup stage's `reason`).
pub fn reason(p: &Pending, retired: bool) -> &'static str {
    if p.purge {
        "purge"
    } else if retired {
        "retired"
    } else if p.removed_since.is_some() {
        "removed"
    } else {
        "disabled"
    }
}

/// What the node knows of its modules now.
pub struct Inputs<'a> {
    /// The modules in the node's release, and its id.
    pub release: &'a BTreeSet<String>,
    pub release_id: Option<&'a str>,
    /// The modules turned off on this node.
    pub disabled: &'a BTreeSet<String>,
    /// The modules the owner purged on this node.
    pub purge: &'a BTreeSet<String>,
    /// The modules that left something here.
    pub present: &'a BTreeSet<String>,
}

/// Bring the pending deletions up to date: a module turned off or gone (with something left here) waits for its
/// deletion from when that was first seen; one back in the release and on goes off the list (the cancelled ones are
/// returned). A purge request for a module enabled here is ignored.
pub fn plan(st: &mut State, i: &Inputs, now: f64) -> Vec<String> {
    let retired = st.retired_at.is_some();
    let mut cancelled = vec![];
    let names: BTreeSet<String> = i.present.iter().chain(st.pending.keys()).cloned().collect();
    for m in names {
        let in_release = !retired && i.release.contains(&m);
        if in_release && !i.disabled.contains(&m) {
            if st.pending.remove(&m).is_some() {
                cancelled.push(m);
            }
            continue;
        }
        let p = st.pending.entry(m.clone()).or_default();
        if in_release {
            p.disabled_since.get_or_insert(now);
            p.removed_since = None;
            p.release = i.release_id.map(str::to_string);
        } else {
            p.removed_since.get_or_insert(now);
        }
        p.purge |= i.purge.contains(&m);
    }
    cancelled
}

/// The pending modules whose deletion is due, with why.
pub fn due(st: &State, now: f64) -> Vec<(String, &'static str)> {
    let days = st.retention_days.unwrap_or(RETENTION_DAYS);
    st.pending.iter().filter(|(_, p)| delete_at(p, days) <= now)
        .map(|(m, p)| (m.clone(), reason(p, st.retired_at.is_some()))).collect()
}

/// The modules that left something here: a data directory, cached datasets or images.
pub fn present(l: &Layout) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = std::fs::read_dir(l.module_data()).into_iter().flatten().flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).map(|e| e.file_name().to_string_lossy().to_string()).collect();
    out.extend(crate::cache::modules(l));
    out.extend(load(l).images.into_iter().filter(|(_, v)| !v.is_empty()).map(|(m, _)| m));
    out
}

/// The bytes of everything under `p` (links not followed).
pub fn dir_bytes(p: &Path) -> u64 {
    let mut n = 0;
    for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
        match e.file_type() {
            Ok(t) if t.is_dir() => n += dir_bytes(&e.path()),
            Ok(_) => n += e.metadata().map(|m| m.len()).unwrap_or(0),
            Err(_) => {}
        }
    }
    n
}

/// The module's cleanup stage in its release entry, when it runs on this platform.
pub fn stage_of(entry: &Value) -> Option<Value> {
    let st = entry["stages"].as_array()?.iter().find(|s| s["cleanup"].as_bool() == Some(true))?.clone();
    let here = crate::facts::platform_token();
    let plats: Vec<&str> = st["platforms"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    (plats.is_empty() || plats.iter().any(|p| *p == here || here.starts_with(&format!("{p}-")))).then_some(st)
}

/// Delete what the module keeps on the node outside the cache and the container runtime: its data directory, and the
/// grants and private directories the agent made for its processes (settings files may hold credentials). Returns the
/// bytes freed and what could not be deleted.
pub fn delete_files(l: &Layout, module: &str) -> (u64, Option<String>) {
    let data = l.module_data().join(module);
    let bytes = dir_bytes(&data);
    let mut err = None;
    if data.exists() {
        if let Err(e) = std::fs::remove_dir_all(&data) {
            err = Some(format!("{}: {e}", data.display()));
        }
    }
    for d in [l.run().join("services").join(module), l.run().join(format!("doctor-{module}")),
              l.run().join("workloads").join(module), l.work().join(format!("cleanup-{module}"))] {
        let _ = std::fs::remove_dir_all(d);
    }
    (bytes - if err.is_some() { dir_bytes(&data) } else { 0 }, err)
}

/// Forget the module's images and return those to remove: the ones no other module that is still here uses.
pub fn take_images(st: &mut State, module: &str) -> Vec<Image> {
    let mine = st.images.remove(module).unwrap_or_default();
    let others: BTreeSet<(String, bool)> = st.images.values().flatten()
        .map(|i| (crate::container_runtime::image_key(&i.image).0, i.gpu)).collect();
    mine.into_iter().filter(|i| !others.contains(&(crate::container_runtime::image_key(&i.image).0, i.gpu))).collect()
}

/// Remove images through the node's runtimes (blocking). Those whose runtime is not running stay for the next try; one
/// the runtime keeps refusing is given up after IMAGE_TRIES. Returns how many went and what is left.
pub fn remove_images(rts: Option<&crate::container_runtime::Containers>, images: Vec<Image>) -> (usize, Vec<Image>) {
    let (mut gone, mut left) = (0, vec![]);
    for mut i in images {
        let rt = rts.map(|r| r.for_job(i.gpu));
        let running = rt.as_ref().is_some_and(|r| r.status().is_ok_and(|s| s.running));
        match rt.filter(|_| running).map(|r| r.remove_image(&i.image)) {
            Some(Ok(())) => {
                info!(image = %i.image, "removed a container image of a deleted module");
                gone += 1;
            }
            Some(Err(e)) => {
                i.tries += 1;
                if i.tries >= IMAGE_TRIES {
                    warn!(image = %i.image, error = %e, "a deleted module's container image could not be removed; given up");
                } else {
                    left.push(i);
                }
            }
            None => left.push(i),
        }
    }
    (gone, left)
}

/// An `image rm`'s outcome (the runtimes' `remove_image`): an image that is not there (any more) counts as removed.
pub fn removed(r: Result<crate::container_runtime::Exec, String>) -> Result<(), String> {
    let r = r?;
    let err = r.stderr_tail(500);
    let low = err.to_ascii_lowercase();
    if r.ok() || ["no such image", "image not known", "not found"].iter().any(|x| low.contains(x)) { Ok(()) } else { Err(err) }
}

/// The size an `image inspect --format {{.Size}}` printed (the runtimes' `image_size`).
#[cfg_attr(windows, allow(dead_code))]
pub fn inspected_size(r: Result<crate::container_runtime::Exec, String>) -> Option<u64> {
    r.ok().filter(|r| r.ok()).and_then(|r| String::from_utf8_lossy(&r.stdout).trim().parse().ok())
}

/// `oarbank-agent remove-images` (an uninstall with `--purge`, a node leaving its fleet): remove every container image the
/// node's modules pulled, through the runtimes that run now (a Linux host's engine keeps its images outside the agent's
/// home). Windows deletes its containers session whole (`containers remove`). Returns what to print.
pub fn remove_all_images(l: &Layout) -> Vec<String> {
    let st = load(l);
    let images: Vec<Image> = st.images.into_values().flatten().chain(st.unremoved).collect();
    if images.is_empty() || cfg!(windows) {
        return vec![];
    }
    let n = images.len();
    let (gone, left) = remove_images(crate::container_runtime::for_node(l).as_ref(), images);
    update(l, |st| {
        st.images.clear();
        st.unremoved = left.clone();
    });
    let mut out = vec![format!("removed {gone} of {n} container images the node's modules pulled")];
    out.extend(left.iter().map(|i| format!("left {} (its container runtime is not running)", i.image)));
    out
}

/// A deletion's record for the coordinator (`module_cleanup` in heartbeats).
#[allow(clippy::too_many_arguments)]
pub fn done_record(module: &str, why: &str, at: f64, freed: u64, images: usize, stage: Option<Value>, error: Option<String>) -> Value {
    json!({"id": format!("{module}@{}", (at * 1000.0) as u64), "module": module, "reason": why, "at": at,
           "freed_bytes": freed, "images_removed": images, "cleanup": stage, "error": error})
}

/// Note a deletion (the oldest unacknowledged ones go past DONE_MAX).
pub fn note_done(st: &mut State, rec: Value) {
    st.done.push(rec);
    let over = st.done.len().saturating_sub(DONE_MAX);
    st.done.drain(..over);
}

/// What the agent hands a cleanup run.
pub struct StageRun<'a> {
    pub layout: &'a Layout,
    pub runtime: &'a crate::runtime::Runtime,
    pub release: &'a Release,
    pub entry: &'a Value,
    pub stage: &'a Value,
    pub reason: &'a str,
    /// The module's node settings, as the agent last had them.
    pub settings: &'a Value,
}

/// Run the module's cleanup stage (runner protocol, "Cleanup runs") and say how it went: `{stage, ok, detail, seconds}`.
/// Best effort: a run that cannot start, fails, crashes or outlasts its time is a failed one, never an error.
pub async fn run_stage(r: &StageRun<'_>) -> Value {
    let started = Instant::now();
    let name = r.stage["name"].as_str().unwrap_or("cleanup").to_string();
    let (ok, detail) = match run(r).await {
        Ok(out) => out,
        Err(e) => (false, format!("{e:#}")),
    };
    let module = r.entry["name"].as_str().unwrap_or("");
    if ok {
        info!(module, stage = %name, "the module's cleanup stage ran");
    } else {
        warn!(module, stage = %name, detail = %detail, "the module's cleanup stage failed; its data is deleted anyway");
    }
    json!({"stage": name, "ok": ok, "detail": detail, "seconds": (started.elapsed().as_secs_f64() * 10.0).round() / 10.0})
}

async fn run(r: &StageRun<'_>) -> anyhow::Result<(bool, String)> {
    use crate::doctor::{base_env, grant_files, module_env, resolve_exec};
    use anyhow::{bail, Context};
    let module = r.entry["name"].as_str().context("the module entry has no name")?.to_string();
    let ws = r.layout.work().join(format!("cleanup-{module}"));
    let _ = std::fs::remove_dir_all(&ws);
    crate::fsutil::private_dir(&ws.join("tmp"))?;
    let _ws_goes = crate::fsutil::RemovedOnDrop(ws.clone());
    let data = r.layout.module_data().join(&module);
    crate::fsutil::private_dir(&data.join("tmp"))?;
    let platform = crate::facts::platform_token();
    let timeout = r.stage["timeout_s"].as_f64().map(Duration::from_secs_f64).unwrap_or(STAGE_LIMIT).min(STAGE_LIMIT);
    let short = r.entry["module_id"].as_str().unwrap_or(&module).rsplit('.').next().unwrap_or(&module).to_string();
    let spec = json!({"envelope": 1, "schema": format!("{short}/spec@1"), "module_id": r.entry["module_id"],
                      "module_version": r.entry["version"], "job_key": "", "stage": r.stage["name"], "protocol": 1,
                      "datasets": [], "mounts": {}, "inputs": {}, "platform": platform,
                      "resources": {"cpu": r.stage["cpu"].as_f64().unwrap_or(1.0), "mem_gb": r.stage["mem_gb"].as_f64().unwrap_or(1.0)},
                      "timeout_s": timeout.as_secs_f64(), "payload": {"reason": r.reason}});
    std::fs::write(ws.join("spec.json"), serde_json::to_vec(&spec)?)?;
    let mut control = crate::jobs::ControlFile::create(&ws)?;
    // the cleanup grants (spec/sandbox.md, "Cleanup runs"): no tools, folders, GPU or containers
    let mut entry = r.entry.clone();
    entry["sandbox"]["tools"] = json!([]);
    let grants = ws.join(".grants");
    let (tools_file, settings_file, _) = grant_files(&grants, &entry, r.settings, &json!({}))?;
    let folders_file = grants.join("folders.json");
    std::fs::write(&folders_file, b"{}")?;
    let bundle = r.release.bundle(&entry);
    let python = r.runtime.module_python(&r.release.dir, &module);
    let mut argv = resolve_exec(entry["runner"]["exec"].as_array().map(Vec::as_slice).unwrap_or(&[]), &bundle, &python);
    if argv.is_empty() {
        bail!("the module entry has no runner exec");
    }
    argv.extend(["run".to_string(), "--spec".to_string(), ws.join("spec.json").display().to_string(), "--workdir".to_string(),
                 ws.display().to_string(), "--out".to_string(), ws.join("result.json").display().to_string()]);
    let net = entry["sandbox"]["net"]["mode"].as_str().unwrap_or("none").to_string();
    let proxy = if net == "egress-allowlist" {
        let allow = entry["sandbox"]["net"]["allow"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_string)).collect();
        Some(crate::proxy::start(allow).await?)
    } else {
        None
    };
    let mut env = base_env(&module, &ws, &ws.join("tmp"));
    env.extend([("OARBANK_WORKDIR".into(), ws.display().to_string()), ("OARBANK_TMP".into(), ws.join("tmp").display().to_string()),
                ("OARBANK_ATTEMPT_ID".into(), "0".into()), ("OARBANK_TOOLS_FILE".into(), tools_file.display().to_string()),
                ("OARBANK_SETTINGS_FILE".into(), settings_file.display().to_string()),
                ("OARBANK_FOLDERS_FILE".into(), folders_file.display().to_string()),
                ("OARBANK_MODULE_DATA".into(), data.display().to_string())]);
    if let Some(p) = &proxy {
        let url = format!("http://127.0.0.1:{}", p.port);
        for k in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy"] {
            env.push((k.into(), url.clone()));
        }
    }
    env.extend(module_env(&entry).map_err(|e| anyhow::anyhow!(e))?);
    if crate::sandbox::available() {
        let mut pol = oarbank_core::sandbox::Policy::new(entry["module_id"].as_str().unwrap_or(&module));
        pol.ro = vec![bundle.display().to_string(), python.display().to_string()];
        let venv = r.release.dir.join("venvs").join(&module);
        if venv.exists() {
            pol.ro.push(venv.display().to_string());
        }
        pol.ro.extend(r.runtime.roots.iter().cloned());
        pol.rw = vec![ws.display().to_string(), data.display().to_string()];
        pol.net = net;
        pol.proxy_port = proxy.as_ref().map(|p| p.port);
        pol.exec_rw = entry["sandbox"]["exec_writable"].as_bool() == Some(true);
        pol.kind = "runner".into();
        pol.exe = Some(python.display().to_string());
        argv = crate::sandbox::wrap(&pol, &grants.join("runner.sb"), &argv).map_err(|e| anyhow::anyhow!(e))?;
    }
    let log = std::fs::File::create(ws.join(".runner.log"))?;
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]).env_clear().envs(env).current_dir(&ws).stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?).stderr(log).kill_on_drop(true);
    control.prepare(cmd.as_std_mut());
    let signal = crate::sandbox::available().then(crate::sandbox::ConfinedSignal::new).transpose()
        .context("the sandbox launcher's confinement signal")?;
    if let Some(s) = &signal {
        s.prepare(cmd.as_std_mut());
    }
    let mut child = crate::sys::spawn_contained_async(&mut cmd, false).context("starting the runner")?;
    let pid = child.id().unwrap_or(0) as i32;
    control.started(pid);
    #[cfg(unix)]
    let record = crate::runners::Record::create(r.layout, 0, pid);
    // never module code outside its sandbox: a runner that does not come up confined is killed
    let sandboxed = signal.is_some();
    let mut refused = None;
    if let Some(s) = signal {
        use crate::sandbox::Came;
        let came = tokio::task::spawn_blocking(move || s.wait(pid as u32, crate::sandbox::CONFINE_GUARD)).await.unwrap_or(Came::Hung);
        if came == Came::Hung || (came == Came::Confined && !crate::sandbox::holds(pid) && !matches!(child.try_wait(), Ok(Some(_)))) {
            refused = Some("the runner did not come up sandboxed");
        }
    }
    let until = Instant::now() + timeout;
    let status = loop {
        if refused.is_some() {
            break None;
        }
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if sandboxed && crate::sandbox::escape(pid).is_some() {
            refused = Some("a process of the run left the module sandbox");
            break None;
        }
        if Instant::now() >= until {
            break None;
        }
        tokio::select! {
            _ = child.wait() => {}
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    };
    crate::procs::signal_group(pid, crate::procs::Sig::Kill);                // nothing outlives the run
    let _ = child.wait().await;
    #[cfg(unix)]
    if let Some(rec) = record {
        rec.remove();
    }
    crate::sys::release(pid);
    drop(proxy);
    let tail = std::fs::read(ws.join(".runner.log")).map(|b| String::from_utf8_lossy(&b[b.len().saturating_sub(1000)..]).trim().to_string())
        .unwrap_or_default();
    Ok(match (status, refused) {
        (_, Some(why)) => (false, why.to_string()),
        (None, None) => (false, format!("it did not finish within {} s", timeout.as_secs())),
        (Some(st), None) if st.success() => (true, String::new()),
        (Some(st), None) => {
            let f: Option<Value> = std::fs::read(ws.join("failure.json")).ok().and_then(|b| serde_json::from_slice(&b).ok());
            (false, match f {
                Some(f) => format!("{}: {}", f["reason"].as_str().unwrap_or("?"), f["detail"].as_str().unwrap_or("")),
                None => format!("exit {}{}", st.code().map(|c| c.to_string()).unwrap_or_else(|| "by signal".into()),
                                if tail.is_empty() { String::new() } else { format!(": {tail}") }),
            })
        }
    })
}

/// The heartbeat's `module_storage`: per module what it keeps here and, for one leaving, when it goes; and the cache.
pub fn report(st: &State, present: &BTreeSet<String>, release: &BTreeSet<String>, data: &BTreeMap<String, u64>,
              cache: &crate::cache::Collected, now: f64) -> Value {
    let days = st.retention_days.unwrap_or(RETENTION_DAYS);
    let names: BTreeSet<&String> = present.iter().chain(st.pending.keys()).collect();
    let modules: Vec<Value> = names.into_iter().map(|m| {
        let p = st.pending.get(m);
        let images = st.images.get(m).cloned().unwrap_or_default();
        let (bytes, datasets) = cache.by_module.get(m).copied().unwrap_or_default();
        json!({"module": m, "state": p.map(|p| reason(p, st.retired_at.is_some())).unwrap_or("enabled"),
               "in_release": release.contains(m), "data_bytes": data.get(m).copied().unwrap_or(0),
               "cache_bytes": bytes, "datasets": datasets, "images": images.len(),
               "image_bytes": images.iter().map(|i| i.bytes).sum::<Option<u64>>(),
               "delete_at": p.map(|p| delete_at(p, days)).filter(|t| t.is_finite()).map(|t| t.max(now))})
    }).collect();
    json!({"at": now, "retention_days": days, "modules": modules, "unremoved_images": st.unremoved.len(),
           "cache": {"bytes": cache.bytes, "datasets": cache.datasets, "cap_bytes": cache.cap, "over_cap": cache.over_cap}})
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: f64 = 86400.0;

    fn set(xs: &[&str]) -> BTreeSet<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    /// Turned off: it goes after the retention, and turning it back on in time cancels that; out of the release: after
    /// at most a day; purged: at once; a retired node's modules are all gone.
    #[test]
    fn deletions_wait_for_their_grace_and_a_module_back_on_keeps_everything() {
        let mut st = State::default();
        let (rel, none) = (set(&["a", "b", "c"]), set(&[]));
        let present = set(&["a", "b", "c", "old"]);
        let i = |disabled: &BTreeSet<String>, purge: &BTreeSet<String>| (disabled.clone(), purge.clone());
        let (off, purge) = i(&set(&["a", "b"]), &none);
        let inputs = Inputs { release: &rel, release_id: Some("r_1"), disabled: &off, purge: &purge, present: &present };
        assert!(plan(&mut st, &inputs, 100.0).is_empty());
        assert_eq!(st.pending.keys().collect::<Vec<_>>(), ["a", "b", "old"]);
        assert_eq!(st.pending["a"], Pending { disabled_since: Some(100.0), release: Some("r_1".into()), ..Default::default() });
        assert_eq!(st.pending["old"].removed_since, Some(100.0));
        assert_eq!(due(&st, 100.0 + DAY - 1.0), []);
        assert_eq!(due(&st, 100.0 + DAY), [("old".to_string(), "removed")]);
        assert_eq!(due(&st, 100.0 + 7.0 * DAY), [("a".into(), "disabled"), ("b".into(), "disabled"), ("old".into(), "removed")]);
        // b is turned back on; a is purged; a later sighting keeps the first time
        let (off, purge) = i(&set(&["a"]), &set(&["a", "c"]));
        let inputs = Inputs { release: &rel, release_id: Some("r_2"), disabled: &off, purge: &purge, present: &present };
        assert_eq!(plan(&mut st, &inputs, 500.0), ["b"]);
        assert!(st.pending["a"].purge && st.pending["a"].disabled_since == Some(100.0) && !st.pending.contains_key("c"));
        assert_eq!(due(&st, 501.0), [("a".to_string(), "purge")]);
        // a leaves the release: the shorter of its two graces; retention 0 deletes at once
        st.pending.get_mut("a").unwrap().purge = false;
        let rel2 = set(&["b", "c"]);
        let inputs = Inputs { release: &rel2, release_id: Some("r_3"), disabled: &off, purge: &none, present: &present };
        plan(&mut st, &inputs, 1000.0);
        assert_eq!((delete_at(&st.pending["a"], 7.0), delete_at(&st.pending["a"], 0.0)), (1000.0 + DAY, 100.0));
        assert_eq!(st.pending["a"].release.as_deref(), Some("r_2"), "the last release that held its bundle");
        assert_eq!(kept_releases_of(&st), set(&["r_2"]));
        st.retired_at = Some(2000.0);
        plan(&mut st, &inputs, 2000.0);
        assert_eq!(st.pending.keys().collect::<Vec<_>>(), ["a", "b", "c", "old"]);
        assert_eq!(reason(&st.pending["c"], true), "retired");
        assert_eq!(delete_at(&st.pending["c"], 7.0), 2000.0 + DAY);
    }

    fn kept_releases_of(st: &State) -> BTreeSet<String> {
        st.pending.values().filter_map(|p| p.release.clone()).collect()
    }

    /// A deleted module's images go unless a module still here uses the same one; acknowledged records go.
    #[test]
    fn images_another_module_uses_stay_and_acknowledged_deletions_go() {
        let img = |r: &str, gpu| Image { image: r.into(), platform: "linux/arm64".into(), gpu, bytes: Some(5), tries: 0 };
        let mut st = State::default();
        st.images.insert("a".into(), vec![img("docker.io/x/y@sha256:01", false), img("docker.io/x/z@sha256:02", false),
                                          img("docker.io/x/z@sha256:02", true)]);
        st.images.insert("b".into(), vec![img("docker.io/x/y@sha256:01", false)]);
        let gone: Vec<String> = take_images(&mut st, "a").into_iter().map(|i| format!("{} {}", i.image, i.gpu)).collect();
        assert_eq!(gone, ["docker.io/x/z@sha256:02 false", "docker.io/x/z@sha256:02 true"]);
        let (n, left) = remove_images(None, vec![img("docker.io/x/z@sha256:02", false)]);
        assert_eq!((n, left.len()), (0, 1), "no runtime: it waits");
        for k in 0..DONE_MAX + 3 {
            note_done(&mut st, done_record("a", "disabled", k as f64, 1, 0, None, None));
        }
        assert_eq!(st.done.len(), DONE_MAX);
        let d = crate::scratch("cleanup-ack");
        let l = Layout::new(d.path().to_path_buf());
        update(&l, |s| *s = State { done: st.done.clone(), ..Default::default() });
        ack(&l, &["a@3000".into(), "a@4000".into()]);
        assert_eq!(load(&l).done.len(), DONE_MAX - 2);
    }

    /// The data directory and the agent's grant directories for the module go; another module's stay.
    #[test]
    fn a_modules_files_go_and_only_its_own() {
        let d = crate::scratch("cleanup-files");
        let l = Layout::new(d.path().to_path_buf());
        for p in [l.module_data().join("a/cache/x.bin"), l.module_data().join("b/keep.bin"), l.run().join("services/a/settings.json"),
                  l.run().join("doctor-a/settings.json"), l.run().join("workloads/a/w/control.json")] {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"12345").unwrap();
        }
        assert_eq!(present(&l), set(&["a", "b"]));
        assert_eq!(delete_files(&l, "a"), (5, None));
        assert!(!l.module_data().join("a").exists() && !l.run().join("services/a").exists() && !l.run().join("doctor-a").exists()
                && !l.run().join("workloads/a").exists() && l.module_data().join("b/keep.bin").exists());
        assert_eq!(present(&l), set(&["b"]));
    }

    /// A cleanup run gets the reason, attempt id 0 and no tools, under the module sandbox; a failure is reported with
    /// the runner's own reason, and a run that outlasts its timeout is killed.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_cleanup_stage_runs_sandboxed_and_reports_how_it_went() {
        let d = crate::scratch("cleanup-stage");
        let root = std::fs::canonicalize(d.path()).unwrap();
        let l = Layout::new(root.join("home"));
        l.ensure().unwrap();
        let dir = l.releases().join("r_t");
        let bundle = dir.join("modules/m");
        std::fs::create_dir_all(&bundle).unwrap();
        let script = bundle.join("clean.sh");
        std::fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cleanup/clean.sh"), &script).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let entry = json!({"name": "m", "module_id": "dev.test.m", "version": "1.0.0", "bundle": "modules/m",
                           "runner": {"exec": ["{bundle}/clean.sh"]},
                           "sandbox": {"contract": 1, "net": {"mode": "none"}, "devices": {"gpu": "none"}, "exec_writable": false,
                                       "tools": [{"id": "java17", "trust": "code-exec"}]},
                           "stages": [{"name": "run"}, {"name": "release", "cleanup": true, "timeout_s": 2}]});
        let rel = Release { id: "r_t".into(), dir, modules: vec![entry.clone()], tools: Value::Null };
        let rt = crate::runtime::Runtime { python: PathBuf::from("/usr/bin/python3"), uv: None, site_dirs: vec![], roots: vec![],
                                           host_provided: None };
        let stage = stage_of(&entry).unwrap();
        let run = |why: &'static str| StageRun { layout: &l, runtime: &rt, release: &rel, entry: &entry, stage: &stage, reason: why,
                                                 settings: &Value::Null };
        let data = l.module_data().join("m");
        let out = run_stage(&run("disabled")).await;
        assert_eq!((out["stage"].as_str(), out["ok"].as_bool()), (Some("release"), Some(true)), "{out}");
        assert_eq!(std::fs::read_to_string(data.join("released")).unwrap(), "disabled 0 {}\n");
        assert!(!l.work().join("cleanup-m").exists(), "its work directory goes");
        std::fs::write(data.join("fail"), b"").unwrap();
        let out = run_stage(&run("purge")).await;
        assert_eq!((out["ok"].as_bool(), out["detail"].as_str()), (Some(false), Some("m/still_registered: the registry said no")));
        std::fs::write(data.join("hang"), b"").unwrap();
        let t = Instant::now();
        let out = run_stage(&run("removed")).await;
        assert_eq!((out["ok"].as_bool(), out["detail"].as_str()), (Some(false), Some("it did not finish within 2 s")));
        assert!(t.elapsed() < Duration::from_secs(20));
    }

    /// The cleanup stage runs only where its platforms admit the node.
    #[test]
    fn the_cleanup_stage_is_taken_from_the_release_entry() {
        let here = crate::facts::platform_token();
        let os = here.split('-').next().unwrap().to_string();
        let e = |plats: Value| json!({"stages": [{"name": "run"}, {"name": "release", "cleanup": true, "platforms": plats}]});
        assert_eq!(stage_of(&e(json!([]))).unwrap()["name"], "release");
        assert!(stage_of(&e(json!([here]))).is_some() && stage_of(&e(json!([os]))).is_some());
        assert!(stage_of(&e(json!(["plan9-amd64"]))).is_none());
        assert!(stage_of(&json!({"stages": [{"name": "run"}]})).is_none());
    }
}
