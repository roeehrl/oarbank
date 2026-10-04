//! Running a grant (docs/protocol.md, "Work": Running a job; runner protocol 1): stage its datasets into a fresh work
//! directory, write spec.json and control.json, start the runner in its own process group under the module sandbox
//! with exactly the protocol's environment, watch it (deadline, stop, pause, usage), then upload its artifacts and
//! complete, or fail with the runner's own fault attribution.

use crate::api::Api;
use crate::doctor::{base_env, grant_files, module_env, resolve_exec};
use crate::paths::Layout;
use crate::release::Release;
use crate::runtime::Runtime;
use crate::{procs, staging};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tracing::{info, warn};

/// Why the agent ends an attempt itself.
#[derive(Debug, Clone, PartialEq)]
pub enum Stop {
    /// `cancel`: stop and release(user_cancel).
    Cancel,
    /// `revoke` or `kill`: kill silently, report nothing.
    Revoke,
    /// release with this reason (drain, protection, limits).
    Release(String),
}

#[derive(Debug, Clone)]
pub struct JobState {
    pub attempt_id: i64,
    pub phase: String,
    pub cpu: f64,
    pub mem_gb: f64,
    pub gpu: bool,
    pub pgid: Option<i32>,
    pub stop: Option<Stop>,
    pub pause: bool,
    pub usage: procs::Usage,
    pub log_bytes: u64,
    /// Unix time the attempt started (protection orders work by age).
    pub started_at: f64,
    /// The runner's declared capabilities and bandwidth class (what protection may do to it).
    pub caps: Vec<String>,
    pub bandwidth: Option<String>,
    /// Cooperative throttle: the thread ceiling protection set (written into control.json).
    pub threads: Option<i64>,
    /// Pools the job reserves or needs (services start on demand for them).
    pub needs: Vec<String>,
    /// Wakes the job's monitor when `stop`, `pause` or `threads` change, so control.json follows at once.
    pub wake: Arc<Notify>,
}

/// The pool names a grant's resources reserve (`pools`) or only require (`needs_pools`).
pub fn needs_of(resources: &Value) -> Vec<String> {
    let mut out: Vec<String> = resources["pools"].as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default();
    for p in resources["needs_pools"].as_array().cloned().unwrap_or_default() {
        if let Some(p) = p.as_str() {
            if !out.iter().any(|x| x == p) {
                out.push(p.to_string());
            }
        }
    }
    out
}

pub type Table = Arc<Mutex<HashMap<i64, JobState>>>;

pub struct Ctx {
    pub api: Arc<Api>,
    pub layout: Layout,
    pub runtime: Runtime,
    pub release: Release,
    pub policy: Value,
    pub table: Table,
    pub registry: Option<Arc<oarbank_protection::SpawnRegistry>>,
    /// The agent's container runtime, for modules approved for containers.
    #[cfg(unix)]
    pub containers: Option<Arc<dyn crate::container_runtime::ContainerRuntime>>,
    /// The module services, for the readiness gate before a runner that needs their pools starts.
    pub services: Option<Arc<Mutex<crate::services::ServiceManager>>>,
}

/// How long a job waits for the services providing its pools to become ready.
const SERVICE_WAIT_S: u64 = 900;

fn mount_of(spec: &Value, did: &str) -> String {
    spec["mounts"][did].as_str().map(str::to_string).unwrap_or_else(|| did.replace(':', "_"))
}

fn set_phase(t: &Table, aid: i64, phase: &str) {
    if let Some(j) = t.lock().unwrap().get_mut(&aid) {
        j.phase = phase.into();
    }
}

fn stop_of(t: &Table, aid: i64) -> Option<Stop> {
    t.lock().unwrap().get(&aid).and_then(|j| j.stop.clone())
}

/// A job's control document (runner protocol 1, "Control"): `{"seq": 0}` before the runner starts, then every change
/// replaced atomically with a newer seq and followed by a nudge (sys.rs `Nudge`), so the runner re-reads it when it
/// changes and never polls.
pub struct ControlFile {
    ws: PathBuf,
    seq: u64,
    nudge: crate::sys::Nudge,
    leader: i32,
}

impl ControlFile {
    pub fn create(ws: &Path) -> std::io::Result<ControlFile> {
        let c = ControlFile { ws: ws.to_path_buf(), seq: 0, nudge: crate::sys::Nudge::new()?, leader: 0 };
        c.replace(json!({}))?;
        Ok(c)
    }

    /// The runner's command, after its environment is set: how the nudge reaches it.
    pub fn prepare(&self, cmd: &mut std::process::Command) {
        self.nudge.prepare(cmd);
    }

    /// The runner started: its container's leader.
    pub fn started(&mut self, leader: i32) {
        self.leader = leader;
    }

    /// Replace the document with a newer seq, then nudge the runner.
    pub fn write(&mut self, doc: Value) -> std::io::Result<()> {
        self.seq += 1;
        self.replace(doc)?;
        self.nudge.send(self.leader);
        Ok(())
    }

    /// Atomically; a replace refused because the runner has the file open (Windows) is retried for up to 2 s.
    fn replace(&self, mut doc: Value) -> std::io::Result<()> {
        doc["seq"] = json!(self.seq);
        let tmp = self.ws.join("control.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&doc)?)?;
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            match std::fs::rename(&tmp, self.ws.join("control.json")) {
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                r => return r,
            }
        }
    }
}

/// The failure.json reasons that become the attempt's end reason (the SDK's `FAILURE_REASONS`; the coordinator maps
/// each to its code). Anything else, a module's own `<module-short>/<code>` included, ends it as `exit_nonzero` with
/// the reason in the detail.
const FAILURE_REASONS: [&str; 5] = ["bad_input", "mode_mismatch", "oom", "doctor", "no_metrics"];

enum Outcome {
    Completed(Value),
    Failed { reason: String, exit_code: Option<i32>, stderr_tail: String, fault: Option<String> },
    Stopped(Stop),
}

/// Stage the grant's datasets and place them at their mounts.
async fn stage_workspace(ctx: &Ctx, spec: &Value, ws: &Path) -> Result<()> {
    for did in spec["datasets"].as_array().cloned().unwrap_or_default() {
        let did = did.as_str().context("dataset id")?;
        staging::stage(&ctx.api, &ctx.layout, did).await?;
        let m = staging::manifest(&ctx.api, &ctx.layout, did).await?;
        let mount = mount_of(spec, did);
        oarbank_core::portable::check_portable_path(&mount, false).map_err(|e| anyhow::anyhow!("mount {mount:?}: {}", e.0))?;
        for f in m["files"].as_array().cloned().unwrap_or_default() {
            let rel = f["path"].as_str().context("file path")?;
            oarbank_core::portable::check_portable_path(rel, true).map_err(|e| anyhow::anyhow!("file {rel:?}: {}", e.0))?;
            let blob = staging::blob_path(&ctx.layout, f["digest"].as_str().unwrap_or(""));
            staging::place(&blob, &ws.join(&mount).join(rel))?;
        }
    }
    Ok(())
}

fn tail(p: &Path, n: usize) -> String {
    std::fs::read(p).map(|b| String::from_utf8_lossy(&b[b.len().saturating_sub(n)..]).to_string()).unwrap_or_default()
}

/// Run one granted attempt. `deadline`: when it must stop, on this node's monotonic clock (clock::local_deadline).
pub async fn run(ctx: Arc<Ctx>, grant: Value, deadline: Option<Instant>) {
    let aid = grant["attempt_id"].as_i64().unwrap_or(0);
    let ws = ctx.layout.work().join(aid.to_string());
    let started = Instant::now();
    let outcome = match execute(&ctx, &grant, &ws, deadline).await {
        Ok(o) => o,
        Err(e) => Outcome::Failed { reason: if format!("{e:#}").contains("dataset") || format!("{e:#}").contains("blob") {
                                        "input_missing".into() } else { "exit_nonzero".into() },
                                    exit_code: None, stderr_tail: format!("{e:#}"), fault: None },
    };
    report(&ctx, aid, &ws, outcome, started.elapsed()).await;
    ctx.table.lock().unwrap().remove(&aid);
    let _ = std::fs::remove_dir_all(&ws);
}

async fn execute(ctx: &Ctx, grant: &Value, ws: &Path, hard_deadline: Option<Instant>) -> Result<Outcome> {
    let aid = grant["attempt_id"].as_i64().context("grant without attempt id")?;
    let spec = &grant["spec"];
    let module = grant["module"].as_str().context("grant without module")?;
    let entry = ctx.release.module(module).context("the module is not in this node's release")?.clone();
    let _ = std::fs::remove_dir_all(ws);
    crate::fsutil::private_dir(&ws.join("tmp"))?;
    set_phase(&ctx.table, aid, "staging");
    stage_workspace(ctx, spec, ws).await?;
    if let Some(s) = stop_of(&ctx.table, aid) {
        return Ok(Outcome::Stopped(s));
    }
    let needs = needs_of(&spec["resources"]);
    if let (false, Some(svc)) = (needs.is_empty(), &ctx.services) {
        // the agent's tick starts the services this job counts towards; the runner waits for their readiness
        let deadline = Instant::now() + std::time::Duration::from_secs(SERVICE_WAIT_S);
        while !svc.lock().unwrap().ready_for(&needs) {
            if let Some(s) = stop_of(&ctx.table, aid) {
                return Ok(Outcome::Stopped(s));
            }
            if Instant::now() > deadline {
                return Ok(Outcome::Failed { reason: "exit_nonzero".into(), exit_code: None, fault: Some("host".into()),
                                            stderr_tail: format!("the services providing {needs:?} did not become ready") });
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    std::fs::write(ws.join("spec.json"), serde_json::to_vec(spec)?)?;
    let mut control = ControlFile::create(ws)?;
    let bundle = ctx.release.bundle(&entry);
    let python = ctx.runtime.module_python(&ctx.release.dir, module);
    let data = ctx.layout.module_data().join(module);
    crate::fsutil::private_dir(&data.join("tmp"))?;
    let grants_dir = ws.join(".grants");
    let mut settings = ctx.policy["module_settings"][module].clone();
    if settings.is_null() {
        settings = json!({});
    }
    let (tools_file, settings_file, tool_paths) = grant_files(&grants_dir, &entry, &settings)?;
    let net = entry["sandbox"]["net"]["mode"].as_str().unwrap_or("none").to_string();
    let proxy = if net == "egress-allowlist" {
        let allow: Vec<String> = entry["sandbox"]["net"]["allow"].as_array().cloned().unwrap_or_default().iter()
            .filter_map(|a| a.as_str().map(str::to_string)).collect();
        Some(crate::proxy::start(allow).await?)
    } else {
        None
    };
    let images: Vec<(String, String)> = entry["sandbox"]["containers"].as_array().cloned().unwrap_or_default().iter()
        .filter_map(|c| Some((c["image"].as_str()?.to_string(), c["platform"].as_str()?.to_string()))).collect();
    #[cfg(windows)]
    let broker: Option<crate::broker::Broker> = match images.is_empty() {
        true => None,
        false => bail!("the module runs containers but this node has no container runtime"),
    };
    #[cfg(unix)]
    let broker = if images.is_empty() {
        None
    } else {
        let rt = ctx.containers.clone().context("the module runs containers but this node has no container runtime")?;
        let sock = crate::paths::socket_path(&ctx.layout.home, &format!("broker-{aid}.sock"))?;
        let res = &spec["resources"];
        let grant = crate::broker::BrokerGrant { attempt_id: aid, module: module.to_string(), approved_images: images,
            workdir: ws.to_path_buf(), module_data: data.clone(), network_granted: net != "none",
            cpus: res["cpu"].as_f64().unwrap_or(1.0), mem_gb: res["mem_gb"].as_f64().unwrap_or(1.0) };
        Some(crate::broker::Broker::start(sock, grant, rt).await?)
    };
    let runner = &entry["runner"];
    let mut argv = resolve_exec(runner["exec"].as_array().map(Vec::as_slice).unwrap_or(&[]), &bundle, &python);
    if argv.is_empty() {
        bail!("the module entry has no runner exec");
    }
    argv.extend(["run", "--spec"].map(String::from));
    argv.push(ws.join("spec.json").display().to_string());
    argv.extend(["--workdir".to_string(), ws.display().to_string(), "--out".to_string(), ws.join("result.json").display().to_string()]);
    if runner["capabilities"].as_array().is_some_and(|c| c.iter().any(|x| x == "progress_events")) {
        argv.extend(["--events".to_string(), ws.join("events.ndjson").display().to_string()]);
    }
    let mut env = base_env(module, ws, &ws.join("tmp"));
    env.extend([("OARBANK_WORKDIR".into(), ws.display().to_string()), ("OARBANK_TMP".into(), ws.join("tmp").display().to_string()),
                ("OARBANK_MODULE_DATA".into(), data.display().to_string()), ("OARBANK_ATTEMPT_ID".into(), aid.to_string()),
                ("OARBANK_TOOLS_FILE".into(), tools_file.display().to_string()),
                ("OARBANK_SETTINGS_FILE".into(), settings_file.display().to_string())]);
    if let Some(p) = &proxy {
        let url = format!("http://127.0.0.1:{}", p.port);
        for k in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy"] {
            env.push((k.into(), url.clone()));
        }
    }
    if let Some(b) = &broker {
        env.push(("OARBANK_BROKER".into(), b.endpoint()));
    }
    if let Some(off) = ctx.policy["disabled_services"].as_array() {
        let mine: Vec<String> = off.iter().filter_map(|s| s.as_str()).filter_map(|s| s.strip_prefix(&format!("{module}/")))
            .map(str::to_string).collect();
        env.push(("OARBANK_DISABLED_SERVICES".into(), mine.join(",")));
    }
    env.extend(module_env(&entry).map_err(|e| anyhow::anyhow!(e))?);
    if crate::sandbox::available() {
        let mut pol = oarbank_core::sandbox::Policy::new(entry["module_id"].as_str().unwrap_or(module));
        pol.ro = vec![bundle.display().to_string(), python.display().to_string()];
        let venv = ctx.release.dir.join("venvs").join(module);
        if venv.exists() {
            pol.ro.push(venv.display().to_string());
        }
        pol.ro.extend(ctx.runtime.roots.iter().cloned());
        pol.ro.extend(tool_paths);
        pol.rw = vec![ws.display().to_string(), data.display().to_string()];
        pol.net = net.clone();
        pol.proxy_port = proxy.as_ref().map(|p| p.port);
        pol.broker_socket = broker.as_ref().map(|b| b.endpoint().trim_start_matches("unix:").to_string());
        pol.gpu = entry["sandbox"]["devices"]["gpu"].as_str().is_some_and(|g| g != "none");
        pol.exec_rw = entry["sandbox"]["exec_writable"].as_bool() == Some(true);
        pol.kind = "runner".into();
        pol.exe = Some(python.display().to_string());
        argv = crate::sandbox::wrap(&pol, &grants_dir.join("runner.sb"), &argv).map_err(|e| anyhow::anyhow!(e))?;
    }
    let log = std::fs::File::create(ws.join(".runner.log"))?;
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]).env_clear().envs(env).current_dir(ws).stdin(std::process::Stdio::null())
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
    // the node's policy may turn the job's reservation into hard limits where the OS has them (spec/sandbox.md,
    // "Resources"): exceeding the memory limit is then the job's fault (oom)
    if ctx.policy["hard_limits"].as_bool() == Some(true) {
        let res = &spec["resources"];
        crate::sys::limit(pid, res["cpu"].as_f64().unwrap_or(0.0), res["mem_gb"].as_f64().unwrap_or(0.0));
    }
    if let Some(r) = &ctx.registry {
        r.register(pid, Some(aid), None);                 // only registered groups may ever be signalled (S16)
    }
    {
        let mut t = ctx.table.lock().unwrap();
        if let Some(j) = t.get_mut(&aid) {
            j.pgid = Some(pid);
            j.phase = "running".into();
        }
    }
    // the launcher says when its sandbox holds, just before the module runs: a runner that does not come up confined
    // is killed, never left running
    if let Some(s) = signal {
        use crate::sandbox::Came;
        let came = tokio::task::spawn_blocking(move || s.wait(pid as u32, crate::sandbox::CONFINE_GUARD)).await
            .unwrap_or(Came::Hung);
        let fault = match came {
            Came::Confined if crate::sandbox::holds(pid) || matches!(child.try_wait(), Ok(Some(_))) => None,
            Came::Confined => Some("sandbox_missing: the launcher said it was confined, but the runner is not"),
            Came::Ended => None,                               // it could not confine itself: its exit says why
            Came::Hung => Some("sandbox_hung: the launcher did not confine itself within the guard"),
        };
        if let Some(f) = fault {
            warn!(attempt = aid, "{f}; killed");
            procs::signal_group(pid, procs::Sig::Kill);
            bail!("the runner did not come up sandboxed");
        }
    }
    let grace = runner["stop_grace_s"].as_f64().unwrap_or(20.0);
    let wake = ctx.table.lock().unwrap().get(&aid).map(|j| j.wake.clone()).unwrap_or_default();
    let mut stopping: Option<(Stop, Instant)> = None;
    let mut paused = false;
    let mut threads: Option<i64> = None;
    let mut log_sent = 0u64;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        let usage = procs::group_usage(pid);
        let log_len = std::fs::metadata(ws.join(".runner.log")).map(|m| m.len()).unwrap_or(0);
        let (stop, want_pause, want_threads) = {
            let mut t = ctx.table.lock().unwrap();
            let j = t.get_mut(&aid);
            match j {
                Some(j) => {
                    j.usage = usage;
                    j.log_bytes = log_len;
                    if let Ok(p) = std::fs::read_to_string(ws.join("phase")) {
                        let p = p.trim().chars().take(40).collect::<String>();
                        if !p.is_empty() && !j.pause {
                            j.phase = p;
                        }
                    }
                    (j.stop.clone(), j.pause, j.threads)
                }
                None => (Some(Stop::Revoke), false, None),
            }
        };
        if log_len > log_sent + 4096 {
            let chunk = std::fs::read(ws.join(".runner.log")).ok().map(|b| String::from_utf8_lossy(&b[log_sent as usize..]).to_string());
            if let Some(c) = chunk {
                if ctx.api.post_text(&format!("/v1/attempts/{aid}/log"), c).await.is_ok() {
                    log_sent = log_len;
                }
            }
        }
        if want_pause != paused || want_threads != threads {
            let mut doc = json!({"pause": want_pause, "reason": "protection"});
            if let Some(t) = want_threads {
                doc["threads"] = json!(t);
            }
            control.write(doc)?;
            if want_pause != paused {
                set_phase(&ctx.table, aid, if want_pause { "paused" } else { "running" });
            }
            paused = want_pause;
            threads = want_threads;
        }
        if stopping.is_none() {
            let timed_out = hard_deadline.is_some_and(|d| Instant::now() > d);
            if let Some(s) = stop.or(if timed_out { Some(Stop::Release("timeout".into())) } else { None }) {
                control.write(json!({"stop": true}))?;
                // POSIX also asks the container with SIGTERM; Windows has no such request (Term terminates the Job
                // Object), so there the nudged document is the request and the kill waits for the grace period
                #[cfg(unix)]
                procs::signal_group(pid, procs::Sig::Term);
                stopping = Some((s, Instant::now()));
            }
        } else if let Some((_, at)) = &stopping {
            if at.elapsed() > Duration::from_secs_f64(grace) {
                procs::signal_group(pid, procs::Sig::Kill);
            }
        }
        // the runner's exit and a control change act at once; usage, logs, phase and deadlines are sampled
        tokio::select! {
            _ = child.wait() => {}
            _ = wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    };
    let oom = crate::sys::oom(pid);
    procs::signal_group(pid, procs::Sig::Kill);                     // nothing outlives its attempt
    if let Some(r) = &ctx.registry {
        r.unregister(pid);
    }
    crate::sys::release(pid);
    drop(proxy);
    #[cfg(unix)]
    drop(broker);                                              // stops serving and removes this attempt's containers
    if let Some((s, _)) = stopping {
        if s == Stop::Release("timeout".into()) {
            return Ok(Outcome::Failed { reason: "timeout".into(), exit_code: status.code(), stderr_tail: tail(&ws.join(".runner.log"), 2000), fault: None });
        }
        return Ok(Outcome::Stopped(s));
    }
    let code = status.code();
    if code == Some(0) {
        if let Ok(b) = std::fs::read(ws.join("result.json")) {
            return Ok(Outcome::Completed(serde_json::from_slice(&b).context("result.json is not JSON")?));
        }
    }
    let failure: Option<Value> = std::fs::read(ws.join("failure.json")).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let fault = failure.as_ref().and_then(|f| f["fault"].as_str().map(str::to_string)).or_else(|| failure.as_ref().and(match code {
        Some(2) => Some("job".into()),
        Some(3) => Some("host".into()),
        Some(75) => Some("transient".into()),
        _ => None,
    }));
    if oom {
        return Ok(Outcome::Failed { reason: "oom".into(), exit_code: code, fault: Some("job".into()),
                                    stderr_tail: format!("over its memory limit\n{}", tail(&ws.join(".runner.log"), 2000)) });
    }
    let reason = failure.as_ref().and_then(|f| f["reason"].as_str()).filter(|r| FAILURE_REASONS.contains(r))
        .map(str::to_string).unwrap_or_else(|| "exit_nonzero".into());
    let detail = failure.as_ref().map(|f| format!("{}: {}\n", f["reason"], f["detail"])).unwrap_or_default();
    Ok(Outcome::Failed { reason, exit_code: code, stderr_tail: detail + &tail(&ws.join(".runner.log"), 2000), fault })
}

/// Upload artifacts named by the result (`files[].local`, relative to the work directory) and replace each `local`
/// with its `digest` and `size`.
async fn upload_artifacts(ctx: &Ctx, ws: &Path, result: &mut Value) -> Result<()> {
    let Some(arts) = result["artifacts"].as_array_mut() else { return Ok(()) };
    for a in arts.iter_mut() {
        for f in a["files"].as_array_mut().into_iter().flatten() {
            let Some(local) = f["local"].as_str().map(str::to_string) else { continue };
            oarbank_core::portable::check_portable_path(&local, true).map_err(|e| anyhow::anyhow!("artifact {local:?}: {}", e.0))?;
            let p: PathBuf = ws.join(&local);
            let meta = std::fs::symlink_metadata(&p).with_context(|| format!("artifact {local} missing"))?;
            if !meta.is_file() {
                bail!("artifact {local} is not a regular file");
            }
            let digest = crate::fsutil::sha256_file(&p)?;
            if !ctx.api.head_ok(&format!("/v1/artifacts/{digest}")).await.unwrap_or(false) {
                ctx.api.put_file(&format!("/v1/artifacts/{digest}"), &p).await?;
            }
            let o = f.as_object_mut().unwrap();
            o.remove("local");
            o.insert("digest".into(), json!(digest));
            o.insert("size".into(), json!(meta.len()));
        }
    }
    Ok(())
}

/// Report how the attempt ended and log it with how long it ran (from the grant, staging included).
async fn report(ctx: &Ctx, aid: i64, ws: &Path, o: Outcome, ran: Duration) {
    let ran_s = (ran.as_secs_f64() * 10.0).round() / 10.0;
    match o {
        Outcome::Completed(mut result) => {
            if let Err(e) = upload_artifacts(ctx, ws, &mut result).await {
                warn!(attempt = aid, error = %e, "artifact upload failed");
                let _ = ctx.api.post(&format!("/v1/attempts/{aid}/fail"),
                                     &json!({"reason": "exit_nonzero", "stderr_tail": format!("artifacts: {e:#}")})).await;
                return;
            }
            let body = json!({"idempotency_key": format!("att-{aid}-complete"), "result": result});
            crate::outbox::send(&ctx.api, &ctx.layout, &format!("/v1/attempts/{aid}/complete"), &body).await;
            info!(attempt = aid, ran_s, "completed");
        }
        Outcome::Failed { reason, exit_code, stderr_tail, fault } => {
            let body = json!({"reason": reason, "exit_code": exit_code, "stderr_tail": stderr_tail.chars().rev().take(2000)
                .collect::<String>().chars().rev().collect::<String>(), "fault": fault});
            crate::outbox::send(&ctx.api, &ctx.layout, &format!("/v1/attempts/{aid}/fail"), &body).await;
            info!(attempt = aid, %reason, ran_s, "failed");
        }
        Outcome::Stopped(Stop::Revoke) => info!(attempt = aid, ran_s, "revoked"),
        Outcome::Stopped(Stop::Cancel) => {
            let _ = ctx.api.post(&format!("/v1/attempts/{aid}/release"), &json!({"reason": "user_cancel"})).await;
            info!(attempt = aid, reason = "user_cancel", ran_s, "cancelled");
        }
        Outcome::Stopped(Stop::Release(reason)) => {
            let _ = ctx.api.post(&format!("/v1/attempts/{aid}/release"), &json!({"reason": reason})).await;
            info!(attempt = aid, %reason, ran_s, "released");
        }
    }
}

/// The heartbeat's `attempts` list.
pub fn attempts(t: &Table) -> Value {
    json!(t.lock().unwrap().values().map(|j| json!({"attempt_id": j.attempt_id, "phase": j.phase, "cpu_s": j.usage.cpu_s,
        "log_bytes": j.log_bytes, "rss_gb": j.usage.footprint_gb})).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oarbank-control-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn seq_of(doc: &str) -> Option<i64> {
        serde_json::from_str::<Value>(doc).ok().and_then(|d| d["seq"].as_i64())
    }

    /// The agent and the SDK's runner-failure schema agree on the end reasons a runner may give.
    #[test]
    fn failure_reasons_match_the_sdk_schema() {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../vendor/oarbank-sdk/schemas/runner-failure-1.schema.json");
        let schema: Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
        let sdk: Vec<&str> = schema["properties"]["reason"]["anyOf"].as_array().unwrap().iter()
            .find_map(|a| a["enum"].as_array()).unwrap().iter().map(|r| r.as_str().unwrap()).collect();
        assert_eq!(sdk, FAILURE_REASONS);
    }

    /// The runner's nudge handler reads control.json: it must already be the new document.
    #[cfg(unix)]
    #[test]
    fn the_nudge_follows_the_replaced_document() {
        let ws = scratch("unix");
        let mut control = ControlFile::create(&ws).unwrap();
        assert_eq!(seq_of(&std::fs::read_to_string(ws.join("control.json")).unwrap()), Some(0));
        let mut cmd = std::process::Command::new("python3");
        cmd.args(["-I", "-c", "import pathlib, signal, sys, time\n\
            d = pathlib.Path(sys.argv[1])\n\
            signal.signal(signal.SIGUSR1, lambda *_: (d / 'seen').write_text((d / 'control.json').read_text()))\n\
            (d / 'ready').write_text('1')\n\
            while True: time.sleep(0.05)\n"]).arg(&ws);
        control.prepare(&mut cmd);
        let mut child = crate::sys::spawn_contained(&mut cmd, false).unwrap();
        control.started(child.id() as i32);
        let wait = |f: &str| (0..600).find_map(|_| std::fs::read_to_string(ws.join(f)).ok().filter(|s| !s.is_empty())
            .or_else(|| { std::thread::sleep(Duration::from_millis(50)); None }));
        assert!(wait("ready").is_some());
        control.write(json!({"pause": true})).unwrap();
        let seen: Value = serde_json::from_str(&wait("seen").expect("the runner was nudged")).unwrap();
        assert_eq!((seen["seq"].as_i64(), seen["pause"].as_bool()), (Some(1), Some(true)));
        procs::signal_group(child.id() as i32, procs::Sig::Kill);
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&ws);
    }

    /// A waiter woken by the control event reads control.json: it must already be the new document.
    #[cfg(windows)]
    #[test]
    fn the_nudge_follows_the_replaced_document() {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        let ws = scratch("windows");
        let mut control = ControlFile::create(&ws).unwrap();
        assert_eq!(seq_of(&std::fs::read_to_string(ws.join("control.json")).unwrap()), Some(0));
        let mut cmd = std::process::Command::new("cmd.exe");
        control.prepare(&mut cmd);
        let event: usize = cmd.get_envs().find(|(k, _)| *k == crate::sys::CONTROL_EVENT_ENV).and_then(|(_, v)| v)
            .and_then(|v| v.to_str()?.parse().ok()).expect("OARBANK_CONTROL_EVENT is set");
        let path = ws.join("control.json");
        let waiter = std::thread::spawn(move || {
            (unsafe { WaitForSingleObject(event as _, 10_000) } == WAIT_OBJECT_0).then(|| std::fs::read_to_string(path).unwrap())
        });
        std::thread::sleep(Duration::from_millis(100));
        control.write(json!({"pause": true})).unwrap();
        let seen: Value = serde_json::from_str(&waiter.join().unwrap().expect("the event was set")).unwrap();
        assert_eq!((seen["seq"].as_i64(), seen["pause"].as_bool()), (Some(1), Some(true)));
        let _ = std::fs::remove_dir_all(&ws);
    }
}
