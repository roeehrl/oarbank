//! `oarbank-node` (docs/design/node-enrollment.md, "oarbank-node"): the node's own command line, the launcher under a
//! second name. `join` reads a code from a hidden prompt, standard input or a file (never from the command line), runs
//! the agent's checks, stages the code for the service through the install plan, and follows the status document until
//! the node joined, waits for approval, or failed with a stable code. `check`, `status`, `leave` and `doctor` read the
//! same document; `policy-apply` is what macOS's managed-policy job runs.

use crate::setup::{self, SetupOpts};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const USAGE: &str = "usage: oarbank-node join [--code-stdin | --code-file PATH | --coordinator URL] [--scope system|personal]
                         [--containers] [--name NAME] [--wait SECONDS | --no-wait] [--no-input] [--json] [--force]
       oarbank-node check [--code-stdin | --code-file PATH | --coordinator URL] [--json]
       oarbank-node status [--json] [--follow]
       oarbank-node leave
       oarbank-node doctor [--json]";

/// A failure with its status code and exit code (node-enrollment.md, "Error codes").
struct Fail {
    code: String,
    message: String,
    exit: i32,
}

fn fail(code: &str, message: impl Into<String>, exit: i32) -> Fail {
    Fail { code: code.into(), message: message.into(), exit }
}

fn exit_for(code: &str) -> i32 {
    match code {
        "E_CODE_FORMAT" => 2,
        "E_CODE_EXPIRED" | "E_CODE_USED" | "E_CODE_REVOKED" | "E_CODE_UNKNOWN" | "E_APPROVAL_DENIED" => 4,
        "E_TLS_PIN_MISMATCH" | "E_IDENTITY" => 5,
        "E_DNS" | "E_TCP" | "E_NOT_ACTIVE" | "E_CLOCK_SKEW" => 6,
        "E_ALREADY_JOINED" => 7,
        "E_PRIVILEGE" => 8,
        _ => 1,
    }
}

/// Where rows, states and the result go: the terminal (text or JSON lines) and the join window's progress file.
struct Out {
    json: bool,
    progress: Option<std::fs::File>,
}

impl Out {
    fn emit(&mut self, v: Value, text: &str) {
        if self.json {
            println!("{v}");
        } else if !text.is_empty() {
            println!("{text}");
        }
        if let Some(f) = &mut self.progress {
            let _ = writeln!(f, "{v}");
            let _ = f.flush();
        }
    }
    fn row(&mut self, r: &Value) {
        let t = format!("  {:<5} {:<9} {}", if r["ok"] == true { "ok" } else { "FAIL" }, r["row"].as_str().unwrap_or(""),
                        r["detail"].as_str().unwrap_or(""));
        self.emit(json!({"type": "row", "row": r["row"], "ok": r["ok"], "detail": r["detail"]}), &t);
    }
    fn state(&mut self, s: &Value, text: &str) {
        self.emit(json!({"type": "state", "status": s}), text);
    }
    fn done(&mut self, r: Result<Value, Fail>) -> i32 {
        match r {
            Ok(v) => {
                let text = v["message"].as_str().unwrap_or("").to_string();
                self.emit(json!({"type": "result", "ok": true, "exit": 0, "detail": v}), &text);
                0
            }
            Err(f) => {
                self.emit(json!({"type": "result", "ok": false, "exit": f.exit, "code": f.code, "message": f.message}), "");
                if !self.json {
                    eprintln!("{} ({})", f.message, f.code);
                }
                f.exit
            }
        }
    }
}

struct Opts {
    rest: Vec<String>,
}

impl Opts {
    fn has(&self, f: &str) -> bool {
        self.rest.iter().any(|o| o == f)
    }
    fn val(&self, f: &str) -> Option<String> {
        self.rest.iter().position(|o| o == f).and_then(|i| self.rest.get(i + 1)).cloned()
    }
}

fn agent_bin() -> Result<PathBuf> {
    let me = std::fs::canonicalize(std::env::current_exe()?)?;
    Ok(me.with_file_name(format!("oarbank-agent{}", std::env::consts::EXE_SUFFIX)))
}

/// The scope this machine's node uses: macOS has two (the console user's agent, or the system service); Linux and
/// Windows install the system service.
fn default_scope(o: &Opts, code_system: bool) -> String {
    if let Some(s) = o.val("--scope") {
        return s;
    }
    if !cfg!(target_os = "macos") {
        return "system".into();
    }
    if setup::privileged() && (code_system || installed_scope().as_deref() != Some("personal")) {
        "system".into()
    } else {
        "personal".into()
    }
}

/// The scope a node is installed in, if any (macOS: a LaunchDaemon is the system service).
fn installed_scope() -> Option<String> {
    if !cfg!(target_os = "macos") {
        return Some("system".into());
    }
    if Path::new(&format!("/Library/LaunchDaemons/{}.plist", crate::LABEL)).exists() {
        return Some("system".into());
    }
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    home.join(format!("Library/LaunchAgents/{}.plist", crate::LABEL)).exists().then(|| "personal".into())
}

fn read_status(home: &Path) -> Value {
    std::fs::read(setup::status_file(home)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null)
}

fn joined_to(home: &Path) -> Option<String> {
    let st = read_status(home);
    let cfg: Value = std::fs::read(home.join("agent.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
    let has_cert = home.join("keys").join("node.pem").exists();
    let joined = matches!(st["state"].as_str(), Some("joined" | "connected" | "offline")) || has_cert;
    joined.then(|| cfg["coordinator"].as_str().or(st["coordinator"].as_str()).unwrap_or("").to_string())
}

/// The code, from a file, standard input, or a hidden prompt on the terminal.
fn read_code(o: &Opts) -> Result<String, Fail> {
    if let Some(f) = o.val("--code-file") {
        return std::fs::read_to_string(&f).map(|s| s.trim().to_string())
            .map_err(|e| fail("E_CODE_FORMAT", format!("reading {f}: {e}"), 2));
    }
    if o.has("--code-stdin") || (!std::io::stdin().is_terminal() && !o.has("--no-input")) {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s).map_err(|e| fail("E_CODE_FORMAT", e.to_string(), 2))?;
        return Ok(s.trim().to_string());
    }
    if o.has("--no-input") {
        return Err(fail("E_CODE_FORMAT", "no join code: give --code-stdin or --code-file (--no-input never prompts)", 2));
    }
    prompt_hidden("Join code (input hidden): ").map(|s| s.trim().to_string()).map_err(|e| fail("E_CODE_FORMAT", e.to_string(), 2))
}

#[cfg(unix)]
fn prompt_hidden(msg: &str) -> std::io::Result<String> {
    use std::os::fd::AsRawFd;
    let tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let fd = tty.as_raw_fd();
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    unsafe { libc::tcgetattr(fd, &mut old) };
    let mut new = old;
    new.c_lflag &= !libc::ECHO;
    new.c_lflag |= libc::ECHONL;
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &new) };
    let mut w = &tty;
    let _ = write!(w, "{msg}");
    let _ = w.flush();
    let mut line = String::new();
    let r = std::io::BufReader::new(&tty).read_line(&mut line);
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
    r.map(|_| line)
}

#[cfg(windows)]
fn prompt_hidden(msg: &str) -> std::io::Result<String> {
    use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE};
    eprint!("{msg}");
    let h = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode = 0u32;
    unsafe { GetConsoleMode(h, &mut mode) };
    unsafe { SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT) };
    let mut line = String::new();
    let r = std::io::stdin().read_line(&mut line);
    unsafe { SetConsoleMode(h, mode) };
    eprintln!();
    r.map(|_| line)
}

/// Run the agent's checks (`oarbank-agent check --json`), relaying each row; Ok: the result's detail.
fn run_check(code: Option<&str>, coordinator: Option<&str>, out: &mut Out) -> Result<Value, Fail> {
    let agent = agent_bin().map_err(|e| fail("E_LOCAL", e.to_string(), 1))?;
    let mut cmd = Command::new(&agent);
    cmd.arg("check").arg("--json").stdout(Stdio::piped()).stderr(Stdio::inherit());
    match coordinator {
        Some(url) if code.is_none() => { cmd.args(["--coordinator", url]); }
        _ => { cmd.arg("--code-stdin").stdin(Stdio::piped()); }
    }
    let mut child = cmd.spawn().map_err(|e| fail("E_LOCAL", format!("starting {}: {e}", agent.display()), 1))?;
    if let (Some(c), Some(mut stdin)) = (code, child.stdin.take()) {
        let _ = stdin.write_all(c.as_bytes());
    }
    let mut result = Value::Null;
    for line in std::io::BufReader::new(child.stdout.take().unwrap()).lines().map_while(|l| l.ok()) {
        let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
        if v.get("row").is_some() {
            out.row(&v);
        } else if v.get("result").is_some() {
            result = v;
        }
    }
    let _ = child.wait();
    if result["result"] == "ok" {
        Ok(result["detail"].clone())
    } else {
        let c = result["code"].as_str().unwrap_or("E_LOCAL");
        Err(fail(c, result["message"].as_str().unwrap_or("the checks did not finish"), exit_for(c)))
    }
}

pub fn main(explicit_home: Option<&Path>, rest: &[String]) -> Result<i32> {
    let o = Opts { rest: rest.to_vec() };
    let mut out = Out { json: o.has("--json"), progress: None };
    if let Some(p) = o.val("--progress-file") {
        out.progress = Some(std::fs::OpenOptions::new().create(true).append(true).open(&p).with_context(|| format!("opening {p}"))?);
    }
    match rest.first().map(String::as_str) {
        Some("join") => Ok(join(explicit_home, &o, &mut out)),
        Some("check") => {
            let r = (|| {
                let coordinator = o.val("--coordinator");
                let code = if coordinator.is_some() && !o.has("--code-stdin") && o.val("--code-file").is_none() { None } else { Some(read_code(&o)?) };
                run_check(code.as_deref(), coordinator.as_deref(), &mut out).map(|d| json!({"message": "All checks passed.", "check": d}))
            })();
            Ok(out.done(r))
        }
        Some("status") => status(explicit_home, &o),
        Some("leave") => Ok({
            let r = leave(explicit_home);
            out.done(r)
        }),
        Some("doctor") => doctor(explicit_home, &o),
        Some("policy-apply") => policy_apply(explicit_home),
        _ => {
            eprintln!("{USAGE}");
            Ok(2)
        }
    }
}

fn join(explicit_home: Option<&Path>, o: &Opts, out: &mut Out) -> i32 {
    let r = join_inner(explicit_home, o, out);
    out.done(r)
}

fn join_inner(explicit_home: Option<&Path>, o: &Opts, out: &mut Out) -> Result<Value, Fail> {
    let coordinator = o.val("--coordinator");
    let code = if coordinator.is_some() { None } else { Some(read_code(o)?) };
    let decoded = code.as_deref().map(oarbank_core::joincode::decode).transpose()
        .map_err(|e| fail("E_CODE_FORMAT", e.to_string(), 2))?;
    let scope = default_scope(o, decoded.as_ref().is_some_and(|c| c.system()));
    if scope == "system" && !setup::privileged() {
        return Err(fail("E_PRIVILEGE", if cfg!(windows) { "Joining needs an administrator: run it from an elevated prompt." }
                                        else { "Joining as a system service needs root: run it with sudo." }, 8));
    }
    let home = setup::scope_home(&scope, explicit_home).map_err(|e| fail("E_LOCAL", e.to_string(), 1))?;
    // a node that has joined: the same coordinator again is done (configuration management re-runs), another needs
    // --force, which leaves only after the new coordinator passed its checks
    let current = joined_to(&home);
    if let Some(cur) = &current {
        let cur = cur.trim_end_matches('/');
        let same = decoded.as_ref().map(|c| c.urls.iter().any(|u| u.trim_end_matches('/') == cur)).unwrap_or(false)
            || coordinator.as_deref().is_some_and(|u| u.trim_end_matches('/') == cur);
        if same && !o.has("--force") {
            return Ok(json!({"message": format!("This machine has already joined {cur}."), "coordinator": cur, "already": true}));
        }
        if !o.has("--force") {
            return Err(fail("E_ALREADY_JOINED", format!("This machine belongs to {cur}. Leave that fleet first (oarbank-node leave), or join with --force."), 7));
        }
    }
    // the offline checks and the network checks, before anything is written
    let detail = run_check(code.as_deref(), coordinator.as_deref(), out)?;
    if let Some(cur) = &current {
        leave_scope(explicit_home, &scope).map_err(|e| fail("E_LOCAL", format!("leaving {cur}: {e:#}"), 1))?;
    }
    // device code: the person compares the fingerprint with the console before anything is sent
    if code.is_none() && std::io::stdin().is_terminal() && !o.has("--no-input") && !o.has("--json") {
        println!("Coordinator certificate authority: sha256:{}…\nCheck that the console (Fleet, Add machine) shows the same fingerprint.",
                 detail["fingerprint"].as_str().unwrap_or("?"));
        print!("Continue? [y/N] ");
        let _ = std::io::stdout().flush();
        let mut a = String::new();
        let _ = std::io::stdin().read_line(&mut a);
        if !a.trim().eq_ignore_ascii_case("y") {
            return Err(fail("E_CANCELLED", "Cancelled.", 1));
        }
    }
    // Windows: container jobs need WSL components, installed now while elevated
    let containers = o.has("--containers") || (detail["containers"] == true && !o.has("--no-containers"));
    let mut restart = false;
    if cfg!(windows) && containers {
        if let Ok(agent) = agent_bin() {
            out.state(&json!({"state": "containers"}), "  ...   containers  installing the WSL components container jobs need");
            restart = Command::new(agent).args(["containers", "install"]).status().map(|s| s.code() == Some(3010)).unwrap_or(false);
        }
    }
    let since = now();
    run_setup(explicit_home, &scope, code.as_deref(), coordinator.as_deref(), o.val("--name").as_deref())?;
    if o.has("--no-wait") {
        return Ok(json!({"message": "The code is staged; the service joins in a moment. Follow it with: oarbank-node status --follow",
                         "staged": true, "restart": restart}));
    }
    let wait_s: u64 = o.val("--wait").and_then(|w| w.parse().ok()).unwrap_or(180);
    follow(&home, since, Duration::from_secs(wait_s), out, restart)
}

/// The install plan in a child process (`setup --join-code-stdin`): its own output (paths, the service manager's
/// commands) is detail a person running `join` does not need, and would break `--json`.
fn run_setup(explicit_home: Option<&Path>, scope: &str, code: Option<&str>, coordinator: Option<&str>, name: Option<&str>) -> Result<(), Fail> {
    let me = std::env::current_exe().map_err(|e| fail("E_LOCAL", e.to_string(), 1))?;
    let mut cmd = Command::new(me);
    if let Some(h) = explicit_home {
        cmd.arg("--home").arg(h);
    }
    cmd.args(["setup", "--scope", scope]);
    if code.is_some() {
        cmd.arg("--join-code-stdin");
    }
    if let Some(u) = coordinator {
        cmd.args(["--coordinator", u]);
    }
    if let Some(n) = name {
        cmd.args(["--name", n]);
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn()
        .map_err(|e| fail("E_LOCAL", e.to_string(), 1))?;
    if let (Some(c), Some(mut stdin)) = (code, child.stdin.take()) {
        let _ = stdin.write_all(c.as_bytes());
    }
    let o = child.wait_with_output().map_err(|e| fail("E_LOCAL", e.to_string(), 1))?;
    if !o.status.success() {
        return Err(fail("E_LOCAL", format!("installing the service failed: {}", String::from_utf8_lossy(&o.stderr).trim()), 1));
    }
    Ok(())
}

/// Follow the status document from `since` until joined (Ok), a final error, or `wait` (pending: exit 3).
fn follow(home: &Path, since: f64, wait: Duration, out: &mut Out, restart: bool) -> Result<Value, Fail> {
    let started = Instant::now();
    let mut last = String::new();
    loop {
        let st = read_status(home);
        let fresh = st["updated_at"].as_f64().is_some_and(|t| t >= since - 1.0);
        let state = if fresh { st["state"].as_str().unwrap_or("") } else { "" };
        if !state.is_empty() && state != last {
            let text = match state {
                "joining" => format!("  ...   joining   {}", st["coordinator"].as_str().unwrap_or("")),
                "pending" => {
                    let mut t = format!("  ...   approval  waiting: ask an admin to approve this machine on the console's Fleet page (key {})",
                                        st["key_fingerprint"].as_str().unwrap_or("?"));
                    if let Some(c) = st["user_code"].as_str() {
                        t += &format!("\n                  its code: {c} (Fleet, Approve a machine by its code)");
                    }
                    t
                }
                _ => String::new(),
            };
            out.state(&st, &text);
            last = state.to_string();
        }
        match state {
            "joined" | "connected" => {
                let mut m = format!("Joined {} as {}. Follow it with: oarbank-node status --follow",
                                    st["coordinator"].as_str().unwrap_or(""), st["node_id"].as_str().unwrap_or("?"));
                if restart {
                    m += "\nRestart Windows to finish installing container support.";
                }
                return Ok(json!({"message": m, "status": st, "restart": restart}));
            }
            "error" if st["retrying"] != true => {
                let c = st["error"]["code"].as_str().unwrap_or("E_LOCAL");
                return Err(fail(c, st["error"]["message"].as_str().unwrap_or("joining failed"), exit_for(c)));
            }
            _ => {}
        }
        if started.elapsed() > wait {
            return if state == "pending" {
                Err(fail("E_PENDING", "Still waiting for approval; the node joins as soon as an admin approves it.", 3))
            } else {
                let c = st["error"]["code"].as_str().unwrap_or("E_TCP");
                Err(fail(c, st["error"]["message"].as_str().unwrap_or("The service has not joined yet; it keeps trying. Check: oarbank-node status"), 6))
            };
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn homes(explicit_home: Option<&Path>) -> Vec<(String, PathBuf)> {
    let scopes: &[&str] = if cfg!(target_os = "macos") { &["system", "personal"] } else { &["system"] };
    scopes.iter().filter_map(|s| setup::scope_home(s, explicit_home).ok().map(|h| (s.to_string(), h))).collect()
}

fn status(explicit_home: Option<&Path>, o: &Opts) -> Result<i32> {
    let mut last = String::new();
    loop {
        let found: Vec<(String, Value)> = homes(explicit_home).into_iter().map(|(s, h)| (s, read_status(&h)))
            .filter(|(_, v)| !v.is_null()).collect();
        let (scope, st) = found.into_iter().next().unwrap_or(("".into(), json!({"state": "not installed"})));
        let text = if o.has("--json") { json!({"scope": scope, "status": st}).to_string() } else { describe(&scope, &st) };
        if text != last {
            println!("{text}");
            last = text;
        }
        if !o.has("--follow") {
            return Ok(match st["state"].as_str() { Some("joined" | "connected") => 0, Some("pending") => 3, Some("error") => 1, _ => 1 });
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn describe(scope: &str, st: &Value) -> String {
    let s = |k: &str| st[k].as_str().unwrap_or("").to_string();
    let mut t = match s("state").as_str() {
        "connected" => format!("Connected to {} as {}", s("coordinator"), s("node_id")),
        "joined" => format!("Joined {} as {} (connecting)", s("coordinator"), s("node_id")),
        "offline" => format!("Joined {} as {}, but offline", s("coordinator"), s("node_id")),
        "pending" => format!("Waiting for approval on {} (key {}{})", s("coordinator"), s("key_fingerprint"),
                             st["user_code"].as_str().map(|c| format!(", machine code {c}")).unwrap_or_default()),
        "joining" => format!("Joining {}", s("coordinator")),
        "unjoined" => "Installed, not joined. Join with: sudo oarbank-node join".to_string(),
        "error" => "Joining failed".to_string(),
        other => other.to_string(),
    };
    if let Some(e) = st["error"].as_object() {
        t += &format!("\n  {} ({})", e.get("message").and_then(Value::as_str).unwrap_or(""), e.get("code").and_then(Value::as_str).unwrap_or(""));
    }
    if !scope.is_empty() && cfg!(target_os = "macos") {
        t += &format!("\n  scope: {}", if scope == "system" { "system service" } else { "this user" });
    }
    if let Some(m) = st["managed_by"].as_str() {
        t += &format!("\n  managed by {m}");
    }
    t
}

/// Forget the coordinator: the service stops and the node's identity, caches and logs go. Linux and Windows then start
/// the waiting service again, as the package left it; macOS chooses its scope at the next join.
fn leave(explicit_home: Option<&Path>) -> Result<Value, Fail> {
    let scope = installed_scope().unwrap_or_else(|| "system".into());
    if scope == "system" && !setup::privileged() {
        return Err(fail("E_PRIVILEGE", "Leaving needs root (sudo) or an administrator.", 8));
    }
    leave_scope(explicit_home, &scope).map_err(|e| fail("E_LOCAL", format!("{e:#}"), 1))?;
    Ok(json!({"message": "This machine left its fleet. Join again with: sudo oarbank-node join"}))
}

fn leave_scope(explicit_home: Option<&Path>, scope: &str) -> Result<()> {
    let home = setup::scope_home(scope, explicit_home)?;
    let status = setup::status_file(&home);
    let _ = setup::remove(explicit_home, &["remove".into(), "--scope".into(), scope.into(), "--purge".into()]);
    if let Some(d) = status.parent() {
        let _ = std::fs::remove_file(d.join("joined"));
    }
    let _ = std::fs::write(&status, serde_json::to_vec_pretty(&json!({"format": 1, "state": "unjoined", "updated_at": now()}))?);
    if !cfg!(target_os = "macos") {
        setup::setup_with(explicit_home, &SetupOpts { scope: scope.into(), ..Default::default() })?;
    }
    Ok(())
}

fn doctor(explicit_home: Option<&Path>, o: &Opts) -> Result<i32> {
    let mut report = json!({});
    let mut ok = true;
    for (scope, home) in homes(explicit_home) {
        let st = read_status(&home);
        if st.is_null() {
            continue;
        }
        report["scope"] = json!(scope);
        report["status"] = st.clone();
        if let Some(url) = st["coordinator"].as_str() {
            let mut rows = vec![];
            let agent = agent_bin()?;
            let o2 = Command::new(&agent).args(["check", "--json", "--coordinator", url]).output();
            if let Ok(o2) = o2 {
                for l in String::from_utf8_lossy(&o2.stdout).lines() {
                    if let Ok(v) = serde_json::from_str::<Value>(l) {
                        if v.get("row").is_some() {
                            rows.push(v);
                        } else if v["result"] != "ok" && v.get("result").is_some() {
                            ok = false;
                            report["check_error"] = v;
                        }
                    }
                }
            }
            report["checks"] = json!(rows);
        }
        break;
    }
    if let Ok(agent) = agent_bin() {
        if let Ok(c) = Command::new(agent).args(["containers", "doctor"]).output() {
            report["containers"] = serde_json::from_slice(&c.stdout).unwrap_or(Value::Null);
        }
    }
    if o.has("--json") {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", describe(report["scope"].as_str().unwrap_or(""), &report["status"]));
        for r in report["checks"].as_array().cloned().unwrap_or_default() {
            println!("  {:<5} {:<9} {}", if r["ok"] == true { "ok" } else { "FAIL" }, r["row"].as_str().unwrap_or(""), r["detail"].as_str().unwrap_or(""));
        }
        if let Some(c) = report["containers"]["state"].as_str() {
            println!("  containers: {c}");
        }
    }
    Ok(if ok { 0 } else { 1 })
}

/// macOS's managed-policy job (`dev.codonic.oarbank.agent.policy`, run by launchd when the managed-preferences file
/// changes and at boot): join with the profile's code or address unless the node has joined. A code that failed for
/// good is remembered (by its hash) so a profile that stays in place is not retried at every boot.
fn policy_apply(explicit_home: Option<&Path>) -> Result<i32> {
    let agent = agent_bin()?;
    let out = Command::new(&agent).args(["policy"]).output()?;
    let pol: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    let code = pol["JoinCode"].as_str().map(str::trim).filter(|c| !c.is_empty()).map(str::to_string);
    let coordinator = pol["Coordinator"].as_str().map(str::trim).filter(|c| !c.is_empty()).map(str::to_string);
    if code.is_none() && coordinator.is_none() {
        return Ok(0);
    }
    let home = setup::scope_home("system", explicit_home)?;
    if homes(explicit_home).iter().any(|(_, h)| joined_to(h).is_some()) {
        return Ok(0);
    }
    let marker = setup::status_file(&home).with_file_name("policy-failed");
    let digest = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(code.clone().or(coordinator.clone()).unwrap_or_default().as_bytes()))
    };
    if std::fs::read_to_string(&marker).map(|m| m.trim() == digest).unwrap_or(false) {
        return Ok(0);
    }
    let mut out = Out { json: true, progress: None };
    let mut rest: Vec<String> = vec!["join".into(), "--scope".into(), "system".into(), "--no-input".into(), "--no-wait".into()];
    if let Some(u) = &coordinator {
        if code.is_none() {
            rest.extend(["--coordinator".into(), u.clone()]);
        }
    }
    if let Some(n) = pol["Name"].as_str() {
        rest.extend(["--name".into(), n.into()]);
    }
    let o = Opts { rest };
    let r = match &code {
        Some(c) => {
            let dir = std::env::temp_dir().join(format!("oarbank-policy-{}", std::process::id()));
            std::fs::create_dir_all(&dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            }
            let f = dir.join("code");
            std::fs::write(&f, c)?;
            let mut o2 = Opts { rest: o.rest.clone() };
            o2.rest.extend(["--code-file".into(), f.display().to_string()]);
            let r = join(explicit_home, &o2, &mut out);
            let _ = std::fs::remove_dir_all(&dir);
            r
        }
        None => join(explicit_home, &o, &mut out),
    };
    if matches!(r, 2 | 4 | 5) {
        let _ = std::fs::create_dir_all(marker.parent().unwrap());
        let _ = std::fs::write(&marker, &digest);
    }
    Ok(r)
}
