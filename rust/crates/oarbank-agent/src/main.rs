//! oarbank-agent: the Oarbank node agent.

mod agent;
mod api;
mod broker;
#[cfg(target_os = "linux")]
mod cgroup;
mod check;
mod checkpoints;
mod clock;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod colima;
mod config;
mod container_runtime;
mod coordinstall;
mod discover;
mod doctor;
mod endpoints;
mod facts;
mod folders;
mod fsutil;
mod gpuapi;
mod host;
mod identity;
mod imageset;
mod jobs;
mod join;
mod keys;
mod moves;
mod outbox;
mod paths;
mod policy;
mod procs;
mod prot;
mod proxy;
mod release;
mod rescue;
mod runtime;
mod sandbox;
#[cfg(target_os = "linux")]
mod sandbox_linux;
#[cfg(windows)]
mod sandbox_windows;
#[cfg(target_os = "macos")]
mod seatbelt;
mod selfupdate;
mod services;
mod signing;
mod staging;
mod status;
mod sys;
mod tls;
mod tuf;
#[cfg_attr(not(windows), allow(dead_code))]
mod wslc;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// A test's scratch directory: a fresh name under the system's temporary directory (one named after the process alone
/// can be a dead process's, with its files, once Windows reuses the id), removed when dropped.
#[cfg(test)]
pub fn scratch(tag: &str) -> tempfile::TempDir {
    tempfile::Builder::new().prefix(&format!("oarbank-{tag}-")).tempdir().unwrap()
}

/// The agent's version: the crate's, unless a build sets OARBANK_AGENT_VERSION (release builds of one source tree with
/// distinct versions, and the update tests).
pub const VERSION: &str = match option_env!("OARBANK_AGENT_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// The marker the coordinator reads from an uploaded build instead of running it (docs/protocol.md, "Agent
/// self-update"): `oarbank-agent-version:<semver>`, NUL-terminated.
#[used]
#[unsafe(no_mangle)]
pub static OARBANK_AGENT_VERSION_MARK: [u8; agent_mark_len()] = agent_mark();

const fn agent_mark_len() -> usize {
    "oarbank-agent-version:".len() + VERSION.len() + 1
}

const fn agent_mark() -> [u8; agent_mark_len()] {
    let mut out = [0u8; agent_mark_len()];
    let a = "oarbank-agent-version:".as_bytes();
    let b = VERSION.as_bytes();
    let mut i = 0;
    while i < a.len() {
        out[i] = a[i];
        i += 1;
    }
    let mut j = 0;
    while j < b.len() {
        out[a.len() + j] = b[j];
        j += 1;
    }
    out
}

#[derive(Parser)]
#[command(name = "oarbank-agent", version = VERSION, about = "The Oarbank node agent")]
struct Cli {
    /// The agent's state directory (default: the platform's application data directory).
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the agent: join or enroll if needed, then keep a session with the coordinator. Started with nothing to join
    /// with, it waits (status `unjoined`) for a staged code (`--join-file`) or, with `--policy`, managed policy.
    Run {
        /// The coordinator's agent URL, https://<host>:7443 (stored in agent.json), or `discover`: the one coordinator
        /// announcing itself on the local network. Without a code the owner approves the node (by its device code).
        #[arg(long)]
        coordinator: Option<String>,
        /// A join code (development and tests; installers stage a file instead, so the code is in no service
        /// definition and on no command line).
        #[arg(long, hide = true)]
        join: Option<String>,
        /// Where a join code is staged (`oarbank-node join`, installers): used while this node has not joined, then
        /// deleted.
        #[arg(long)]
        join_file: Option<PathBuf>,
        /// The status document to keep (node-enrollment.md): readable by everyone, no secrets.
        #[arg(long)]
        status_file: Option<PathBuf>,
        /// Read managed policy (MDM profile, Group Policy, /etc/oarbank/policy.json) while not joined.
        #[arg(long)]
        policy: bool,
        /// The name this node asks for when its code has no label.
        #[arg(long)]
        name: Option<String>,
        /// Serve session helpers, which tell host protection what this service's account may not read about the
        /// people using the machine (system installs).
        #[arg(long)]
        session_hub: bool,
    },
    /// Check a join code, or a coordinator address, without joining: the code's format and expiry, DNS, TCP, the
    /// coordinator's identity and TLS certificate authority, the clock. Nothing secret is sent and nothing is written.
    Check {
        /// A file holding the join code.
        #[arg(long)]
        code_file: Option<PathBuf>,
        /// Read the join code from standard input.
        #[arg(long)]
        code_stdin: bool,
        /// Check a coordinator address instead of a code (joining by address: prints the fingerprints to compare).
        #[arg(long)]
        coordinator: Option<String>,
        /// One JSON object per line: each check, then the result.
        #[arg(long)]
        json: bool,
    },
    /// Report this person's session to the system agent's host protection: their processes' paths and arguments,
    /// their front window and last input (each person's session runs one; system installs start it).
    #[command(name = "session-helper")]
    SessionHelper,
    /// Enroll and wait for the owner's approval, then exit.
    Enroll {
        #[arg(long)]
        coordinator: Option<String>,
        /// Give up after this many seconds.
        #[arg(long)]
        wait: Option<u64>,
    },
    /// Print this node's facts as JSON.
    Facts,
    /// Print the GPU APIs this node provides, on the host and in its containers, with what was found for each (the
    /// doctor report's `gpu_apis`), as JSON.
    #[command(name = "gpu-apis")]
    GpuApis,
    /// List coordinators announcing themselves on the local network (a hint: enrolling still needs the owner's approval).
    Discover {
        /// Seconds to listen.
        #[arg(long, default_value_t = 3.0)]
        wait: f64,
    },
    /// Run host protection locally for a few ticks and print the capacity, telemetry and guard.
    Status,
    /// This node's container runtime: its report (facts `containers`), what is missing and how to fix it.
    Containers {
        #[command(subcommand)]
        action: ContainersCmd,
    },
    /// The managed policy in force, as JSON (`oarbank-node policy-apply`; node-enrollment.md, "Managed policy keys").
    #[command(hide = true)]
    Policy,
    /// This node's sandbox backend and what it enforces, as JSON (the coordinator asks it on Linux and Windows).
    #[command(name = "sandbox-status", hide = true)]
    SandboxStatus,
    /// Apply a sandbox profile to this process, then exec argv (internal: how module processes start).
    #[command(name = "sandbox-exec", hide = true)]
    SandboxExec {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ContainersCmd {
    /// Print the runtime's report: exit 0 when it can run containers, 3 when something is missing (each with its fix).
    Doctor {
        /// Also run real containers through the runtime: mount, limits, no network, cleanup.
        #[arg(long)]
        probe: bool,
        /// With --probe: also run a container with every GPU (`gpus = "all"`).
        #[arg(long)]
        gpu: bool,
    },
    /// Windows: install the WSL components the runtime needs (an administrator; exit 3010 when Windows must restart,
    /// 1618 while another Windows Installer installation runs: the WSL package is one, and never goes inside another).
    Install {
        /// Wait up to this many seconds for another installation to finish (default: exit 1618 at once).
        #[arg(long, default_value_t = 0)]
        wait: u64,
    },
    /// Windows: end the agent's WSL containers session and delete its storage (the WSL package stays).
    Remove,
}

/// `oarbank-agent containers ...`.
fn containers(layout: &paths::Layout, action: ContainersCmd) -> anyhow::Result<()> {
    match action {
        ContainersCmd::Doctor { probe, gpu } => {
            let mut report = facts::collect(&layout.home)["containers"].clone();
            #[cfg(windows)]
            {
                // the prerequisites as they are now, beside the running agent's last report
                let now = wslc::check();
                if !now.is_empty() {
                    report["missing"] = serde_json::json!(now.iter().map(wslc::Missing::json).collect::<Vec<_>>());
                    report["state"] = serde_json::json!("missing");
                }
            }
            #[cfg(target_os = "macos")]
            {
                // the prerequisites as they are now (as this account sees them: run it as the agent's account), beside
                // the running agent's last report
                let now = container_runtime::mac_report_now(&layout.home);
                if !now.missing.is_empty() {
                    report["missing"] = serde_json::json!(now.missing.iter().map(colima::Missing::json).collect::<Vec<_>>());
                    report["state"] = serde_json::json!("missing");
                    report["gpu"] = serde_json::json!("undetected");
                }
                report["gpu_profile"]["missing"] = serde_json::json!(now.gpu_missing.iter().map(colima::Missing::json).collect::<Vec<_>>());
            }
            let mut ok = report["missing"].as_array().is_none_or(|m| m.is_empty());
            if probe {
                match container_runtime::for_node(layout) {
                    Some(rt) => {
                        let checks = container_runtime::probe(&rt, &layout.work(), gpu);
                        ok = checks.iter().all(|c| c["ok"] == true);
                        report["probe"] = serde_json::json!(checks);
                        // the probe's own runtime's report (Windows: the session it used) is the current one
                        if let Some(r) = rt.cpu.report() {
                            let checks = report["probe"].take();
                            report = r;
                            report["probe"] = checks;
                        }
                    }
                    None => {
                        ok = false;
                        report["probe"] = serde_json::json!([{"check": "runtime", "ok": false, "detail": "no container runtime on this node"}]);
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
            std::process::exit(if ok { 0 } else { 3 })
        }
        #[cfg(windows)]
        ContainersCmd::Install { wait } => {
            // never inside another installation (an MSI's custom action, Windows Update): Windows Installer runs one
            // installation at a time, and one started inside another breaks both (docs/design/windows-containers.md)
            if !wslc::wait_for_installer(std::time::Duration::from_secs(wait)) {
                eprintln!("another installation is in progress (Windows Installer): run this again when it has finished");
                std::process::exit(wslc::EXIT_INSTALLER_BUSY)
            }
            match wslc::install() {
                Ok(wslc::Installed::Restart) => {
                    println!("installed; restart Windows to finish (the Virtual Machine Platform)");
                    std::process::exit(wslc::EXIT_RESTART)
                }
                Ok(wslc::Installed::Done) => {
                    println!("installed the WSL components");
                    Ok(())
                }
                Ok(wslc::Installed::Nothing) => {
                    println!("nothing to install: the WSL components are in place");
                    Ok(())
                }
                Err(wslc::InstallError::Busy(e)) => {
                    eprintln!("{e}");
                    std::process::exit(wslc::EXIT_INSTALLER_BUSY)
                }
                Err(wslc::InstallError::Failed(e)) => anyhow::bail!(e),
            }
        }
        #[cfg(windows)]
        ContainersCmd::Remove => wslc::remove(&layout.home).map_err(anyhow::Error::msg),
        #[cfg(not(windows))]
        ContainersCmd::Install { .. } | ContainersCmd::Remove => anyhow::bail!("only on Windows: this node's runtime is the host's own"),
    }
}

fn main() -> anyhow::Result<()> {
    // the marker must survive the linker: on ELF `#[used]` does not keep a section from --gc-sections, a reference does
    std::hint::black_box(&OARBANK_AGENT_VERSION_MARK);
    // the sandbox launcher runs before anything else: no logging setup, no runtime, nothing the module could affect
    let raw: Vec<String> = std::env::args().collect();
    if raw.get(1).map(String::as_str) == Some("sandbox-exec") {
        sandbox::exec(&raw[2..]);
    }
    // colour only on a terminal: under a service manager the output goes to a log file or the journal
    tracing_subscriber::fmt().with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout())).with_env_filter(
        tracing_subscriber::EnvFilter::try_from_env("OARBANK_LOG").unwrap_or_else(|_| "info".into())).init();
    let cli = Cli::parse();
    let layout = paths::Layout::new(cli.home.unwrap_or_else(paths::agent_home));
    let rt = tokio::runtime::Runtime::new()?;
    match cli.cmd {
        Cmd::SandboxExec { args } => sandbox::exec(&args),
        Cmd::SandboxStatus => {
            println!("{}", sandbox::report());
            Ok(())
        }
        Cmd::Containers { action } => containers(&layout, action),
        Cmd::Policy => {
            let p = policy::read();
            println!("{}", serde_json::json!({"JoinCode": p.join_code, "Coordinator": p.coordinator, "Scope": p.scope,
                "Containers": p.containers, "Name": p.name, "AllowUserJoin": p.allow_user_join,
                "ManagedByOrganizationName": p.managed_by}));
            Ok(())
        }
        Cmd::Status => rt.block_on(async {
            // a scratch home: opening the live one would point its agent.json at this placeholder coordinator
            let _ = layout;
            let scratch = std::env::temp_dir().join(format!("oarbank-status-{}", std::process::id()));
            let mut a = agent::Agent::open(paths::Layout::new(scratch.clone()), Some("https://127.0.0.1:7443"))?;
            if a.directives.is_null() {
                a.directives = serde_json::json!({"desired_state": "active", "lifecycle": "ready", "policy": {}, "limits": {}});
            }
            for _ in 0..12 {
                a.protect();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            let p = a.prot.as_ref().expect("ticked");
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "capacity": p.capacity.as_ref().map(|c| c.to_json()), "telemetry": p.telemetry,
                "guard_reason": p.last.as_ref().map(|r| r.guard_reason.clone())}))?);
            Ok(())
        }),
        Cmd::Discover { wait } => {
            println!("{}", serde_json::to_string_pretty(&discover::browse(wait).map_err(anyhow::Error::msg)?)?);
            Ok(())
        }
        Cmd::Facts => {
            println!("{}", serde_json::to_string_pretty(&facts::collect(&layout.home))?);
            Ok(())
        }
        Cmd::GpuApis => {
            gpuapi::watchdog(gpuapi::limit());
            let mut r = gpuapi::detect(&layout.home);
            r["platform"] = serde_json::json!(facts::platform_token());
            r["agent_version"] = serde_json::json!(VERSION);
            println!("{}", serde_json::to_string_pretty(&r)?);
            Ok(())
        }
        Cmd::Enroll { coordinator, wait } => rt.block_on(async {
            let mut a = agent::Agent::open(layout, coordinator.as_deref())?;
            a.enroll(std::time::Duration::from_secs(2), wait.map(std::time::Duration::from_secs)).await
        }),
        Cmd::SessionHelper => Err(oarbank_protection::platform::run_session_helper().into()),
        Cmd::Check { code_file, code_stdin, coordinator, json } => {
            let code = read_code(code_file.as_deref(), code_stdin)?;
            let code = rt.block_on(check_cmd(code, coordinator, json));
            std::process::exit(code)
        }
        Cmd::Run { coordinator, join, join_file, status_file, policy, name, session_hub } => rt.block_on(async {
            // cgroups first, while the agent has no children (cgroup.rs)
            #[cfg(target_os = "linux")]
            let _ = cgroup::root();
            // compiled in only when a test build sets it: a version that cannot start, for the rollback tests
            if option_env!("OARBANK_AGENT_TEST_CRASH").is_some() {
                eprintln!("test build: crashing on start");
                std::process::exit(1);
            }
            let code = serve(layout, Serve { coordinator, join, join_file, status_file, policy, name, session_hub }).await?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }),
    }
}

/// A join code from a file or standard input (trimmed), never from the command line.
fn read_code(file: Option<&std::path::Path>, stdin: bool) -> anyhow::Result<Option<String>> {
    if let Some(f) = file {
        return Ok(Some(std::fs::read_to_string(f).map_err(|e| anyhow::anyhow!("reading {}: {e}", f.display()))?.trim().to_string()));
    }
    if stdin {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
        return Ok(Some(s.trim().to_string()));
    }
    Ok(None)
}

/// `oarbank-agent check`: the rows as they finish, then the result; the exit code says which kind of failure.
async fn check_cmd(code: Option<String>, coordinator: Option<String>, as_json: bool) -> i32 {
    use check::{Fail, Row};
    let print_row = move |r: &Row| {
        if as_json {
            println!("{}", r.json());
        } else {
            println!("  {:<5} {:<9} {}", if r.ok { "ok" } else { "FAIL" }, r.id, r.detail);
        }
    };
    let finish = |res: Result<serde_json::Value, Fail>| -> i32 {
        match res {
            Ok(v) => {
                if as_json { println!("{}", serde_json::json!({"result": "ok", "detail": v})); } else { println!("All checks passed."); }
                0
            }
            Err(f) => {
                if as_json {
                    println!("{}", serde_json::json!({"result": "error", "code": f.code, "message": f.message}));
                } else {
                    eprintln!("{} ({})", f.message, f.code);
                }
                f.exit_code()
            }
        }
    };
    let mut emit = |r: Row| print_row(&r);
    match (code, coordinator) {
        (Some(code), _) => {
            let c = match check::offline(&code) {
                Ok(c) => c,
                Err(f) => {
                    print_row(&Row { id: "code", ok: false, detail: f.message.clone() });
                    return finish(Err(f));
                }
            };
            print_row(&check::code_row(&c));
            let mut last = None;
            for url in &c.urls {
                let p = check::probe(url, &c.pins, Some(&c.cik), &mut emit).await;
                match p.fail {
                    None => return finish(Ok(serde_json::json!({"url": p.url, "fingerprint": p.fingerprint,
                        "approve": c.approve(), "system": c.system(), "containers": c.containers(), "multi": c.multi(),
                        "expires_at": c.expires_at, "host": c.host()}))),
                    Some(f) => {
                        let fatal = !f.retryable();
                        last = Some(f);
                        if fatal {
                            break;
                        }
                    }
                }
            }
            finish(Err(last.unwrap_or_else(|| Fail::new("E_TCP", "no address answered"))))
        }
        (None, Some(url)) => {
            let p = check::probe(&url, &[], None, &mut emit).await;
            match p.fail {
                None => finish(Ok(serde_json::json!({"url": p.url, "fingerprint": p.fingerprint,
                    "identity": p.cik.as_deref().map(|k| check::identity_fingerprint(k)[..16].to_string())}))),
                Some(f) => finish(Err(f)),
            }
        }
        (None, None) => finish(Err(Fail::new("E_CODE_FORMAT", "give --code-file, --code-stdin or --coordinator"))),
    }
}

struct Serve {
    coordinator: Option<String>,
    join: Option<String>,
    join_file: Option<PathBuf>,
    status_file: Option<PathBuf>,
    policy: bool,
    name: Option<String>,
    session_hub: bool,
}

/// The agent's life (node-enrollment.md, "The node's states"): with an identity (a certificate, or an enrollment
/// waiting for approval) it keeps its session; otherwise it joins with a staged code or managed policy's code, or
/// enrolls by address, or waits for one of those. A join that ends (a refused code, a declined machine) goes back to
/// waiting, so a new code can be staged without reinstalling anything.
async fn serve(layout: paths::Layout, o: Serve) -> anyhow::Result<i32> {
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = tx.send(true);
    });
    let mut st = status::Status::new(o.status_file.clone());
    let mut join_arg = o.join.clone();
    let mut failed_policy_code: Option<String> = None;
    let coordinator = match o.coordinator.as_deref() {
        Some("discover") => Some(discover_one()?),
        c => c.map(str::to_string),
    };
    loop {
        if *rx.borrow() {
            return Ok(0);
        }
        let pol = if o.policy { policy::read() } else { policy::Policy::default() };
        if st.get("managed_by").and_then(|v| v.as_str()) != pol.managed_by.as_deref() {
            let state = st.state().to_string();
            st.set(if state.is_empty() { status::UNJOINED } else { &state }, serde_json::json!({"managed_by": pol.managed_by}));
        }
        let name = o.name.clone().or(pol.name.clone());
        let cfg = config::Config::load(&layout.config()).ok().flatten();
        let has_identity = keys::have_cert(&layout) || cfg.as_ref().is_some_and(|c| c.enrollment_id.is_some());
        let staged = o.join_file.as_ref().filter(|f| f.exists()).cloned();
        let mut a = if has_identity {
            if let Some(f) = &staged {
                let _ = std::fs::remove_file(f);             // a node that has joined ignores a code (leave first)
            }
            agent::Agent::open(paths::Layout::new(layout.home.clone()), coordinator.as_deref())?
        } else if let Some((code, from_policy)) = join_arg.take().map(|c| (c, false))
            .or_else(|| staged.as_ref().and_then(|f| std::fs::read_to_string(f).ok()).map(|c| (c.trim().to_string(), false)))
            .or_else(|| pol.join_code.clone().filter(|c| failed_policy_code.as_deref() != Some(c.as_str())).map(|c| (c, true))) {
            let r = join::join(&layout, &code, name.as_deref(), staged.as_deref(), &mut st).await;
            if let Err(f) = &r {
                if f.code == join::SUPERSEDED {
                    continue;                                 // the new code is in the file: join with it now
                }
            }
            if let Some(f) = staged.as_ref().filter(|f| std::fs::read_to_string(f).is_ok_and(|s| s.trim() == code.trim())) {
                let _ = std::fs::remove_file(f);
            }
            match r {
                Ok(a) => a,
                Err(f) => {
                    tracing::warn!(code = f.code, "join ended: {}", f.message);
                    if from_policy {
                        failed_policy_code = Some(code);
                    }
                    wait(&rx, 5).await;
                    continue;
                }
            }
        } else if let Some(url) = coordinator.clone().or(pol.coordinator.clone()) {
            let mut a = agent::Agent::open(paths::Layout::new(layout.home.clone()), Some(&url))?;
            a.cfg.name = name.clone();
            a.cfg.save(&layout.config())?;
            st.set(status::JOINING, serde_json::json!({"coordinator": url}));
            a
        } else {
            if !matches!(st.state(), status::UNJOINED | status::ERROR) {
                st.reset(status::UNJOINED);
            }
            wait(&rx, 5).await;
            continue;
        };
        a.status = st.clone();
        a.session_hub = o.session_hub;
        let r = a.run(rx.clone()).await;
        st = a.status.clone();
        match r {
            Ok(code) => return Ok(code),
            Err(e) if e.downcast_ref::<agent::EnrollmentEnded>().is_some() => {
                // back to waiting: this coordinator's trust and the unused key go
                let _ = std::fs::remove_file(layout.config());
                let _ = std::fs::remove_file(layout.node_key());
                wait(&rx, 5).await;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn wait(rx: &tokio::sync::watch::Receiver<bool>, secs: u64) {
    let mut rx = rx.clone();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(secs), rx.changed()).await;
}

/// `--coordinator discover`: exactly one coordinator must be announcing itself.
fn discover_one() -> anyhow::Result<String> {
    let found = discover::browse(4.0).map_err(anyhow::Error::msg)?;
    match found.as_slice() {
        [one] => {
            let url = one["url"].as_str().unwrap_or_default().to_string();
            tracing::warn!(url = %url, fleet = %one["fleet_id"], "found a coordinator on the local network; the owner must approve this node");
            Ok(url)
        }
        [] => anyhow::bail!("no coordinator announces itself on the local network{}: give --coordinator <url> or --join <code>",
                            if cfg!(target_os = "macos") { " (or macOS holds this program's local network requests until a person \
                                allows them: System Settings, Privacy & Security, Local Network)" } else { "" }),
        many => anyhow::bail!("{} coordinators announce themselves here: give --coordinator <url> ({})", many.len(),
                              many.iter().filter_map(|f| f["url"].as_str()).collect::<Vec<_>>().join(", ")),
    }
}

#[cfg(test)]
mod tests {
    /// What a dead process left never reaches a test that runs under its reused process id: a scratch directory is new
    /// and empty even beside the one such a process left under a name made of the tag and the id (as the CDI test's
    /// did, which then read a dead run's nvidia.yaml), and it goes with its guard.
    #[test]
    fn a_scratch_directory_is_new_and_goes_with_its_guard() {
        let left = std::env::temp_dir().join(format!("oarbank-cdi-{}", std::process::id()));
        std::fs::create_dir_all(&left).unwrap();
        std::fs::write(left.join("nvidia.yaml"), "kind: nvidia.com/gpu\n").unwrap();
        let d = super::scratch("cdi");
        let (path, found) = (d.path().to_path_buf(), std::fs::read_dir(d.path()).unwrap().count());
        drop(d);
        let _ = std::fs::remove_dir_all(&left);
        assert_eq!((found, path.exists()), (0, false), "(files found in a new scratch directory, still there once dropped)");
    }
}
