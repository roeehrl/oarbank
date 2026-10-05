//! oarbank-agent: the Oarbank node agent.

mod agent;
mod api;
mod broker;
#[cfg(target_os = "linux")]
mod cgroup;
mod checkpoints;
mod clock;
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
    /// Run the agent: enroll if needed, then keep a session with the coordinator.
    Run {
        /// The coordinator's agent URL, https://<host>:7443 (stored in agent.json), or `discover`: the one coordinator
        /// announcing itself on the local network.
        #[arg(long)]
        coordinator: Option<String>,
        /// A join code from the coordinator's owner (`oarbank join-code`): it names the coordinator and approves this node.
        #[arg(long)]
        join: Option<String>,
        /// A file holding a join code (installers and MDM): used while this node has no certificate, then deleted.
        #[arg(long)]
        join_file: Option<PathBuf>,
        /// Serve session helpers, which tell host protection what this service's account may not read about the
        /// people using the machine (system installs).
        #[arg(long)]
        session_hub: bool,
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
    /// This node's sandbox backend and what it enforces, as JSON (the coordinator asks it on Linux and Windows).
    #[command(name = "sandbox-status", hide = true)]
    SandboxStatus,
    /// Exit 0 when the process started through `sandbox-exec` is confined (internal: the coordinator's check).
    #[command(name = "sandbox-check", hide = true)]
    SandboxCheck { pid: i32 },
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
    /// Windows: install the WSL components the runtime needs (an administrator; exit 3010 when Windows must restart).
    Install,
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
        ContainersCmd::Install => match wslc::install() {
            Ok(true) => {
                println!("installed; restart Windows to finish (the Virtual Machine Platform)");
                std::process::exit(3010)
            }
            Ok(false) => {
                println!("nothing to install");
                Ok(())
            }
            Err(e) => anyhow::bail!(e),
        },
        #[cfg(windows)]
        ContainersCmd::Remove => wslc::remove(&layout.home).map_err(anyhow::Error::msg),
        #[cfg(not(windows))]
        ContainersCmd::Install | ContainersCmd::Remove => anyhow::bail!("only on Windows: this node's runtime is the host's own"),
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
        Cmd::SandboxCheck { pid } => std::process::exit(if sandbox::is_confined(pid) { 0 } else { 1 }),
        Cmd::Status => rt.block_on(async {
            let mut a = agent::Agent::open(layout, Some("https://127.0.0.1:7443"))?;
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
            println!("{}", serde_json::to_string_pretty(&discover::browse(wait))?);
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
        Cmd::Run { coordinator, mut join, join_file, session_hub } => rt.block_on(async {
            // cgroups first, while the agent has no children (cgroup.rs)
            #[cfg(target_os = "linux")]
            let _ = cgroup::root();
            // compiled in only when a test build sets it: a version that cannot start, for the rollback tests
            if option_env!("OARBANK_AGENT_TEST_CRASH").is_some() {
                eprintln!("test build: crashing on start");
                std::process::exit(1);
            }
            // the join secret never sits in a service definition: it is read from a file, kept in agent.json until the
            // enrollment uses it, and the file is removed
            let mut consumed = None;
            if let Some(f) = join_file.filter(|f| f.exists()) {
                if join.is_none() && !keys::have_cert(&layout) {
                    join = Some(std::fs::read_to_string(&f)?.trim().to_string());
                }
                consumed = Some(f);
            }
            let coordinator = match coordinator.as_deref() {
                Some("discover") => Some(discover_one()?),
                c => c.map(str::to_string),
            };
            let mut a = match &join {
                Some(code) => agent::Agent::open_with_join(layout, code).await?,
                None => agent::Agent::open(layout, coordinator.as_deref())?,
            };
            if let Some(f) = consumed {
                let _ = std::fs::remove_file(f);
            }
            a.session_hub = session_hub;
            let (tx, rx) = tokio::sync::watch::channel(false);
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = tx.send(true);
            });
            let code = a.run(rx).await?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }),
    }
}

/// `--coordinator discover`: exactly one coordinator must be announcing itself.
fn discover_one() -> anyhow::Result<String> {
    let found = discover::browse(4.0);
    match found.as_slice() {
        [one] => {
            let url = one["url"].as_str().unwrap_or_default().to_string();
            tracing::warn!(url = %url, fleet = %one["fleet_id"], "found a coordinator on the local network; the owner must approve this node");
            Ok(url)
        }
        [] => anyhow::bail!("no coordinator announces itself on the local network: give --coordinator <url> or --join <code>"),
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
