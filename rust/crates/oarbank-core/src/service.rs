//! Service definitions for the platforms' service managers (docs/design/architecture.md, "Host interfaces"): pure
//! rendering, no OS calls. launchd property lists (macOS), systemd units (Linux), and the `sc.exe create` arguments of
//! a Windows service.

/// A long-running service: what to run, as whom, with which environment and logs.
#[derive(Debug, Clone, Default)]
pub struct ServiceSpec {
    pub label: String,
    pub program: Vec<String>,
    pub env: Vec<(String, String)>,
    pub working_dir: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    /// System scope only: the account the service runs as (launchd `UserName`).
    pub user: Option<String>,
    pub keep_alive: bool,
    /// Without `keep_alive`: restart only after a failed exit (a clean exit 0 stays stopped).
    pub restart_on_failure: bool,
    /// macOS: the bundle identifier of the app this job belongs to (launchd `AssociatedBundleIdentifiers`). System
    /// Settings, Login Items, "Allow in the Background" then lists the job under that app's name and icon (Oarbank Node,
    /// Oarbank Coordinator) instead of the signing team's name, so whoever switches it off sees what stops.
    pub associated_bundle: Option<String>,
    /// How long the service manager waits for the service to stop after asking it to (SIGTERM) before it kills it:
    /// launchd `ExitTimeOut`, systemd `TimeoutStopSec` (their defaults, 20 s and 90 s, otherwise).
    pub stop_timeout_s: Option<u32>,
}

/// The agent's stop timeout: on a stop the agent stops its jobs' runners (checkpointing first where they can), releases
/// their attempts and stops what it must of the services (agent.rs `stop_jobs`, at most about 25 s for the runners and
/// their reports), and must not be killed meanwhile, or a runner outlives it until its watchdog or its next start ends
/// it. The Windows launcher waits as long for the agent before it ends it.
pub const AGENT_STOP_TIMEOUT_S: u32 = 60;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// A launchd property list. Jobs run at the default QoS (`ProcessType` Standard): Background QoS made module tools
/// many times slower.
pub fn launchd_plist(s: &ServiceSpec) -> String {
    launchd_plist_with(s, "")
}

/// The LaunchAgent that runs the session helper in every GUI login (`LimitLoadToSessionType` Aqua), installed in
/// /Library/LaunchAgents by a system install: `agent` is the agent binary installed beside the launcher (root's,
/// never the service account's current version). `associated_bundle`: the app it belongs to in Login Items.
pub fn session_helper_plist(label: &str, agent: &str, associated_bundle: Option<&str>) -> String {
    let spec = ServiceSpec { label: label.into(), program: vec![agent.into(), "session-helper".into()], keep_alive: true,
                             associated_bundle: associated_bundle.map(str::to_string), ..Default::default() };
    launchd_plist_with(&spec, "  <key>LimitLoadToSessionType</key><string>Aqua</string>\n")
}

fn launchd_plist_with(s: &ServiceSpec, extra: &str) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
        \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n");
    out += &format!("  <key>Label</key><string>{}</string>\n", esc(&s.label));
    out += "  <key>ProgramArguments</key><array>\n";
    for a in &s.program {
        out += &format!("    <string>{}</string>\n", esc(a));
    }
    out += "  </array>\n";
    if !s.env.is_empty() {
        out += "  <key>EnvironmentVariables</key><dict>\n";
        for (k, v) in &s.env {
            out += &format!("    <key>{}</key><string>{}</string>\n", esc(k), esc(v));
        }
        out += "  </dict>\n";
    }
    if let Some(d) = &s.working_dir {
        out += &format!("  <key>WorkingDirectory</key><string>{}</string>\n", esc(d));
    }
    if let Some(p) = &s.stdout {
        out += &format!("  <key>StandardOutPath</key><string>{}</string>\n", esc(p));
    }
    if let Some(p) = &s.stderr {
        out += &format!("  <key>StandardErrorPath</key><string>{}</string>\n", esc(p));
    }
    if let Some(u) = &s.user {
        out += &format!("  <key>UserName</key><string>{}</string>\n", esc(u));
    }
    out += "  <key>RunAtLoad</key><true/>\n";
    out += &format!("  <key>KeepAlive</key>{}\n", if s.keep_alive { "<true/>" } else if s.restart_on_failure {
        "<dict><key>SuccessfulExit</key><false/></dict>" } else { "<false/>" });
    out += "  <key>ThrottleInterval</key><integer>10</integer>\n";
    if let Some(t) = s.stop_timeout_s {
        out += &format!("  <key>ExitTimeOut</key><integer>{t}</integer>\n");
    }
    out += "  <key>ProcessType</key><string>Standard</string>\n";
    if let Some(b) = &s.associated_bundle {
        out += &format!("  <key>AssociatedBundleIdentifiers</key><array><string>{}</string></array>\n", esc(b));
    }
    out += extra;
    out += "</dict></plist>\n";
    out
}

/// systemd's quoting: an argument in double quotes, with \ and " escaped and % doubled.
fn systemd_quote(a: &str) -> String {
    format!("\"{}\"", a.replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%"))
}

/// A systemd unit. The launcher handles exit 75 itself, so the unit restarts on any exit; `Delegate=yes` lets the
/// agent manage its jobs' cgroups. A system unit run as an account gets the runtime directory `/run/oarbank`,
/// readable by everyone, where the agent serves the people's session helpers.
pub fn systemd_unit(s: &ServiceSpec, description: &str, system: bool) -> String {
    let mut out = format!("[Unit]\nDescription={description}\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\n");
    out += &format!("ExecStart={}\n", s.program.iter().map(|a| systemd_quote(a)).collect::<Vec<_>>().join(" "));
    for (k, v) in &s.env {
        out += &format!("Environment={}\n", systemd_quote(&format!("{k}={v}")));
    }
    if let Some(d) = &s.working_dir {
        out += &format!("WorkingDirectory={d}\n");             // a path setting: taken literally, no quoting
    }
    if let (true, Some(u)) = (system, &s.user) {
        out += &format!("User={u}\nGroup={u}\nRuntimeDirectory=oarbank\nRuntimeDirectoryMode=0755\n");
    }
    out += if s.keep_alive { "Restart=always\n" } else if s.restart_on_failure { "Restart=on-failure\n" } else { "Restart=no\n" };
    out += "RestartSec=10\nKillMode=mixed\nDelegate=yes\n";
    if let Some(t) = s.stop_timeout_s {
        out += &format!("TimeoutStopSec={t}\n");
    }
    out += "\n[Install]\n";
    out += if system { "WantedBy=multi-user.target\n" } else { "WantedBy=default.target\n" };
    out
}

/// The systemd user unit that runs the session helper in every person's user manager (enabled with
/// `systemctl --global`): `agent` is the agent binary installed beside the launcher (root's, never the service
/// account's), and the service's own account runs none.
pub fn session_helper_unit(agent: &str, account: &str) -> String {
    format!("[Unit]\nDescription=Oarbank session helper (tells the Oarbank agent's host protection about this session)\n\
             ConditionUser=!{account}\n\n[Service]\nExecStart={} \"session-helper\"\nRestart=always\nRestartSec=10\n\n\
             [Install]\nWantedBy=default.target\n", systemd_quote(agent))
}

/// `sc.exe create` arguments for a Windows service whose binary path is `program` (quoted per the Windows rules),
/// started automatically (delayed) as `account` (a virtual account such as `NT SERVICE\\<name>` by default).
pub fn sc_create_args(name: &str, display: &str, program: &[String], account: Option<&str>) -> Vec<String> {
    let quote = |a: &str| if a.is_empty() || a.contains([' ', '\t', '"']) { format!("\"{}\"", a.replace('"', "\\\"")) } else { a.to_string() };
    let bin = program.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ");
    let obj = account.map(str::to_string).unwrap_or_else(|| format!("NT SERVICE\\{name}"));
    vec!["create".into(), name.into(), "binPath=".into(), bin, "start=".into(), "delayed-auto".into(), "obj=".into(), obj,
         "DisplayName=".into(), display.into()]
}

/// `icacls` arguments that give a system service's home to the service's virtual account (`NT SERVICE\\<name>`, which
/// exists once the service does) and otherwise only to Administrators and SYSTEM, named by SID so any display language
/// works: inheritance from ProgramData (which lets every user read, and create files) is removed.
/// The status directory (node-enrollment.md): the service may write it; everyone keeps reading it (inherited).
pub fn icacls_status_args(name: &str, dir: &str) -> Vec<String> {
    vec![dir.into(), "/grant".into(), format!("NT SERVICE\\{name}:(OI)(CI)M")]
}

pub fn icacls_home_args(name: &str, home: &str) -> Vec<String> {
    vec![home.into(), "/inheritance:r".into(), "/grant:r".into(), format!("NT SERVICE\\{name}:(OI)(CI)F"),
         "/grant:r".into(), "*S-1-5-32-544:(OI)(CI)F".into(), "/grant:r".into(), "*S-1-5-18:(OI)(CI)F".into()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_an_escaped_launchd_job() {
        let p = launchd_plist(&ServiceSpec { label: "dev.codonic.oarbank.agent".into(),
            program: vec!["/x/oarbank-launcher".into(), "--home".into(), "/a b/<home>".into(), "run".into()],
            env: vec![("OARBANK_LOG".into(), "info".into())], keep_alive: true, ..Default::default() });
        assert!(p.contains("<string>/a b/&lt;home&gt;</string>") && p.contains("<key>KeepAlive</key><true/>"));
        assert!(p.contains("<key>ProcessType</key><string>Standard</string>") && !p.contains("UserName"));
        assert!(!p.contains("AssociatedBundleIdentifiers") && !p.contains("ExitTimeOut"));
        let stops = launchd_plist(&ServiceSpec { label: "x".into(), program: vec!["/x".into()], stop_timeout_s: Some(AGENT_STOP_TIMEOUT_S),
                                                 ..Default::default() });
        assert!(stops.contains("<key>ExitTimeOut</key><integer>60</integer>\n"));
        let owned = launchd_plist(&ServiceSpec { label: "dev.codonic.oarbank.agent".into(), program: vec!["/x".into()],
            associated_bundle: Some("dev.codonic.oarbank.node".into()), ..Default::default() });
        assert!(owned.contains("<key>AssociatedBundleIdentifiers</key><array><string>dev.codonic.oarbank.node</string></array>\n"));
        let h = session_helper_plist("dev.codonic.oarbank.agent.session", "/Library/Oarbank/bin/oarbank-agent", Some("dev.codonic.oarbank.node"));
        assert!(h.contains("<key>Label</key><string>dev.codonic.oarbank.agent.session</string>"));
        assert!(h.contains("<array>\n    <string>/Library/Oarbank/bin/oarbank-agent</string>\n    <string>session-helper</string>\n  </array>"));
        assert!(h.contains("<key>LimitLoadToSessionType</key><string>Aqua</string>\n</dict></plist>") && h.contains("<key>KeepAlive</key><true/>"));
        assert!(!h.contains("UserName") && !h.contains("StandardOutPath"));
        assert!(h.contains("<key>AssociatedBundleIdentifiers</key><array><string>dev.codonic.oarbank.node</string></array>"));
    }

    #[test]
    fn renders_a_systemd_unit_and_sc_arguments() {
        let spec = ServiceSpec { label: "oarbank-agent".into(), program: vec!["/opt/oarbank/oarbank-launcher".into(), "--home".into(),
            "/var/lib/oarbank/a b".into(), "run".into()], env: vec![("OARBANK_LOG".into(), "info".into())], user: Some("oarbank".into()),
            keep_alive: true, ..Default::default() };
        let u = systemd_unit(&spec, "Oarbank agent", true);
        assert!(u.contains("ExecStart=\"/opt/oarbank/oarbank-launcher\" \"--home\" \"/var/lib/oarbank/a b\" \"run\"\n"));
        assert!(u.contains("User=oarbank\n") && u.contains("Restart=always") && u.contains("WantedBy=multi-user.target"));
        assert!(u.contains("RuntimeDirectory=oarbank\nRuntimeDirectoryMode=0755\n"));
        assert!(!u.contains("TimeoutStopSec"));
        let stops = systemd_unit(&ServiceSpec { stop_timeout_s: Some(AGENT_STOP_TIMEOUT_S), ..spec.clone() }, "Oarbank agent", true);
        assert!(stops.contains("KillMode=mixed\nDelegate=yes\nTimeoutStopSec=60\n\n[Install]\n"));
        let personal = systemd_unit(&spec, "x", false);
        assert!(!personal.contains("User=") && !personal.contains("RuntimeDirectory"));
        let h = session_helper_unit("/usr/lib/oarbank/oarbank-agent", "oarbank");
        assert!(h.contains("ExecStart=\"/usr/lib/oarbank/oarbank-agent\" \"session-helper\"\n"));
        assert!(h.contains("ConditionUser=!oarbank\n") && h.contains("WantedBy=default.target"));
        let a = sc_create_args("OarbankAgent", "Oarbank agent", &[r"C:\Program Files\Oarbank\oarbank-launcher.exe".into(), "run".into()], None);
        assert_eq!(a[3], r#""C:\Program Files\Oarbank\oarbank-launcher.exe" run"#);
        assert_eq!(a[7], r"NT SERVICE\OarbankAgent");
    }

    #[test]
    fn a_service_home_belongs_to_its_virtual_account_administrators_and_system() {
        let a = icacls_home_args("dev.codonic.oarbank.agent", r"C:\ProgramData\Oarbank\agent");
        assert_eq!(a[..2], [r"C:\ProgramData\Oarbank\agent", "/inheritance:r"]);
        let grants: Vec<&str> = a.chunks(2).skip(1).map(|g| { assert_eq!(g[0], "/grant:r"); g[1].as_str() }).collect();
        assert_eq!(grants, [r"NT SERVICE\dev.codonic.oarbank.agent:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"]);
    }
}
