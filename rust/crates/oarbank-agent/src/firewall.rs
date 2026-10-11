//! The host's own firewall, for inbound listeners (docs/design/inbound-listeners.md, "Firewalls"): whether it would
//! let connections reach the agent (the doctor's `FIREWALL_BLOCKED`), and `oarbank-agent firewall allow`, which an
//! administrator (the launcher at install) runs to let them through:
//!
//! - macOS: the Application Firewall (`socketfilterfw`), per application: allowed when it is off, or the agent's
//!   binary is permitted (a Developer ID-signed binary is when "allow signed software" is on);
//! - Linux: nftables, ufw or firewalld when active; `allow` adds an `inet oarbank` table accepting only the listener
//!   ports, with a per-address connection limit;
//! - Windows: Defender Firewall; the elevated helper adds an inbound rule for the agent's path and the exact port when
//!   a listener opens (`firewall_allow`), so a first listen never raises a prompt that would create block rules.
//!
//! Reading runs read-only commands; nothing here changes anything unless `allow` is called.

use serde_json::{json, Value};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct State {
    pub kind: &'static str,
    /// The firewall is on (None: unknown).
    pub enabled: Option<bool>,
    /// It lets the agent accept connections (None: unknown).
    pub agent_allowed: Option<bool>,
    pub detail: Option<String>,
}

impl State {
    /// The doctor's input: the firewall blocks the agent.
    pub fn blocks(&self) -> Option<bool> {
        match (self.enabled, self.agent_allowed) {
            (Some(false), _) => Some(false),
            (Some(true), Some(a)) => Some(!a),
            _ => None,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({"kind": self.kind, "enabled": self.enabled, "agent_allowed": self.agent_allowed, "detail": self.detail})
    }
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).stdin(std::process::Stdio::null()).output().ok()?;
    Some(format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[cfg(target_os = "macos")]
const SOCKETFILTERFW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/// `socketfilterfw --getglobalstate`: "Firewall is enabled. (State = 1)", "... disabled. (State = 0)".
pub fn parse_macos_global(s: &str) -> Option<bool> {
    let l = s.to_ascii_lowercase();
    if l.contains("state = 0") || l.contains("is disabled") {
        Some(false)
    } else if l.contains("state = 1") || l.contains("state = 2") || l.contains("is enabled") || l.contains("blocking all") {
        Some(true)
    } else {
        None
    }
}

/// `socketfilterfw --getappblocked <path>`: "The application ... is permitted" / "... is blocked"; an application the
/// firewall does not list yet is judged by "allow signed software" (`--getallowsigned`).
pub fn parse_macos_app(s: &str) -> Option<bool> {
    let l = s.to_ascii_lowercase();
    if l.contains("permitted") || l.contains("is not blocked") {
        Some(true)
    } else if l.contains("blocked") {
        Some(false)
    } else {
        None
    }
}

/// `netsh advfirewall show currentprofile state`: "State                                 ON".
pub fn parse_windows_state(s: &str) -> Option<bool> {
    s.lines().find(|l| l.trim_start().to_ascii_lowercase().starts_with("state")).map(|l| l.to_ascii_uppercase().contains("ON"))
}

/// The firewall's state for the agent's own binary.
pub fn status() -> State {
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
    #[cfg(target_os = "macos")]
    {
        let enabled = run(SOCKETFILTERFW, &["--getglobalstate"]).and_then(|s| parse_macos_global(&s));
        let blockall = run(SOCKETFILTERFW, &["--getblockall"]).is_some_and(|s| s.to_ascii_lowercase().contains("enabled"));
        let app = run(SOCKETFILTERFW, &["--getappblocked", &exe]).and_then(|s| parse_macos_app(&s));
        let signed = run(SOCKETFILTERFW, &["--getallowsigned"]).map(|s| s.to_ascii_lowercase().contains("enabled"));
        let allowed = if blockall { Some(false) } else { app.or(signed) };
        State { kind: "macos-alf", enabled, agent_allowed: allowed, detail: blockall.then(|| "the firewall blocks all incoming connections".into()) }
    }
    #[cfg(target_os = "linux")]
    {
        let _ = exe;
        let active = |unit: &str| run("systemctl", &["is-active", unit]).is_some_and(|s| s.trim() == "active");
        let kind = if active("firewalld") { "firewalld" } else if active("ufw") { "ufw" } else if active("nftables") { "nftables" } else { "none" };
        State { kind, enabled: Some(kind != "none"), agent_allowed: if kind == "none" { Some(true) } else { None },
                detail: (kind != "none").then(|| format!("{kind} is active: make sure it accepts the listener ports (oarbank-agent firewall allow)")) }
    }
    #[cfg(windows)]
    {
        let enabled = run("netsh", &["advfirewall", "show", "currentprofile", "state"]).and_then(|s| parse_windows_state(&s));
        let rule = run("netsh", &["advfirewall", "firewall", "show", "rule", "name=all", "dir=in"])
            .map(|s| s.contains("Oarbank listener") && s.to_ascii_lowercase().contains(&exe.to_ascii_lowercase()));
        State { kind: "windows-defender", enabled, agent_allowed: rule, detail: None }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = exe;
        State { kind: "unknown", ..Default::default() }
    }
}

/// The nftables table `allow` installs on Linux: only the listener ports, a per-address connection limit.
pub fn nft_table(ports: &[u16]) -> String {
    let set = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
    format!("table inet oarbank {{\n  chain input {{\n    type filter hook input priority -5; policy accept;\n    \
             tcp dport {{ {set} }} ct count over 64 reject\n    tcp dport {{ {set} }} accept\n  }}\n}}\n")
}

/// Let connections reach the agent (an administrator; the launcher at install). `ports`: the listener ports (Linux,
/// Windows); macOS allows the application whatever its ports.
pub fn allow(ports: &[u16]) -> anyhow::Result<String> {
    let exe = std::env::current_exe()?.display().to_string();
    #[cfg(target_os = "macos")]
    {
        let _ = ports;
        let a = run(SOCKETFILTERFW, &["--add", &exe]).unwrap_or_default();
        let b = run(SOCKETFILTERFW, &["--unblockapp", &exe]).unwrap_or_default();
        Ok(format!("{}{}", a.trim(), b.trim()))
    }
    #[cfg(target_os = "linux")]
    {
        let _ = exe;
        anyhow::ensure!(!ports.is_empty(), "no listener ports given (--port)");
        let _ = std::process::Command::new("nft").args(["delete", "table", "inet", "oarbank"]).output();
        let mut c = std::process::Command::new("nft").args(["-f", "-"]).stdin(std::process::Stdio::piped()).spawn()?;
        use std::io::Write;
        c.stdin.take().expect("piped").write_all(nft_table(ports).as_bytes())?;
        anyhow::ensure!(c.wait()?.success(), "nft refused the table (run as root)");
        Ok(format!("nftables table inet oarbank accepts TCP {ports:?}"))
    }
    #[cfg(windows)]
    {
        let mut out = String::new();
        for p in ports {
            let r = run("netsh", &["advfirewall", "firewall", "add", "rule", &format!("name=Oarbank listener {p}"), "dir=in", "action=allow",
                                   &format!("program={exe}"), "protocol=TCP", &format!("localport={p}")]).unwrap_or_default();
            out.push_str(r.trim());
        }
        Ok(out)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (exe, ports);
        anyhow::bail!("not supported on this OS")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_answers_are_read() {
        assert_eq!(parse_macos_global("Firewall is enabled. (State = 1)"), Some(true));
        assert_eq!(parse_macos_global("Firewall is disabled. (State = 0)"), Some(false));
        assert_eq!(parse_macos_app("The application /x/oarbank-agent is permitted"), Some(true));
        assert_eq!(parse_macos_app("The application /x/oarbank-agent is blocked"), Some(false));
        assert_eq!(parse_windows_state("Domain Profile Settings:\n------\nState                                 ON\n"), Some(true));
        assert_eq!(parse_windows_state("State                                 OFF"), Some(false));
        assert_eq!(State { kind: "x", enabled: Some(true), agent_allowed: Some(false), detail: None }.blocks(), Some(true));
        assert_eq!(State { kind: "x", enabled: Some(false), agent_allowed: None, detail: None }.blocks(), Some(false));
        assert!(nft_table(&[9000, 41000]).contains("tcp dport { 9000, 41000 } accept"));
    }
}
