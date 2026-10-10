//! Managed policy (docs/design/node-enrollment.md, "Managed policy keys"): what an MDM profile, Group Policy/Intune or
//! a config-management tool set for this node. macOS: the managed-preferences domain `dev.codonic.oarbank.agent`;
//! Windows: `HKLM\SOFTWARE\Policies\Codonic\Oarbank\Agent`; Linux: `/etc/oarbank/policy.json`. `OARBANK_POLICY_FILE`
//! names a JSON file instead (tests). Values are never logged: a join code is a secret.

use serde_json::Value;

pub const DOMAIN: &str = "dev.codonic.oarbank.agent";

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Policy {
    pub join_code: Option<String>,
    pub coordinator: Option<String>,
    pub scope: Option<String>,
    pub containers: Option<bool>,
    pub name: Option<String>,
    pub allow_user_join: Option<bool>,
    pub managed_by: Option<String>,
    /// `ShowStatusIcon`: false hides Oarbank Node's menu bar (macOS) or notification-area (Windows) icon on every
    /// account, true keeps it shown; set either way, the app's own setting is greyed out ("Managed by …"). The agent
    /// only reports it (`oarbank-agent policy`): the apps read the policy themselves.
    pub show_status_icon: Option<bool>,
}

impl Policy {
    pub fn from_json(v: &Value) -> Policy {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty()).map(str::to_string);
        let b = |k: &str| v.get(k).and_then(|x| match x {
            Value::Bool(b) => Some(*b),
            Value::Number(n) => n.as_i64().map(|n| n != 0),
            Value::String(t) => match t.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" => Some(true),
                "0" | "false" | "no" => Some(false),
                _ => None,
            },
            _ => None,
        });
        Policy { join_code: s("JoinCode"), coordinator: s("Coordinator"), scope: s("Scope"), containers: b("Containers"),
                 name: s("Name"), allow_user_join: b("AllowUserJoin"), managed_by: s("ManagedByOrganizationName"),
                 show_status_icon: b("ShowStatusIcon") }
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        *self == Policy::default()
    }
}

/// The policy in force, or the default (nothing managed) when none is set or it cannot be read.
pub fn read() -> Policy {
    if let Some(f) = std::env::var_os("OARBANK_POLICY_FILE") {
        return std::fs::read(f).ok().and_then(|b| serde_json::from_slice(&b).ok()).map(|v| Policy::from_json(&v)).unwrap_or_default();
    }
    read_os().map(|v| Policy::from_json(&v)).unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn read_os() -> Option<Value> {
    let p = format!("/Library/Managed Preferences/{DOMAIN}.plist");
    if !std::path::Path::new(&p).exists() {
        return None;
    }
    // managed preferences may be binary or XML; plutil reads both
    let out = std::process::Command::new("/usr/bin/plutil").args(["-convert", "json", "-o", "-", &p]).output().ok()?;
    out.status.success().then(|| serde_json::from_slice(&out.stdout).ok()).flatten()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn read_os() -> Option<Value> {
    serde_json::from_slice(&std::fs::read("/etc/oarbank/policy.json").ok()?).ok()
}

#[cfg(windows)]
fn read_os() -> Option<Value> {
    let out = std::process::Command::new("reg").args(["query", r"HKLM\SOFTWARE\Policies\Codonic\Oarbank\Agent"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_reg(&String::from_utf8_lossy(&out.stdout)))
}

/// `reg query` output: `    Name    REG_SZ    value` and `    Name    REG_DWORD    0x1`.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_reg(text: &str) -> Value {
    let mut m = serde_json::Map::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.trim().splitn(3, "    ").map(str::trim).collect();
        if let [name, ty, val] = parts[..] {
            let v = match ty {
                "REG_DWORD" => Value::from(i64::from_str_radix(val.trim_start_matches("0x"), 16).unwrap_or(0)),
                "REG_SZ" | "REG_EXPAND_SZ" => Value::from(val),
                _ => continue,
            };
            m.insert(name.to_string(), v);
        }
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_and_types_are_read_leniently() {
        let p = Policy::from_json(&json!({"JoinCode": " OB2-X ", "Containers": 1, "AllowUserJoin": "false",
                                          "Scope": "system", "ManagedByOrganizationName": "Example", "Name": "",
                                          "ShowStatusIcon": 0}));
        assert_eq!(p, Policy { join_code: Some("OB2-X".into()), coordinator: None, scope: Some("system".into()),
                               containers: Some(true), name: None, allow_user_join: Some(false),
                               managed_by: Some("Example".into()), show_status_icon: Some(false) });
        assert!(Policy::from_json(&json!({})).is_empty());
    }

    #[test]
    fn registry_output_parses() {
        let out = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Codonic\\Oarbank\\Agent\r\n    JoinCode    REG_SZ    OB2-ABC\r\n    Containers    REG_DWORD    0x1\r\n    ShowStatusIcon    REG_DWORD    0x0\r\n\r\n";
        let p = Policy::from_json(&parse_reg(out));
        assert_eq!((p.join_code.as_deref(), p.containers, p.show_status_icon), (Some("OB2-ABC"), Some(true), Some(false)));
    }
}
