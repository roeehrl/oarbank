//! The node's status document (docs/design/node-enrollment.md, "The node's states and status document"): where this
//! node is in joining and whether its session is up, for the join window, the menu bar and tray apps, `oarbank-node
//! status` and installers. It holds no secrets and is readable by everyone; the agent writes it (`run --status-file`)
//! through a temporary file and a rename, so a reader never sees half of it. Beside it, a `joined` marker file exists
//! while the node holds a certificate (what an MDM detection rule looks for).

use serde_json::{json, Map, Value};
use std::path::PathBuf;

#[derive(Default, Clone)]
pub struct Status {
    path: Option<PathBuf>,
    doc: Map<String, Value>,
}

pub const UNJOINED: &str = "unjoined";
pub const JOINING: &str = "joining";
pub const PENDING: &str = "pending";
pub const JOINED: &str = "joined";
pub const CONNECTED: &str = "connected";
pub const OFFLINE: &str = "offline";
pub const ERROR: &str = "error";

fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

impl Status {
    pub fn new(path: Option<PathBuf>) -> Status {
        let doc = path.as_ref().and_then(|p| std::fs::read(p).ok()).and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v.as_object().cloned()).unwrap_or_default();
        Status { path, doc }
    }

    pub fn state(&self) -> &str {
        self.doc.get("state").and_then(Value::as_str).unwrap_or("")
    }

    pub fn get(&self, k: &str) -> Option<&Value> {
        self.doc.get(k)
    }

    /// Move to `state`, merging `fields` (a null removes a field). Leaving `error` clears the error.
    pub fn set(&mut self, state: &str, fields: Value) {
        if state != ERROR && state != OFFLINE {
            self.doc.remove("error");
        }
        self.doc.insert("state".into(), json!(state));
        if let Value::Object(f) = fields {
            for (k, v) in f {
                if v.is_null() {
                    self.doc.remove(&k);
                } else {
                    self.doc.insert(k, v);
                }
            }
        }
        self.write();
    }

    /// An error with its stable code and message, staying in `state` (`error`, or `offline` for a lost session).
    pub fn fail(&mut self, state: &str, code: &str, message: &str, fields: Value) {
        self.doc.insert("error".into(), json!({"code": code, "message": message}));
        self.set(state, fields);
    }

    /// Forget everything about a previous coordinator (a join that ended, a node that left).
    pub fn reset(&mut self, state: &str) {
        let keep: Vec<(String, Value)> = ["managed_by"].iter()
            .filter_map(|k| self.doc.get(*k).map(|v| (k.to_string(), v.clone()))).collect();
        self.doc.clear();
        self.doc.extend(keep);
        self.set(state, json!({}));
    }

    fn write(&mut self) {
        let Some(p) = &self.path else { return };
        self.doc.insert("format".into(), json!(1));
        self.doc.insert("updated_at".into(), json!(now()));
        let dir = p.parent().map(|d| d.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
        let _ = std::fs::create_dir_all(&dir);
        let tmp = dir.join(format!(".node.{}.tmp", std::process::id()));
        if std::fs::write(&tmp, serde_json::to_vec_pretty(&Value::Object(self.doc.clone())).unwrap_or_default()).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644));
            }
            if std::fs::rename(&tmp, p).is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
        }
        let marker = dir.join("joined");
        if matches!(self.state(), JOINED | CONNECTED | OFFLINE) {
            if !marker.exists() {
                let _ = std::fs::write(&marker, b"1\n");
            }
        } else {
            let _ = std::fs::remove_file(&marker);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_merge_fields_clear_errors_and_mark_joined() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("status/node.json");
        let mut s = Status::new(Some(p.clone()));
        s.fail(ERROR, "E_TCP", "no answer", json!({"coordinator": "https://c:7443"}));
        s.set(PENDING, json!({"user_code": "WDJB-MJHT"}));
        let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!((v["state"].as_str(), v["error"].is_null(), v["coordinator"].as_str(), v["format"].as_i64()),
                   (Some("pending"), true, Some("https://c:7443"), Some(1)));
        assert!(!d.path().join("status/joined").exists());
        s.set(CONNECTED, json!({"user_code": null, "node_id": "n_1"}));
        let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert!(v["user_code"].is_null() && v["node_id"] == "n_1");
        assert!(d.path().join("status/joined").exists());
        s.reset(UNJOINED);
        assert!(!d.path().join("status/joined").exists());
        assert_eq!(Status::new(Some(p)).state(), "unjoined");
    }
}
