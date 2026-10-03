//! Results that must reach the coordinator (complete, fail): written to `outbox/` before they are sent, retried
//! until they arrive, and replayed after a restart. The coordinator's idempotency keys make replays harmless.

use crate::api::{Api, ApiError};
use crate::paths::Layout;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

fn file_for(l: &Layout, path: &str) -> std::path::PathBuf {
    l.outbox().join(format!("{}.json", &hex::encode(Sha256::digest(path.as_bytes()))[..24]))
}

async fn try_send(api: &Api, path: &str, body: &Value) -> Result<(), bool> {
    match api.post(path, body).await {
        Ok(_) => Ok(()),
        // busy, transport, coordinator moving: keep it; any other refusal is final (the attempt is gone)
        Err(ApiError::Transport(_)) => Err(true),
        Err(ApiError::Http { status, .. }) if status == 503 || status == 0 || status == 410 => Err(true),
        Err(_) => Err(false),
    }
}

pub async fn send(api: &Api, l: &Layout, path: &str, body: &Value) {
    let f = file_for(l, path);
    let _ = crate::fsutil::write_private(&f, &serde_json::to_vec(&json!({"path": path, "body": body})).unwrap_or_default());
    let mut wait = Duration::from_secs(1);
    for _ in 0..8 {
        match try_send(api, path, body).await {
            Ok(()) | Err(false) => {
                let _ = std::fs::remove_file(&f);
                return;
            }
            Err(true) => {
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(Duration::from_secs(30));
            }
        }
    }
    // still queued: flush() retries it after the next hello
}

/// Replay whatever is queued (after a restart or an outage).
pub async fn flush(api: &Api, l: &Layout) {
    let Ok(rd) = std::fs::read_dir(l.outbox()) else { return };
    for e in rd.filter_map(|e| e.ok()) {
        let Ok(v) = serde_json::from_slice::<Value>(&std::fs::read(e.path()).unwrap_or_default()) else {
            let _ = std::fs::remove_file(e.path());
            continue;
        };
        if let Some(p) = v["path"].as_str() {
            if try_send(api, p, &v["body"]).await != Err(true) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}
