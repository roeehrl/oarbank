//! Rescue moves (docs/design/coordinator-move.md, "If something goes wrong"; docs/protocol.md, "Coordinator identity
//! and moves": Rescue moves). When the coordinator is compromised or lost, the owner signs a move to a fresh
//! coordinator (`oarbank owner rescue-move`), the target adds its own signature, and the file is published at a rescue
//! location the pinned owner key set names. The agent looks there once its coordinator has been unreachable for 30
//! minutes (then every 10 minutes while that lasts), and every 6 hours in any case, since a compromised coordinator may
//! still answer. A statement it finds is recorded only when it verifies against the pinned trust exactly like one from
//! a directive: the next epoch, from the key this agent trusts, signed by the target and the owner (moves.rs); the move
//! is then followed as usual.

use crate::config::Trust;
use crate::moves::Statement;
use std::time::Duration;
use tracing::info;

/// How long the coordinator must have been unreachable before the rescue locations are read.
pub const LOST_AFTER_S: f64 = 1800.0;
/// The pause between two looks.
pub const RETRY_S: f64 = 600.0;
/// A look while the coordinator answers.
pub const PERIODIC_S: f64 = 6.0 * 3600.0;
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

/// When to read the rescue locations.
#[derive(Debug, Default)]
pub struct RescueWatch {
    last_contact: Option<f64>,
    last_look: Option<f64>,
    next_look: f64,
}

impl RescueWatch {
    /// A hello or heartbeat succeeded.
    pub fn contact(&mut self, now: f64) {
        self.last_contact = Some(now);
    }

    /// Whether to look now (and if so, the look is booked): the coordinator unreachable for `LOST_AFTER_S` since the
    /// last contact (or since ever), or `PERIODIC_S` since the last look; never twice within `RETRY_S`.
    pub fn due(&mut self, now: f64, unreachable: bool) -> bool {
        if now < self.next_look {
            return false;
        }
        let lost = unreachable && self.last_contact.is_none_or(|c| now - c > LOST_AFTER_S);
        if !lost && self.last_look.is_some_and(|l| now - l < PERIODIC_S) {
            return false;
        }
        self.last_look = Some(now);
        self.next_look = now + RETRY_S;
        true
    }
}

/// The client for rescue locations: public CA roots, no redirects (a location answers itself or not at all).
pub fn client() -> anyhow::Result<reqwest::Client> {
    crate::staging::origin_client()
}

/// The first statement at the trust's rescue locations, in their order, that verifies against it now; with the location
/// it came from.
pub async fn find(client: &reqwest::Client, trust: &Trust, now: f64) -> Option<(String, Statement)> {
    for url in &trust.owner_rescue {
        match fetch(client, url).await.and_then(|s| s.verify(trust, now, true).map(|_| s)) {
            Ok(s) => return Some((url.clone(), s)),
            Err(e) => info!(location = %url, error = %format!("{e:#}"), "no rescue move for this agent there"),
        }
    }
    None
}

/// `{"coordinator_move": {statement, signatures}}` at `url`.
async fn fetch(client: &reqwest::Client, url: &str) -> anyhow::Result<Statement> {
    let r = client.get(url).timeout(FETCH_TIMEOUT).send().await?;
    if r.status() != reqwest::StatusCode::OK {
        anyhow::bail!("answered {}", r.status());
    }
    let body: serde_json::Value = r.json().await?;
    Statement::parse(&body["coordinator_move"])
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub fn key(n: u8) -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[n; 32]);
        let p = B64.encode(sk.verifying_key().to_bytes());
        (sk, p)
    }

    /// What `oarbank owner rescue-move` writes and `python -m oarbank.coordinator.rescue sign` completes: no `from`
    /// signature, the owner's and the target's.
    pub fn rescue_file(from: &str, to: &(SigningKey, String), owner: &SigningKey, epoch: i64, to_url: &str) -> Value {
        let raw = serde_json::to_string(&json!({"type": "oarbank.coordinator-move/v1", "rescue": true, "fleet_id": "fleet_a",
            "move_id": "mv_rescue_0a1b2c3d", "epoch": epoch, "from": {"url": null, "cik": from},
            "to": {"url": to_url, "cik": to.1, "ts_stable_node_id": null, "required_tag": null},
            "issued_at": 1, "not_before": 1, "expires": 4e9, "canary": [], "prev": null})).unwrap();
        json!({"coordinator_move": {"statement": raw, "signatures": {
            "owner": B64.encode(owner.sign(raw.as_bytes()).to_bytes()), "to": B64.encode(to.0.sign(raw.as_bytes()).to_bytes())}}})
    }

    /// A one-file-per-path HTTP server on 127.0.0.1: `(path, status, extra headers, body)`; anything else is a 404.
    pub async fn serve(routes: Vec<(&'static str, u16, &'static str, String)>) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                let routes = routes.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = c.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("").to_string();
                    let (status, headers, body) = routes.iter().find(|r| r.0 == path)
                        .map(|r| (r.1, r.2, r.3.clone())).unwrap_or((404, "", String::new()));
                    let resp = format!("HTTP/1.1 {status} X\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    let _ = c.write_all(resp.as_bytes()).await;
                });
            }
        });
        base
    }

    fn trust(a: &str, owner: &str, rescue: Vec<String>) -> Trust {
        Trust { cik: Some(a.into()), fleet_id: Some("fleet_a".into()), max_epoch: 1, owner_keys: vec![owner.into()],
                owner_version: 1, owner_rescue: rescue, ..Default::default() }
    }

    #[test]
    fn looks_every_six_hours_and_every_ten_minutes_once_the_coordinator_is_lost() {
        let mut w = RescueWatch::default();
        assert!(w.due(1000.0, false));                              // once at start
        assert!(!w.due(1000.0 + RETRY_S + 1.0, false));             // answering: not again for six hours
        assert!(w.due(1000.0 + PERIODIC_S + 1.0, false));
        let t = 1000.0 + PERIODIC_S + 100.0;                        // the coordinator answers, then goes away
        w.contact(t);
        assert!(!w.due(t + 60.0, true));                            // unreachable for a minute only
        assert!(w.due(t + LOST_AFTER_S + 1.0, true));               // lost for 30 minutes
        assert!(!w.due(t + LOST_AFTER_S + RETRY_S - 1.0, true));    // not twice within ten minutes
        assert!(w.due(t + LOST_AFTER_S + RETRY_S + 1.0, true));
        let mut fresh = RescueWatch::default();
        assert!(fresh.due(5.0, true) && !fresh.due(6.0, true));     // never reached since start: lost already
    }

    #[tokio::test]
    async fn the_first_statement_that_verifies_is_found_and_redirects_are_not_followed() {
        let (a, b, owner, rogue) = (key(1), key(2), key(3), key(9));
        let good = rescue_file(&a.1, &b, &owner.0, 2, "https://b:7443").to_string();
        let base = serve(vec![
            ("/junk", 200, "", "not json".into()),
            ("/redirect", 302, "Location: /good\r\n", String::new()),
            ("/stale", 200, "", rescue_file(&a.1, &b, &owner.0, 5, "https://b:7443").to_string()),   // not the next epoch
            ("/rogue", 200, "", rescue_file(&a.1, &b, &rogue.0, 2, "https://b:7443").to_string()),   // not the pinned owner
            ("/good", 200, "", good),
        ]).await;
        let at = |p: &str| format!("{base}{p}");
        let c = client().unwrap();
        let t = trust(&a.1, &owner.1, ["/gone", "/junk", "/redirect", "/stale", "/rogue", "/good"].iter().map(|p| at(p)).collect());
        let (url, s) = find(&c, &t, 10.0).await.expect("found");
        assert_eq!((url, s.epoch, s.to_url.as_str(), s.rescue), (at("/good"), 2, "https://b:7443", true));
        assert!(find(&c, &trust(&a.1, &owner.1, vec![at("/redirect"), at("/rogue")]), 10.0).await.is_none());
        let mut moved_on = trust(&a.1, &owner.1, vec![at("/good")]);
        moved_on.max_epoch = 2;                                       // already followed: the file is stale now
        assert!(find(&c, &moved_on, 10.0).await.is_none());
    }
}
