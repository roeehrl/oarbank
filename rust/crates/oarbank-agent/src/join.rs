//! Joining with a code (docs/design/node-enrollment.md): the offline checks, then each of the code's coordinator URLs is
//! probed (check.rs) until one passes; the agent then pins that coordinator's identity key and CA from the code, sends
//! the secret over the pinned connection, and reports what the coordinator decided. A refused code, a pin mismatch or
//! a forged identity ends the attempt; an unreachable coordinator is retried until the code expires.

use crate::agent::Agent;
use crate::check::{self, Fail, Row};
use crate::paths::Layout;
use crate::status::{self, Status};
use oarbank_core::joincode::JoinCode;
use serde_json::json;
use std::time::Duration;
use tracing::{info, warn};

/// A join given up for a newly staged code (not an error the status document shows).
pub const SUPERSEDED: &str = "E_SUPERSEDED";

/// The RFC 8628 user-code alphabet (no vowels, no look-alikes): what a node shows when it joins by address.
pub const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";

pub fn new_user_code() -> String {
    let s: String = (0..8).map(|_| USER_CODE_ALPHABET[rand::random::<u32>() as usize % 20] as char).collect();
    format!("{}-{}", &s[..4], &s[4..])
}

/// The error code for a coordinator's `join_error`.
pub fn refusal(join_error: &str) -> Fail {
    match join_error {
        "expired" => Fail::new("E_CODE_EXPIRED", "This code has expired. Make a new one in the console."),
        "used" => Fail::new("E_CODE_USED", "This code was already used (or has no uses left). Make a new one in the console."),
        "revoked" => Fail::new("E_CODE_REVOKED", "This code was revoked in the console. Make a new one."),
        _ => Fail::new("E_CODE_UNKNOWN", "The coordinator doesn't know this code. It may have been made by another coordinator."),
    }
}

pub enum EnrollError {
    /// The coordinator refused the code or the machine (final).
    Refused(Fail),
    Other(anyhow::Error),
}

impl From<anyhow::Error> for EnrollError {
    fn from(e: anyhow::Error) -> Self {
        EnrollError::Other(e)
    }
}

/// One attempt: probe the code's URLs, then enroll with the first that passes. Ok: the agent, enrollment requested
/// (approved or pending). Err: why, and whether trying again later can help (`Fail::retryable`).
pub async fn attempt(layout: &Layout, code: &JoinCode, name: Option<&str>, status: &Status,
                     emit: &mut (dyn FnMut(Row) + Send)) -> Result<Agent, Fail> {
    let mut last: Option<Fail> = None;
    for url in &code.urls {
        let p = check::probe(url, &code.pins, Some(&code.cik), emit).await;
        if let Some(f) = p.fail {
            warn!(url = %url, code = f.code, "join check failed: {}", f.message);
            let fatal = !f.retryable();
            last = Some(f);
            if fatal {
                break;                       // a forged identity or a pin mismatch: no other address is tried
            }
            continue;
        }
        // a fresh agent.json for this coordinator: nothing from an earlier, failed join is trusted
        let _ = std::fs::remove_file(layout.config());
        let mut a = Agent::open(Layout::new(layout.home.clone()), Some(&p.url)).map_err(|e| Fail::new("E_LOCAL", format!("{e:#}")))?;
        a.status = status.clone();
        let t = &mut a.cfg.coordinator_trust;
        t.cik = Some(code.cik.clone());
        t.ca_spki_sha256 = code.pins.first().cloned();
        t.ca_next_spki_sha256 = code.pins.get(1).cloned();
        a.cfg.join_secret = Some(code.token());
        a.cfg.name = name.map(str::to_string);
        a.cfg.save(&a.layout.config()).map_err(|e| Fail::new("E_LOCAL", format!("{e:#}")))?;
        match a.request_enrollment().await {
            Ok(_) => return Ok(a),
            Err(EnrollError::Refused(f)) => {
                let _ = std::fs::remove_file(layout.config());
                return Err(f);
            }
            Err(EnrollError::Other(e)) => {
                warn!(url = %url, error = %e, "enrollment request failed");
                last = Some(Fail::new("E_TCP", format!("The coordinator at {} did not take the request: {e:#}", p.url)));
            }
        }
    }
    Err(last.unwrap_or_else(|| Fail::new("E_TCP", "No coordinator address in the code answered.")))
}

/// Join with `code`, retrying a coordinator that cannot be reached until the code expires. Ok: enrolled or pending;
/// Err: a final failure (the status document says which).
pub async fn join(layout: &Layout, code: &str, name: Option<&str>, staged: Option<&std::path::Path>,
                  status: &mut Status) -> Result<Agent, Fail> {
    let c = match check::offline(code) {
        Ok(c) => c,
        Err(f) => {
            status.fail(status::ERROR, f.code, &f.message, json!({}));
            return Err(f);
        }
    };
    status.set(status::JOINING, json!({"coordinator": c.urls[0], "fingerprint": c.fingerprint(),
                                       "code_expires_at": c.expires_at, "enrollment_id": null, "node_id": null,
                                       "checks": null, "retrying": null}));
    let mut backoff = Duration::from_secs(2);
    loop {
        let mut rows = vec![];
        match attempt(layout, &c, name, status, &mut |r: Row| rows.push(r.json())).await {
            Ok(a) => {
                info!(coordinator = %a.cfg.coordinator, "join code accepted");
                *status = a.status.clone();
                return Ok(a);
            }
            Err(f) if f.retryable() && (c.expires_at as f64) > now() + backoff.as_secs_f64() => {
                status.fail(status::ERROR, f.code, &f.message, json!({"checks": rows, "retrying": true}));
                // a newly staged code replaces the one being retried
                let until = std::time::Instant::now() + backoff;
                while std::time::Instant::now() < until {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    if staged.and_then(|p| std::fs::read_to_string(p).ok()).is_some_and(|s| s.trim() != code.trim()) {
                        return Err(Fail::new(SUPERSEDED, "another code was staged"));
                    }
                }
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
            Err(f) => {
                let f = if f.retryable() {
                    Fail::new("E_CODE_EXPIRED", format!("The code expired before the coordinator could be reached. {}", f.message))
                } else { f };
                status.fail(status::ERROR, f.code, &f.message, json!({"checks": rows, "retrying": null}));
                return Err(f);
            }
        }
    }
}

fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn user_codes_use_the_rfc_8628_alphabet() {
        for _ in 0..50 {
            let c = super::new_user_code();
            assert_eq!(c.len(), 9);
            assert!(c.chars().filter(|&ch| ch != '-').all(|ch| super::USER_CODE_ALPHABET.contains(&(ch as u8))), "{c}");
        }
    }
}
