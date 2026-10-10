//! The checks before a join (docs/design/node-enrollment.md, "Error codes"): each one names what it tested, so a person
//! sees "the port did not answer" instead of one opaque failure. DNS, TCP, the coordinator's identity proof (signed by
//! the key the join code pins), its TLS CA (the code's pin) and a TLS connection verified against that CA, the clock
//! and the coordinator's role. Nothing secret is sent: the secret leaves only after every check passed, over the pinned
//! connection (agent.rs, `request_enrollment`). Without a code (`--coordinator`) the checks pin nothing and report the
//! fingerprints a person compares with the console.

use crate::config::Trust;
use crate::{identity, tls};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

pub const CLOCK_SKEW_S: f64 = 300.0;

#[derive(Debug, Clone)]
pub struct Row {
    pub id: &'static str,
    pub ok: bool,
    pub detail: String,
}

impl Row {
    pub fn json(&self) -> Value {
        json!({"row": self.id, "ok": self.ok, "detail": self.detail})
    }
}

#[derive(Debug, Clone)]
pub struct Fail {
    pub code: &'static str,
    pub message: String,
}

impl Fail {
    pub fn new(code: &'static str, message: impl Into<String>) -> Fail {
        Fail { code, message: message.into() }
    }
    /// Worth trying again later with the same code (the network, a coordinator restarting or moving).
    pub fn retryable(&self) -> bool {
        matches!(self.code, "E_DNS" | "E_TCP" | "E_NOT_ACTIVE")
    }
    /// `oarbank-node` / `oarbank-agent check` exit code (node-enrollment.md, "oarbank-node").
    pub fn exit_code(&self) -> i32 {
        match self.code {
            "E_CODE_FORMAT" => 2,
            "E_CODE_EXPIRED" | "E_CODE_USED" | "E_CODE_REVOKED" | "E_CODE_UNKNOWN" => 4,
            "E_TLS_PIN_MISMATCH" | "E_IDENTITY" => 5,
            "E_DNS" | "E_TCP" | "E_NOT_ACTIVE" | "E_CLOCK_SKEW" => 6,
            "E_ALREADY_JOINED" => 7,
            "E_PRIVILEGE" => 8,
            _ => 1,
        }
    }
}

/// What a probe of one coordinator URL found.
#[derive(Debug, Default)]
pub struct Probe {
    pub url: String,
    pub ca_pem: Option<String>,
    /// First 16 hex digits of the CA pin the coordinator signed (what the console shows).
    pub fingerprint: Option<String>,
    pub cik: Option<String>,
    pub fail: Option<Fail>,
}

fn proxy_for(url: &reqwest::Url) -> Option<String> {
    if url.scheme() != "https" {
        return None;
    }
    let host = url.host_str().unwrap_or("");
    let no = std::env::var("NO_PROXY").or_else(|_| std::env::var("no_proxy")).unwrap_or_default();
    if no.split(',').map(str::trim).any(|n| n == "*" || (!n.is_empty() && host.ends_with(n.trim_start_matches('.')))) {
        return None;
    }
    std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("https_proxy")).ok().filter(|p| !p.is_empty())
}

/// Probe `url`: `pins` (hex SPKI hashes) and `cik` come from a join code; empty and None pin nothing (join by address).
pub async fn probe(url: &str, pins: &[String], cik: Option<&str>, emit: &mut (dyn FnMut(Row) + Send)) -> Probe {
    let mut p = Probe { url: url.trim_end_matches('/').to_string(), ..Default::default() };
    if let Err(f) = run(&mut p, pins, cik, emit).await {
        p.fail = Some(f);
    }
    p
}

async fn run(p: &mut Probe, pins: &[String], cik: Option<&str>, emit: &mut (dyn FnMut(Row) + Send)) -> Result<(), Fail> {
    let u = reqwest::Url::parse(&p.url).map_err(|e| Fail::new("E_CODE_FORMAT", format!("{}: not a URL ({e})", p.url)))?;
    let host = u.host_str().unwrap_or("").trim_matches(|c| c == '[' || c == ']').to_string();
    let port = u.port_or_known_default().unwrap_or(7443);
    let mut row = |id: &'static str, ok: bool, detail: String| emit(Row { id, ok, detail });

    // DNS
    let addrs: Vec<std::net::SocketAddr> = match tokio::time::timeout(Duration::from_secs(8), tokio::net::lookup_host((host.as_str(), port))).await {
        Ok(Ok(a)) => a.collect(),
        _ => vec![],
    };
    if addrs.is_empty() {
        let m = format!("Can't find {host}. Check this computer's network connection and DNS.");
        row("dns", false, m.clone());
        return Err(Fail::new("E_DNS", m));
    }
    row("dns", true, format!("{host} -> {}", addrs.iter().map(|a| a.ip().to_string()).collect::<Vec<_>>().join(", ")));

    // TCP (through a proxy the agent's own client would use, the direct connection is not the one that matters)
    match proxy_for(&u) {
        Some(proxy) => row("tcp", true, format!("via proxy {proxy}")),
        None => {
            let started = Instant::now();
            let mut last = String::new();
            let mut ok = false;
            for a in &addrs {
                match tokio::time::timeout(Duration::from_secs(6), tokio::net::TcpStream::connect(a)).await {
                    Ok(Ok(_)) => {
                        ok = true;
                        break;
                    }
                    Ok(Err(e)) => last = e.to_string(),
                    Err(_) => last = "timed out".into(),
                }
            }
            if !ok {
                let m = format!("{host} didn't answer on port {port} ({last}). The coordinator may be off, or a firewall \
                                 is blocking outgoing connections to it.");
                row("tcp", false, m.clone());
                return Err(Fail::new("E_TCP", m));
            }
            row("tcp", true, format!("port {port} answered in {} ms", started.elapsed().as_millis()));
        }
    }

    // the identity proof, over TLS without verification: it is verified by the key it is signed with
    let boot = tls::bootstrap_client().map_err(|e| Fail::new("E_TCP", e.to_string()))?;
    let nonce = identity::new_nonce();
    let ans: Value = match boot.get(format!("{}/v1/identity?nonce={nonce}", p.url)).send().await {
        Ok(r) if r.status().is_success() => r.json().await.map_err(|_| {
            let m = format!("{} answered, but not as an Oarbank coordinator.", p.url);
            row("identity", false, m.clone());
            Fail::new("E_IDENTITY", m)
        })?,
        Ok(r) => {
            let m = format!("{} answered HTTP {}: it is not an Oarbank coordinator's agent port.", p.url, r.status().as_u16());
            row("identity", false, m.clone());
            return Err(Fail::new("E_IDENTITY", m));
        }
        Err(e) => {
            let m = format!("The TLS connection to {host}:{port} failed: {e}");
            row("identity", false, m.clone());
            return Err(Fail::new("E_TCP", m));
        }
    };
    let trust = Trust { cik: cik.map(str::to_string), ..Default::default() };
    let proof = match identity::check(&ans, &nonce, &trust) {
        Ok(pr) => pr,
        Err(e) => {
            let m = if cik.is_some() && format!("{e}").contains("another key") {
                "The server is not the coordinator this code was made by (its identity key differs). The code may be \
                 for another coordinator, or something is impersonating it.".to_string()
            } else {
                format!("The coordinator's identity proof is not valid: {e:#}")
            };
            row("identity", false, m.clone());
            return Err(Fail::new("E_IDENTITY", m));
        }
    };
    p.cik = Some(proof.cik.clone());
    row("identity", true, format!("fleet {}, key {}", &proof.fleet_id, &identity_fingerprint(&proof.cik)[..16]));

    // the CA: the one the signed proof names, which must be the code's pin; then a TLS connection verified against it
    let signed = proof.ca_spki_sha256.clone().unwrap_or_default();
    let ca_pem = ans["ca_pem"].as_str().unwrap_or("").to_string();
    let offered = tls::certs_from_pem(&ca_pem).ok().and_then(|mut c| (!c.is_empty()).then(|| c.remove(0)))
        .and_then(|der| tls::spki_sha256(&der).ok()).unwrap_or_default();
    let in_pins = |x: &str| pins.iter().any(|q| q.eq_ignore_ascii_case(x));
    let pin_ok = !signed.is_empty() && offered.eq_ignore_ascii_case(&signed)
        && (pins.is_empty() || in_pins(&signed) || proof.ca_next_spki_sha256.as_deref().is_some_and(in_pins));
    p.fingerprint = Some(signed.get(..16).unwrap_or(&signed).to_string());
    if !pin_ok {
        let m = "The server's certificate authority doesn't match this code. You may be behind a TLS-inspecting proxy, \
                 or the code is for a different coordinator.".to_string();
        row("tls", false, m.clone());
        return Err(Fail::new("E_TLS_PIN_MISMATCH", m));
    }
    let mut allowed: Vec<String> = vec![signed.clone()];
    allowed.extend(proof.ca_next_spki_sha256.clone());
    let verified = match tls::pinned_client(&ca_pem, &allowed, None) {
        Ok(c) => c.get(format!("{}/v1/identity?nonce={}", p.url, identity::new_nonce())).send().await
            .map(|r| r.status().is_success()).unwrap_or(false),
        Err(_) => false,
    };
    if !verified {
        let m = format!("The TLS certificate {host} presents is not issued by the coordinator's certificate authority. \
                         A TLS-inspecting proxy may be in the way.");
        row("tls", false, m.clone());
        return Err(Fail::new("E_TLS_PIN_MISMATCH", m));
    }
    row("tls", true, format!("certificate authority sha256:{}… {}", &signed[..16.min(signed.len())],
                             if pins.is_empty() { "(compare it with the console)" } else { "matches the code" }));
    p.ca_pem = Some(ca_pem);

    // the clock, against the time the coordinator signed
    let ts = serde_json::from_str::<Value>(ans["payload"].as_str().unwrap_or("{}")).ok().and_then(|d| d["ts"].as_f64());
    if let Some(ts) = ts {
        let skew = now() - ts;
        if skew.abs() > CLOCK_SKEW_S {
            let m = format!("This computer's clock is {} {} the coordinator's. Turn on automatic time and try again.",
                            human(skew.abs()), if skew > 0.0 { "ahead of" } else { "behind" });
            row("clock", false, m.clone());
            return Err(Fail::new("E_CLOCK_SKEW", m));
        }
        row("clock", true, format!("{skew:+.1} s"));
    }

    if proof.role != "active" {
        let m = format!("The coordinator at {} is a {} copy, not the active coordinator. Try again in a few minutes.",
                        p.url, proof.role.replace('_', " "));
        row("role", false, m.clone());
        return Err(Fail::new("E_NOT_ACTIVE", m));
    }
    Ok(())
}

fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

pub fn human(s: f64) -> String {
    if s < 120.0 { format!("{s:.0} seconds") } else if s < 7200.0 { format!("{:.0} minutes", s / 60.0) } else { format!("{:.1} hours", s / 3600.0) }
}

/// SHA-256 of the raw identity key, hex (identity.py `fingerprint`).
pub fn identity_fingerprint(cik_b64: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let raw = base64::engine::general_purpose::STANDARD.decode(cik_b64).unwrap_or_default();
    hex::encode(Sha256::digest(raw))
}

/// The offline checks of a code: format and check digits, then its expiry.
pub fn offline(code: &str) -> Result<oarbank_core::joincode::JoinCode, Fail> {
    let c = oarbank_core::joincode::decode(code).map_err(|e| Fail::new("E_CODE_FORMAT", e.to_string()))?;
    let left = c.expires_at as f64 - now();
    if left <= 0.0 {
        return Err(Fail::new("E_CODE_EXPIRED", format!("This code expired {} ago. Make a new one in the console.", human(-left))));
    }
    Ok(c)
}

/// The summary row of an offline check: coordinator, expiry, approval.
pub fn code_row(c: &oarbank_core::joincode::JoinCode) -> Row {
    let left = c.expires_at as f64 - now();
    let approval = if c.approve() { "approved at once" } else { "needs the owner's approval" };
    Row { id: "code", ok: true, detail: format!("coordinator {} · expires in {} · {approval}", c.host(), human(left)) }
}
