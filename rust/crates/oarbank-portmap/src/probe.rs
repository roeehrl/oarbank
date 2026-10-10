//! The dial-back probe (D49). The prober connects to the listener's external address and writes
//! `OARBANK-PROBE/1 <probe_id>\n`; the listener (the agent itself, never the module) answers
//! `OARBANK-PROBE/1 OK <nonce>\n`, or `OARBANK-PROBE/1 SAME <nonce>\n` when the probe came from the node's own network
//! (which proves nothing about reachability). The nonce never travels before the answer, so only the real target can
//! give it: an echo server or a hairpinning router cannot fake success.

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const MAGIC: &[u8] = b"OARBANK-PROBE/1 ";
const MAX_LINE: usize = 128;

/// A probe id or nonce: 32 lowercase hex characters (16 random bytes).
pub fn valid_token(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn token() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// The probe line a prober sends.
pub fn request(probe_id: &str) -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.extend_from_slice(probe_id.as_bytes());
    v.push(b'\n');
    v
}

/// What the first bytes of a connection are: a whole probe line (its id), the start of one (read more), or anything
/// else (a real client: relay the bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum First {
    Probe(String),
    Partial,
    NotProbe,
}

pub fn classify_first(b: &[u8]) -> First {
    let n = b.len().min(MAGIC.len());
    if b[..n] != MAGIC[..n] {
        return First::NotProbe;
    }
    if b.len() < MAGIC.len() {
        return First::Partial;
    }
    match b.iter().position(|c| *c == b'\n') {
        Some(i) => {
            let id = String::from_utf8_lossy(&b[MAGIC.len()..i]).trim().to_string();
            if valid_token(&id) { First::Probe(id) } else { First::NotProbe }
        }
        None if b.len() < MAX_LINE => First::Partial,
        None => First::NotProbe,
    }
}

pub fn answer(nonce: &str, same_network: bool) -> Vec<u8> {
    format!("OARBANK-PROBE/1 {} {nonce}\n", if same_network { "SAME" } else { "OK" }).into_bytes()
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Ok { rtt_ms: f64 },
    /// It reached the node, but from the node's own network.
    SameNetwork,
    /// Something answered, but not the target (a wrong nonce, another server).
    WrongAnswer,
    Refused,
    Timeout,
    Error(String),
}

impl Outcome {
    pub fn ok(&self) -> bool {
        matches!(self, Outcome::Ok { .. })
    }

    pub fn detail(&self) -> Option<String> {
        match self {
            Outcome::Ok { .. } => None,
            Outcome::SameNetwork => Some("same_network".into()),
            Outcome::WrongAnswer => Some("wrong_answer".into()),
            Outcome::Refused => Some("refused".into()),
            Outcome::Timeout => Some("timeout".into()),
            Outcome::Error(e) => Some(e.clone()),
        }
    }
}

/// Read one line of at most `MAX_LINE` bytes.
pub async fn read_line<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    while out.len() < MAX_LINE {
        if r.read(&mut b).await? == 0 {
            break;
        }
        if b[0] == b'\n' {
            break;
        }
        out.push(b[0]);
    }
    Ok(out)
}

/// Dial `to`, send the probe and check the answer against `nonce`. 5 s for the connection, 5 s for the answer.
pub async fn dial(to: SocketAddr, probe_id: &str, nonce: &str, timeout: Duration) -> Outcome {
    let start = Instant::now();
    let mut s = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(to)).await {
        Err(_) => return Outcome::Timeout,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Outcome::Refused,
        Ok(Err(e)) => return Outcome::Error(e.to_string()),
        Ok(Ok(s)) => s,
    };
    if let Err(e) = s.write_all(&request(probe_id)).await {
        return Outcome::Error(e.to_string());
    }
    let line = match tokio::time::timeout(timeout, read_line(&mut s)).await {
        Err(_) => return Outcome::Timeout,
        Ok(Err(e)) => return Outcome::Error(e.to_string()),
        Ok(Ok(l)) => String::from_utf8_lossy(&l).trim().to_string(),
    };
    check(&line, nonce, start.elapsed())
}

/// Judge an answer line.
pub fn check(line: &str, nonce: &str, rtt: Duration) -> Outcome {
    if line == format!("OARBANK-PROBE/1 OK {nonce}") {
        Outcome::Ok { rtt_ms: (rtt.as_secs_f64() * 1000.0 * 10.0).round() / 10.0 }
    } else if line == format!("OARBANK-PROBE/1 SAME {nonce}") {
        Outcome::SameNetwork
    } else {
        Outcome::WrongAnswer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_bytes_are_told_apart() {
        let id = token();
        assert_eq!(classify_first(&request(&id)), First::Probe(id.clone()));
        assert_eq!(classify_first(b"OARBANK-PR"), First::Partial);
        assert_eq!(classify_first(&MAGIC[..MAGIC.len()]), First::Partial);
        assert_eq!(classify_first(b"GET / HTTP/1.1\r\n"), First::NotProbe);
        assert_eq!(classify_first(b"OARBANK-PROBE/1 not-a-token\n"), First::NotProbe);
        assert_eq!(classify_first(b""), First::Partial);
    }

    #[test]
    fn only_the_nonce_counts() {
        let n = token();
        assert!(check(&format!("OARBANK-PROBE/1 OK {n}"), &n, Duration::from_millis(3)).ok());
        assert_eq!(check(&format!("OARBANK-PROBE/1 SAME {n}"), &n, Duration::ZERO), Outcome::SameNetwork);
        assert_eq!(check(&format!("OARBANK-PROBE/1 OK {}", token()), &n, Duration::ZERO), Outcome::WrongAnswer);
        assert_eq!(check("OARBANK-PROBE/1 deadbeef", &n, Duration::ZERO), Outcome::WrongAnswer, "an echo");
    }

    #[tokio::test]
    async fn an_echo_server_cannot_pass_a_probe() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let mut b = [0u8; 256];
                if let Ok(n) = s.read(&mut b).await {
                    let _ = s.write_all(&b[..n]).await;
                }
            }
        });
        let out = dial(at, &token(), &token(), Duration::from_secs(5)).await;
        assert_eq!(out, Outcome::WrongAnswer);
    }
}
