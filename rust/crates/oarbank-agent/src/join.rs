//! Join codes (the coordinator's joincodes.py): candidate addresses, the coordinator CA's SPKI hash, and a one-time
//! secret that approves this enrollment. The pin makes the first connection authenticated (no trust on first use).

use anyhow::{bail, Context, Result};
use serde_json::Value;

pub struct Join {
    pub urls: Vec<String>,
    pub ca_spki: String,
    pub secret: String,
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn b32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u64, 0u32);
    for c in s.bytes().filter(|&c| c != b'=') {
        let v = B32.iter().position(|&x| x == c)? as u64;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn b32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u64, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xedb8_8320 } else { c >> 1 };
        }
    }
    !c
}

pub fn decode(code: &str) -> Result<Join> {
    let code: String = code.split_whitespace().collect::<String>().to_ascii_uppercase();
    let rest = code.strip_prefix("OB1-").context("not an Oarbank join code")?;
    let (body, chk) = rest.rsplit_once('-').context("not an Oarbank join code")?;
    let want: String = b32_encode(&crc32(body.as_bytes()).to_be_bytes()).chars().take(4).collect();
    if want != chk {
        bail!("the join code is mistyped (check characters do not match)");
    }
    let raw = b32_decode(body).context("the join code is not base32")?;
    let v: Value = serde_json::from_slice(&raw).context("the join code does not decode")?;
    let urls: Vec<String> = v["u"].as_array().cloned().unwrap_or_default().iter().filter_map(|u| u.as_str().map(str::to_string)).collect();
    let (Some(p), Some(t)) = (v["p"].as_str(), v["t"].as_str()) else { bail!("incomplete join code") };
    if urls.is_empty() {
        bail!("the join code names no coordinator address");
    }
    Ok(Join { urls, ca_spki: p.to_ascii_lowercase(), secret: t.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_what_the_coordinator_encodes_and_refuses_typos() {
        // produced by oarbank.coordinator.joincodes.encode(["https://h:7443"], "ab" * 32, "s3cret")
        let raw = r#"{"u":["https://h:7443"],"p":"abababababababababababababababababababababababababababababababab","t":"s3cret"}"#;
        let body = b32_encode(raw.as_bytes());
        let chk: String = b32_encode(&crc32(body.as_bytes()).to_be_bytes()).chars().take(4).collect();
        let code = format!("OB1-{body}-{chk}");
        let j = decode(&code.to_lowercase()).unwrap();
        assert_eq!((j.urls[0].as_str(), j.secret.as_str()), ("https://h:7443", "s3cret"));
        let mut typo = code.clone();
        typo.replace_range(10..11, if &code[10..11] == "A" { "B" } else { "A" });
        assert!(decode(&typo).is_err());
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
