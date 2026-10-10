//! Join codes, format OB2 (docs/design/node-enrollment.md; the coordinator's joincodes.py is the other half): the
//! coordinator's agent URLs, its identity key and TLS CA pins, the code's expiry and the console's suggested install
//! options, an id and a secret, all under a CRC-32 so a mistyped or truncated code is refused before anything is sent.
//! `src/oarbank/contracts/vectors/joincode.json` holds the vectors both sides replay.

use base64::Engine;

pub const PREFIX: &str = "OB2-";
pub const F_APPROVE: u8 = 1;
pub const F_SYSTEM: u8 = 2;
pub const F_CONTAINERS: u8 = 4;
pub const F_MULTI: u8 = 8;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinCode {
    pub flags: u8,
    /// Unix seconds (minute resolution).
    pub expires_at: i64,
    /// The coordinator identity key: base64 of the raw Ed25519 public key, as identity proofs spell it.
    pub cik: String,
    /// Hex SHA-256 of the CA SubjectPublicKeyInfo: the current CA first, then a successor during a rotation.
    pub pins: Vec<String>,
    pub urls: Vec<String>,
    pub id: String,
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodeError {
    #[error("that is not an Oarbank join code (they start with OB2-)")]
    NotACode,
    #[error("that is a join code from an older coordinator: make a new one in the console")]
    OldFormat,
    #[error("the join code has a character that is not in it ({0:?}): copy it again from the console")]
    BadChar(char),
    #[error("the join code is incomplete: copy it again from the console")]
    Incomplete,
    #[error("the join code is mistyped or incomplete (its check digits do not match): copy it again")]
    Checksum,
    #[error("join code format {0} is not supported by this version")]
    Version(u8),
    #[error("the join code is malformed")]
    Malformed,
}

impl JoinCode {
    /// What the enrollment request carries: `<id hex>.<secret hex>`.
    pub fn token(&self) -> String {
        format!("{}.{}", self.id, self.secret)
    }
    pub fn approve(&self) -> bool { self.flags & F_APPROVE != 0 }
    pub fn system(&self) -> bool { self.flags & F_SYSTEM != 0 }
    pub fn containers(&self) -> bool { self.flags & F_CONTAINERS != 0 }
    pub fn multi(&self) -> bool { self.flags & F_MULTI != 0 }
    /// The first 16 hex digits of the current CA pin: what people compare with the console.
    pub fn fingerprint(&self) -> String {
        self.pins.first().map(|p| p[..16.min(p.len())].to_string()).unwrap_or_default()
    }
    /// The first URL's host, for display.
    pub fn host(&self) -> String {
        let u = self.urls.first().map(String::as_str).unwrap_or("");
        let rest = u.split_once("://").map(|(_, r)| r).unwrap_or(u);
        rest.split('/').next().unwrap_or(rest).to_string()
    }
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xedb8_8320 } else { c >> 1 };
        }
    }
    !c
}

pub fn b32encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u64, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn b32value(c: char) -> Option<u64> {
    match c {
        'I' | 'L' => Some(1),
        'O' => Some(0),
        _ => ALPHABET.iter().position(|&x| x as char == c).map(|v| v as u64),
    }
}

pub fn b32decode(s: &str) -> Result<Vec<u8>, CodeError> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u64, 0u32);
    for c in s.chars() {
        let v = b32value(c).ok_or(CodeError::BadChar(c))?;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// Parse a pasted code: whitespace and dashes are ignored, case folded (ASCII), I/L read as 1 and O as 0.
pub fn decode(code: &str) -> Result<JoinCode, CodeError> {
    let s: String = code.split_whitespace().collect::<String>().to_ascii_uppercase();
    let Some(body) = s.strip_prefix("OB2") else {
        return Err(if s.starts_with("OB1") { CodeError::OldFormat } else { CodeError::NotACode });
    };
    let raw = b32decode(&body.replace('-', ""))?;
    if raw.len() < 1 + 1 + 4 + 32 + 1 + 1 + 8 + 16 + 4 {
        return Err(CodeError::Incomplete);
    }
    let (body, crc) = raw.split_at(raw.len() - 4);
    if crc32(body).to_be_bytes() != crc {
        return Err(CodeError::Checksum);
    }
    if body[0] != 2 {
        return Err(CodeError::Version(body[0]));
    }
    let take = |i: &mut usize, n: usize| -> Result<&[u8], CodeError> {
        let s = body.get(*i..*i + n).ok_or(CodeError::Malformed)?;
        *i += n;
        Ok(s)
    };
    let mut i = 1;
    let flags = take(&mut i, 1)?[0];
    let expires_at = u32::from_be_bytes(take(&mut i, 4)?.try_into().unwrap()) as i64 * 60;
    let cik = base64::engine::general_purpose::STANDARD.encode(take(&mut i, 32)?);
    let n = take(&mut i, 1)?[0] as usize;
    let mut pins = Vec::with_capacity(n);
    for _ in 0..n {
        pins.push(hex::encode(take(&mut i, 32)?));
    }
    let n = take(&mut i, 1)?[0] as usize;
    let mut urls = Vec::with_capacity(n);
    for _ in 0..n {
        let len = take(&mut i, 1)?[0] as usize;
        urls.push(String::from_utf8(take(&mut i, len)?.to_vec()).map_err(|_| CodeError::Malformed)?);
    }
    let id = hex::encode(take(&mut i, 8)?);
    let secret = hex::encode(take(&mut i, 16)?);
    if i != body.len() || pins.is_empty() || urls.is_empty() {
        return Err(CodeError::Malformed);
    }
    Ok(JoinCode { flags, expires_at, cik, pins, urls, id, secret })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../../../../src/oarbank/contracts/vectors/joincode.json");

    #[test]
    fn the_shared_vectors_decode() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let codes = v["codes"].as_array().unwrap();
        for c in codes {
            let d = decode(c["text"].as_str().unwrap()).unwrap();
            assert_eq!(d.flags as u64, c["flags"].as_u64().unwrap());
            assert_eq!(d.expires_at, c["expires_at"].as_i64().unwrap());
            assert_eq!(d.cik, c["cik"].as_str().unwrap());
            assert_eq!(d.pins, c["pins"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_string()).collect::<Vec<_>>());
            assert_eq!(d.urls, c["urls"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_string()).collect::<Vec<_>>());
            assert_eq!(d.id, c["id"].as_str().unwrap());
            assert_eq!(d.secret, c["secret"].as_str().unwrap());
        }
        for e in v["equivalent"].as_array().unwrap() {
            let same = &codes[e["same_as"].as_u64().unwrap() as usize]["text"];
            assert_eq!(decode(e["text"].as_str().unwrap()).unwrap(), decode(same.as_str().unwrap()).unwrap());
        }
        for bad in v["invalid"].as_array().unwrap() {
            assert!(decode(bad["text"].as_str().unwrap()).is_err(), "{}", bad["why"]);
        }
    }

    #[test]
    fn the_codec_round_trips_and_checks() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let data: Vec<u8> = (0..=255u8).collect();
        assert_eq!(b32decode(&b32encode(&data)).unwrap(), data);
        assert_eq!(decode("OB1-XYZ"), Err(CodeError::OldFormat));
        assert_eq!(decode("tskey-abc"), Err(CodeError::NotACode));
    }
}
