//! Canonical JSON and job keys (module protocol: `job_key = H(module_id, compat, key_inputs)`), byte-identical to the
//! SDK's `keys.py`.
//!
//! The canonical form is RFC 8785 (JCS) plus three refusals: NaN and infinities, integers beyond ±2^53 (send those as
//! decimal strings) and non-string object keys (which a `serde_json::Value` cannot hold). The shared vectors in
//! spec/vectors/canonical-json.json and job-key.json pin it down.
//!
//! An integer and an integral float are the same number (`3` and `3.0` both canonicalise to `3`), but only integers
//! are range-checked: `1e16` is fine, `10000000000000000` is refused, exactly as Python's `json.loads` + `keys.py`.

use serde_json::{Number, Value};
use sha2::{Digest, Sha256};

/// Integers beyond ±2^53 have no canonical form (2^53 itself has).
pub const MAX_SAFE_INT: u64 = 1 << 53;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CanonicalError(pub String);

fn err<T>(msg: impl Into<String>) -> Result<T, CanonicalError> {
    Err(CanonicalError(msg.into()))
}

/// RFC 8785 canonical JSON of `v`.
pub fn canonical_json(v: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(&mut out, v)?;
    Ok(out)
}

/// `canonical_json(v)` as UTF-8 bytes (what job keys hash).
pub fn canonical_bytes(v: &Value) -> Result<Vec<u8>, CanonicalError> {
    canonical_json(v).map(String::into_bytes)
}

/// Parse a JSON document the way the SDK's `json.loads` does for canonicalisation: integer literals beyond ±2^53 are
/// refused (a plain `serde_json` parse would silently turn them into floats).
pub fn parse_json(text: &str) -> Result<Value, CanonicalError> {
    let v: Value = serde_json::from_str(text).map_err(|e| CanonicalError(format!("not JSON: {e}")))?;
    check_integer_literals(text)?;
    Ok(v)
}

/// `canonical_json(parse_json(text))`.
pub fn canonical_json_str(text: &str) -> Result<String, CanonicalError> {
    canonical_json(&parse_json(text)?)
}

/// `sha256(canonical {"module", "compat", "inputs"})` in hex, with `:<stage>` appended for a non-empty stage.
pub fn job_key(module_id: &str, compat: &str, key_inputs: &Value, stage: Option<&str>) -> Result<String, CanonicalError> {
    let mut m = serde_json::Map::new();
    m.insert("module".into(), Value::String(module_id.into()));
    m.insert("compat".into(), Value::String(compat.into()));
    m.insert("inputs".into(), key_inputs.clone());
    let h = hex::encode(Sha256::digest(canonical_bytes(&Value::Object(m))?));
    Ok(match stage {
        Some(s) if !s.is_empty() => format!("{h}:{s}"),
        _ => h,
    })
}

fn write_value(out: &mut String, v: &Value) -> Result<(), CanonicalError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&number(n)?),
        Value::String(s) => write_string(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, x)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut items: Vec<(&String, &Value)> = m.iter().collect();
            items.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (k, x)) in items.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value(out, x)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// A JSON number: integers (range-checked) print as integers, floats per ECMAScript `Number.prototype.toString`.
pub fn number(n: &Number) -> Result<String, CanonicalError> {
    if let Some(u) = n.as_u64() {
        return integer(u as i128);
    }
    if let Some(i) = n.as_i64() {
        return integer(i as i128);
    }
    // Neither u64 nor i64: a float, or (with serde_json's arbitrary_precision) an integer literal too large for both.
    let s = n.to_string();
    if !s.contains(['.', 'e', 'E']) {
        return err(format!("integer {s} is beyond ±2^53: send it as a decimal string"));
    }
    match n.as_f64() {
        Some(x) => float(x),
        None => err(format!("number {s} has no canonical form")),
    }
}

fn integer(v: i128) -> Result<String, CanonicalError> {
    if v.unsigned_abs() > MAX_SAFE_INT as u128 {
        return err(format!("integer {v} is beyond ±2^53: send it as a decimal string"));
    }
    Ok(v.to_string())
}

/// ECMAScript `Number.prototype.toString` over the shortest round-trip digits (RFC 8785 §3.2.2.3).
pub fn float(x: f64) -> Result<String, CanonicalError> {
    if !x.is_finite() {
        return err("NaN and infinities have no canonical form");
    }
    if x == 0.0 {
        return Ok("0".into());
    }
    // The shortest digits that round-trip, the closest to x, ties to even: the digits of Python's repr. (std's `{:e}`
    // breaks ties upwards: 2330662528422.65625 prints ...6563 there, ...6562 in Python and ECMAScript.)
    let mut buf = zmij::Buffer::new();
    let r = buf.format_finite(x.abs());
    let (mant, exp) = r.split_once(['e', 'E']).unwrap_or((r, "0"));
    let exp: i64 = exp.parse().expect("an integer exponent");
    let (ip, fp) = mant.split_once('.').unwrap_or((mant, ""));
    let all = format!("{ip}{fp}");
    let stripped = all.trim_start_matches('0');
    let lead_zeros = (all.len() - stripped.len()) as i64;
    let n = ip.len() as i64 + exp - lead_zeros; // position of the decimal point relative to `digits`
    let digits = match stripped.trim_end_matches('0') {
        "" => "0",
        d => d,
    };
    let k = digits.len() as i64;
    let s = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let frac = if k > 1 { format!(".{}", &digits[1..]) } else { String::new() };
        format!("{}{frac}e{}{}", &digits[..1], if e >= 0 { "+" } else { "-" }, e.abs())
    };
    Ok(if x < 0.0 { format!("-{s}") } else { s })
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Refuse integer literals (no fraction, no exponent) beyond ±2^53 in a JSON text that already parsed.
fn check_integer_literals(text: &str) -> Result<(), CanonicalError> {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() {
                    match b[i] {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                if b[i] == b'-' {
                    i += 1;
                }
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                let int_end = i;
                let is_float = i < b.len() && matches!(b[i], b'.' | b'e' | b'E');
                while i < b.len() && matches!(b[i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                    i += 1;
                }
                if !is_float {
                    let lit = &text[start..int_end];
                    let digits = lit.trim_start_matches('-').trim_start_matches('0');
                    let too_big = digits.len() > 16 && (digits.len() > 30 || digits.parse::<u128>().map_or(true, |v| v > MAX_SAFE_INT as u128));
                    if too_big {
                        // JSON forbids leading zeros and '+', so the literal is already Python's str(int)
                        return err(format!("integer {lit} is beyond ±2^53: send it as a decimal string"));
                    }
                }
            }
            _ => i += 1,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn f(x: f64) -> String {
        float(x).unwrap()
    }

    #[test]
    fn ecmascript_number_formatting() {
        assert_eq!(f(3.0), "3");
        assert_eq!(f(-3.5), "-3.5");
        assert_eq!(f(-0.0), "0");
        assert_eq!(f(1e16), "10000000000000000");
        assert_eq!(f(1e21), "1e+21");
        assert_eq!(f(1e20), "100000000000000000000");
        assert_eq!(f(1e-6), "0.000001");
        assert_eq!(f(1e-7), "1e-7");
        assert_eq!(f(1.2345678901234568e20), "123456789012345680000");
        assert_eq!(f(4.5e21), "4.5e+21");
        assert_eq!(f(5e-324), "5e-324");
        assert_eq!(f(1.7976931348623157e308), "1.7976931348623157e+308");
        assert_eq!(f(0.1), "0.1");
        assert_eq!(f(123.456), "123.456");
        assert_eq!(f(1.5e-7), "1.5e-7");
        assert_eq!(f(2500000000000000.0), "2500000000000000");
        assert_eq!(f("2330662528422.65625".parse().unwrap()), "2330662528422.6562"); // a tie at 17 digits: the even one
        assert_eq!(f(1e15), "1000000000000000");
        assert_eq!(f(0.000123), "0.000123");
        assert!(float(f64::NAN).is_err() && float(f64::INFINITY).is_err() && float(f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn integers_are_range_checked_but_integral_floats_are_not() {
        assert_eq!(canonical_json(&json!(9007199254740992u64)).unwrap(), "9007199254740992");
        assert_eq!(canonical_json(&json!(-9007199254740992i64)).unwrap(), "-9007199254740992");
        assert!(canonical_json(&json!(9007199254740993u64)).is_err());
        assert!(canonical_json(&json!(-9007199254740993i64)).is_err());
        assert!(canonical_json(&json!(u64::MAX)).is_err());
        assert_eq!(canonical_json(&json!(1e16)).unwrap(), "10000000000000000");
        assert!(canonical_json_str("10000000000000000").is_err());
        assert!(canonical_json_str("[1, 100000000000000000000000000000000000000000]").is_err());
        assert!(canonical_json_str("-9007199254740993").is_err());
        assert_eq!(canonical_json_str("1e16").unwrap(), "10000000000000000");
        assert_eq!(canonical_json_str("-0").unwrap(), "0");
        assert_eq!(canonical_json_str("[3, 3.0, 3e0, 0.3e1]").unwrap(), "[3,3,3,3]");
        assert_eq!(canonical_json_str("\"9007199254740993\"").unwrap(), "\"9007199254740993\"");
        assert_eq!(canonical_json_str("{\"k\\\"99999999999999999\": 1}").unwrap(), "{\"k\\\"99999999999999999\":1}");
    }

    #[test]
    fn refusals() {
        for bad in ["NaN", "Infinity", "-Infinity", "1e400", "[1,", "\"\\ud800\""] {
            assert!(canonical_json_str(bad).is_err(), "{bad}");
        }
        let e = canonical_json_str("9007199254740993").unwrap_err();
        assert_eq!(e.0, "integer 9007199254740993 is beyond ±2^53: send it as a decimal string");
    }

    #[test]
    fn keys_sort_by_utf16_code_units_and_strings_escape_minimally() {
        let v = json!({"\u{ffff}": 1, "\u{1f600}": 2, "a": 3, "é": 4, "€": 5});
        assert_eq!(canonical_json(&v).unwrap(), "{\"a\":3,\"é\":4,\"€\":5,\"\u{1f600}\":2,\"\u{ffff}\":1}");
        let s = json!("\u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f}\"\\/é");
        assert_eq!(canonical_json(&s).unwrap(), "\"\\b\\f\\n\\r\\t\\u0001\\u001f\u{7f}\\\"\\\\/é\"");
    }

    #[test]
    fn job_keys() {
        let a = job_key("dev.x.y", "c", &json!({"n": 3}), None).unwrap();
        assert_eq!(a, job_key("dev.x.y", "c", &json!({"n": 3.0}), None).unwrap());
        assert_eq!(a, job_key("dev.x.y", "c", &json!({"n": 3}), Some("")).unwrap());
        assert_eq!(format!("{a}:score"), job_key("dev.x.y", "c", &json!({"n": 3}), Some("score")).unwrap());
        assert_ne!(a, job_key("dev.x.y", "c2", &json!({"n": 3}), None).unwrap());
        assert_eq!(a.len(), 64);
    }
}
