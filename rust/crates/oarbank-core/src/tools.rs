//! Host tool versions, constraints and resolution (docs/design/host-tools.md; oarbank-sdk spec/sandbox.md, "Host
//! tools"). The pure decisions the agent shares with the coordinator (`oarbank.coordinator.tools`) and the SDK
//! (`oarbank_sdk.toolversion`), replayed from `spec/vectors/tool-versions.json` and
//! `src/oarbank/contracts/vectors/tool-resolution.json`.
//!
//! Versions: dot-separated numbers (`_` separates too), an optional pre-release (`-ea`, which sorts below its release)
//! and build (`+7`, ignored); missing segments are zero. Constraints: comma-separated clauses `op version`, all of which
//! hold, with Nomad's operators `=` (`==`), `!=`, `>`, `>=`, `<`, `<=` and `~>` (the last given segment may grow).

use serde_json::{json, Value};
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub nums: Vec<u64>,
    pub pre: Option<String>,
    pub text: String,
}

fn ident_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

impl Version {
    pub fn parse(text: &str) -> Result<Version, String> {
        let t = text.trim();
        let bad = || format!("{t:?} is not a version (numbers separated by dots, e.g. 17.0.12)");
        let (rest, build) = match t.split_once('+') {
            Some((a, b)) => (a, Some(b)),
            None => (t, None),
        };
        if build.is_some_and(|b| !ident_ok(b)) {
            return Err(bad());
        }
        let (num, pre) = match rest.split_once('-') {
            Some((a, b)) => (a, Some(b)),
            None => (rest, None),
        };
        if pre.is_some_and(|p| !ident_ok(p)) {
            return Err(bad());
        }
        let mut nums = vec![];
        for seg in num.split(['.', '_']) {
            if seg.is_empty() || !seg.chars().all(|c| c.is_ascii_digit()) {
                return Err(bad());
            }
            nums.push(seg.parse::<u64>().map_err(|_| bad())?);
        }
        Ok(Version { nums, pre: pre.map(str::to_string), text: t.to_string() })
    }

    fn pre_key(&self) -> Vec<(u8, u64, String)> {
        self.pre.as_deref().map(|p| p.split('.').map(|i| {
            if !i.is_empty() && i.chars().all(|c| c.is_ascii_digit()) {
                (0, i.parse::<u64>().unwrap_or(u64::MAX), String::new())
            } else {
                (1, 0, i.to_string())
            }
        }).collect()).unwrap_or_default()
    }

    pub fn compare(&self, other: &Version) -> Ordering {
        let w = self.nums.len().max(other.nums.len());
        for i in 0..w {
            let (a, b) = (self.nums.get(i).copied().unwrap_or(0), other.nums.get(i).copied().unwrap_or(0));
            if a != b {
                return a.cmp(&b);
            }
        }
        match (self.pre.is_none(), other.pre.is_none()) {
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            _ => self.pre_key().cmp(&other.pre_key()),
        }
    }

    /// The canonical spelling: segments joined by dots, the pre-release kept, the build dropped.
    pub fn normalized(&self) -> String {
        let n: Vec<String> = self.nums.iter().map(u64::to_string).collect();
        n.join(".") + &self.pre.as_ref().map(|p| format!("-{p}")).unwrap_or_default()
    }
}

const OPS: [&str; 8] = ["~>", "==", "!=", ">=", "<=", "=", ">", "<"];

/// [(operator, version)] of a constraint (`==` read as `=`).
pub fn parse_constraint(text: &str) -> Result<Vec<(String, Version)>, String> {
    if text.trim().is_empty() {
        return Err("a version constraint is not empty".into());
    }
    let mut out = vec![];
    for part in text.split(',') {
        let p = part.trim();
        let op = OPS.iter().find(|o| p.starts_with(**o)).ok_or_else(|| format!("{p:?} is not an operator and a version"))?;
        let v = p[op.len()..].trim();
        if v.is_empty() || v.chars().any(char::is_whitespace) {
            return Err(format!("{p:?} is not an operator and a version"));
        }
        out.push((if *op == "==" { "=".to_string() } else { op.to_string() }, Version::parse(v)?));
    }
    Ok(out)
}

/// The constraint in its canonical spelling: `>=17,<22` → `>=17, <22`.
pub fn describe(text: &str) -> Result<String, String> {
    Ok(parse_constraint(text)?.iter().map(|(op, v)| format!("{op}{}", v.text)).collect::<Vec<_>>().join(", "))
}

fn clause(v: &Version, op: &str, c: &Version) -> bool {
    if op == "~>" {
        if v.compare(c) == Ordering::Less {
            return false;
        }
        let mut upper: Vec<u64> = if c.nums.len() > 1 { c.nums[..c.nums.len() - 1].to_vec() } else { c.nums.clone() };
        if let Some(last) = upper.last_mut() {
            *last += 1;
        }
        let up = Version { nums: upper, pre: None, text: String::new() };
        return v.compare(&up) == Ordering::Less;
    }
    let r = v.compare(c);
    match op {
        "=" => r == Ordering::Equal,
        "!=" => r != Ordering::Equal,
        ">" => r == Ordering::Greater,
        ">=" => r != Ordering::Less,
        "<" => r == Ordering::Less,
        "<=" => r != Ordering::Greater,
        _ => false,
    }
}

/// Does `version` satisfy `constraint` (None or empty: any version)? An unparseable version satisfies only no
/// constraint; an unparseable constraint none.
pub fn satisfies(version: &str, constraint: Option<&str>) -> bool {
    let Some(c) = constraint.filter(|c| !c.is_empty()) else { return true };
    let (Ok(v), Ok(cs)) = (Version::parse(version), parse_constraint(c)) else { return false };
    cs.iter().all(|(op, cv)| clause(&v, op, cv))
}

/// An architecture as platform tokens name it: aarch64 → arm64, x86_64 → amd64; others lower-cased.
pub fn arch(raw: &str) -> String {
    let r = raw.trim().to_ascii_lowercase();
    match r.as_str() {
        "aarch64" | "arm64" | "arm64e" => "arm64".into(),
        "x86_64" | "amd64" | "x64" | "x86-64" => "amd64".into(),
        _ => r,
    }
}

/// Does an installation of arch `installed` fit a request's `arch` (any, native, arm64, amd64) on a node whose native
/// arch is `native`? An unknown arch fits only `any`.
pub fn arch_fits(installed: &str, want: &str, native: &str) -> bool {
    let have = arch(installed);
    if want.is_empty() || want == "any" {
        return true;
    }
    if have.is_empty() {
        return false;
    }
    have == if want == "native" { arch(native) } else { want.to_string() }
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}

fn ver(i: &Value) -> &str {
    if s(i, "version").is_empty() { "an unknown version" } else { s(i, "version") }
}

fn is_ok(i: &Value) -> bool {
    i["status"].as_str() == Some("ok")
}

fn vcmp(a: &Value, b: &Value) -> Ordering {
    match (Version::parse(s(a, "version")), Version::parse(s(b, "version"))) {
        (Ok(x), Ok(y)) => x.compare(&y),
        (Ok(_), Err(_)) => Ordering::Greater,
        (Err(_), Ok(_)) => Ordering::Less,
        _ => Ordering::Equal,
    }
}

fn fits(i: &Value, req: &Value, native: &str) -> bool {
    satisfies(s(i, "version"), req["version"].as_str()) && arch_fits(s(i, "arch"), req["arch"].as_str().unwrap_or("any"), native)
}

fn needs(req: &Value, native: &str) -> String {
    let mut want = vec![];
    if let Some(v) = req["version"].as_str().filter(|v| !v.is_empty()) {
        want.push(v.to_string());
    }
    match req["arch"].as_str().unwrap_or("any") {
        "any" | "" => {}
        "native" => want.push(format!("native {}", if arch(native).is_empty() { "arch".to_string() } else { arch(native) })),
        a => want.push(a.to_string()),
    }
    if want.is_empty() { "any version".into() } else { want.join(", ") }
}

fn found(ok: &[&Value], native: &str) -> String {
    let mut sorted: Vec<&Value> = ok.to_vec();
    sorted.sort_by(|a, b| vcmp(b, a));
    let parts: Vec<String> = sorted.iter().take(3).map(|i| {
        let v = if s(i, "version").is_empty() { "an unknown version" } else { s(i, "version") };
        let a = if !s(i, "arch").is_empty() && arch(s(i, "arch")) != arch(native) { format!(" ({})", s(i, "arch")) } else { String::new() };
        format!("{v}{a} at {}", s(i, "path"))
    }).collect();
    let more = ok.len() as i64 - 3;
    parts.join(", ") + &if more > 0 { format!(" and {more} more") } else { String::new() }
}

/// Best first: the node's native arch, then the highest version, then the path (ascending).
pub fn order(insts: &mut [&Value], native: &str) {
    let n = arch(native);
    insts.sort_by(|a, b| {
        let (na, nb) = (arch(s(a, "arch")) == n, arch(s(b, "arch")) == n);
        nb.cmp(&na).then_with(|| vcmp(b, a)).then_with(|| s(a, "path").cmp(s(b, "path")))
    });
}

/// The installation a request (`{id, version, arch}`) resolves to among a node's installations: `{status:
/// ok|not_found|version_unmet|refused, code, installation, source: pinned|detected, detail}`, as the coordinator's
/// `tools.resolve` computes it. With a pin, only that installation (matched by its canonical or given path) counts.
pub fn resolve(insts: &[Value], req: &Value, native: &str, pin: Option<&str>) -> Value {
    let tid = s(req, "id");
    let out = |status: &str, inst: Option<&Value>, detail: String, source: Option<&str>| {
        let code = match status {
            "not_found" => json!("TOOL_NOT_FOUND"),
            "version_unmet" => json!("TOOL_VERSION_UNMET"),
            "refused" => json!("TOOL_REFUSED"),
            _ => Value::Null,
        };
        json!({"status": status, "code": code, "installation": inst.cloned().unwrap_or(Value::Null), "source": source, "detail": detail})
    };
    let reason = |i: &Value| { let st = s(i, "status"); st.strip_prefix("refused: ").unwrap_or(st).to_string() };
    if let Some(pin) = pin.filter(|p| !p.is_empty()) {
        let Some(hit) = insts.iter().find(|i| s(i, "path") == pin || s(i, "given") == pin) else {
            return out("refused", None, format!("the path set for {tid} here, {pin}, is not an installation this node found \
                                                 (Re-detect, or set a path the node can verify)"), None);
        };
        if !is_ok(hit) {
            return out("refused", Some(hit), format!("the path set for {tid} here, {pin}, was refused: {}", reason(hit)), None);
        }
        if !fits(hit, req, native) {
            let v = if s(hit, "version").is_empty() { "an unknown version" } else { s(hit, "version") };
            return out("version_unmet", Some(hit), format!("the path set for {tid} here is {v} at {}; needs {}", s(hit, "path"),
                                                           needs(req, native)), None);
        }
        return out("ok", Some(hit), format!("{} at {} (set for this node)", ver(hit), s(hit, "path")), Some("pinned"));
    }
    let ok: Vec<&Value> = insts.iter().filter(|i| is_ok(i)).collect();
    let mut good: Vec<&Value> = ok.iter().copied().filter(|i| fits(i, req, native)).collect();
    if !good.is_empty() {
        order(&mut good, native);
        let best = good[0];
        return out("ok", Some(best), format!("{} at {}", ver(best), s(best, "path")), Some("detected"));
    }
    if !ok.is_empty() {
        return out("version_unmet", None, format!("found {}; needs {}", found(&ok, native), needs(req, native)), None);
    }
    if let Some(i) = insts.iter().find(|i| !is_ok(i)) {
        return out("refused", Some(i), format!("{}: {}", s(i, "path"), reason(i)), None);
    }
    out("not_found", None, format!("no {tid} found on this node"), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sdk_vectors() -> Value {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../vendor/oarbank-sdk/spec/vectors/tool-versions.json");
        serde_json::from_str(&std::fs::read_to_string(p).expect("the SDK's tool-versions.json")).unwrap()
    }

    #[test]
    fn versions_and_constraints_replay_the_sdk_vectors() {
        let v = sdk_vectors();
        for (raw, want) in v["normalized"].as_object().unwrap() {
            assert_eq!(Version::parse(raw).unwrap().normalized(), want.as_str().unwrap(), "{raw}");
        }
        for bad in v["versions_bad"].as_array().unwrap() {
            assert!(Version::parse(bad.as_str().unwrap()).is_err(), "{bad}");
        }
        let asc: Vec<&str> = v["ascending"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
        let mut sorted = asc.clone();
        sorted.sort_by(|a, b| Version::parse(a).unwrap().compare(&Version::parse(b).unwrap()));
        assert_eq!(sorted, asc);
        for c in v["constraints"].as_array().unwrap() {
            let text = c["constraint"].as_str().unwrap();
            assert_eq!(describe(text).unwrap(), c["canonical"].as_str().unwrap());
            for (ver, ok) in c["matches"].as_object().unwrap() {
                assert_eq!(satisfies(ver, Some(text)), ok.as_bool().unwrap(), "{ver} {text}");
            }
        }
        for bad in v["constraints_bad"].as_array().unwrap() {
            assert!(parse_constraint(bad.as_str().unwrap()).is_err(), "{bad}");
        }
        for a in v["arch"].as_array().unwrap() {
            assert_eq!(arch_fits(s(a, "installed"), s(a, "want"), s(a, "native")), a["fits"].as_bool().unwrap(), "{a}");
        }
    }

    #[test]
    fn resolution_replays_the_coordinators_vectors() {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/oarbank/contracts/vectors/tool-resolution.json");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(p).expect("tool-resolution.json")).unwrap();
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 10);
        for c in cases {
            let insts = c["installations"].as_array().cloned().unwrap_or_default();
            let got = resolve(&insts, &c["request"], s(c, "native"), c["pin"].as_str());
            assert_eq!(got, c["resolved"], "{}", c["name"]);
        }
    }
}
