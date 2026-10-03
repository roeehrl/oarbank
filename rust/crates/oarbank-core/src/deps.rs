//! A module's Python dependencies (spec/bundles.md, "Dependencies"), as the SDK's `deps.py`: hash-pinned
//! requirements and the wheel filenames that fit a platform.
//!
//! - `requirements.txt` lists every distribution as `name==version --hash=sha256:<64 hex>`; options, markers,
//!   unpinned or unhashed lines and host-provided distributions are refused.
//! - A wheel fits a platform when its tags cover it and CPython 3.12 (`cp312`): pure `py3-none`, exactly `cp312`, or
//!   `abi3` for cp3x <= 312.
//!
//! Like `portable`, the wheel name pattern is anchored strictly: Python's `$` also matches before a trailing newline.

use std::collections::BTreeSet;

use crate::{portable, py};

pub const WHEELS_DIR: &str = "wheels";
/// The hosts' managed CPython (spec/manifest.md, runtime kind python).
pub const PY_TAG: &str = "cp312";
/// Distributions the host provides; a module must not pin them.
pub const HOST_PROVIDED: [&str; 6] =
    ["oarbank-sdk", "pydantic", "pydantic-core", "annotated-types", "typing-extensions", "typing-inspection"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct DepsError(pub String);

/// One pinned distribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// Normalised (`norm`).
    pub name: String,
    pub version: String,
    pub hashes: BTreeSet<String>,
}

/// The tags of a wheel filename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheelTags {
    pub dist: String,
    pub version: String,
    pub py: Vec<String>,
    pub abi: Vec<String>,
    pub plat: Vec<String>,
}

/// PEP 503 name normalisation: runs of `-_.` become `-`, lowercase.
pub fn norm(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut in_run = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !in_run {
                out.push('-');
            }
            in_run = true;
        } else {
            out.push(c);
            in_run = false;
        }
    }
    out.to_lowercase()
}

/// `^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?==([A-Za-z0-9.+!_-]+)(.*)$` -> (name, version, rest).
fn match_pin(line: &str) -> Option<(&str, &str, &str)> {
    let b = line.as_bytes();
    if !b.first()?.is_ascii_alphanumeric() {
        return None;
    }
    let name_ch = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-');
    let mut i = 1;
    while i < b.len() && name_ch(b[i]) {
        i += 1;
    }
    let name = &line[..i];
    let mut j = i;
    if b.get(j) == Some(&b'[') {
        let close = line[j + 1..].find(']')? + j + 1;
        j = close + 1;
    }
    if !line[j..].starts_with("==") {
        return None;
    }
    j += 2;
    let ver_ch = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'!' | b'_' | b'-');
    let start = j;
    while j < b.len() && ver_ch(b[j]) {
        j += 1;
    }
    if j == start {
        return None;
    }
    Some((name, &line[start..j], &line[j..]))
}

/// `re.findall(r"--hash=sha256:([0-9a-f]{64})", rest)`.
fn find_hashes(rest: &str) -> Vec<String> {
    const P: &str = "--hash=sha256:";
    let b = rest.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if rest[i..].starts_with(P) {
            let h = &b[i + P.len()..];
            if h.len() >= 64 && h[..64].iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c)) {
                out.push(String::from_utf8_lossy(&h[..64]).into_owned());
                i += P.len() + 64;
                continue;
            }
        }
        i += rest[i..].chars().next().map_or(1, char::len_utf8);
    }
    out
}

/// The pins of a hash-pinned requirements file; DepsError (every problem, `; `-joined) on anything else.
pub fn parse_requirements(text: &str) -> Result<Vec<Requirement>, DepsError> {
    let joined = text.replace("\\\n", " ");
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for (idx, raw) in py::splitlines(&joined).into_iter().enumerate() {
        let n = idx + 1;
        let line = py::strip(raw.split(" #").next().unwrap_or(raw));
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('-') {
            let opt = line.split(py::isspace).find(|s| !s.is_empty()).unwrap_or(line);
            errors.push(format!("line {n}: options are not allowed ({opt}): the host installs offline from wheels/"));
            continue;
        }
        let Some((name, ver, rest)) = match_pin(line) else {
            let head: String = line.chars().take(60).collect();
            errors.push(format!("line {n}: {} is not `name==version --hash=sha256:...`", py::repr(&head)));
            continue;
        };
        let name = norm(name);
        if rest.split("--hash").next().unwrap_or(rest).contains(';') {
            errors.push(format!("line {n}: environment markers are not allowed; ship wheels for every platform instead"));
        }
        let hashes = find_hashes(rest);
        if hashes.is_empty() {
            errors.push(format!(
                "line {n}: {name}=={ver} has no --hash=sha256 (generate with `uv pip compile --generate-hashes`)"
            ));
        }
        if HOST_PROVIDED.contains(&name.as_str()) {
            errors.push(format!("line {n}: {name} is provided by the host; do not pin it"));
        }
        out.push(Requirement { name, version: ver.to_string(), hashes: hashes.into_iter().collect() });
    }
    if !errors.is_empty() {
        return Err(DepsError(errors.join("; ")));
    }
    Ok(out)
}

/// The tags of `<dist>-<ver>[-<build>]-<py>-<abi>-<plat>.whl` (compressed tag sets split on `.`); None otherwise.
pub fn wheel_tags(filename: &str) -> Option<WheelTags> {
    let stem = filename.strip_suffix(".whl")?;
    let seg: Vec<&str> = stem.split('-').collect();
    if seg.iter().any(|s| s.is_empty()) {
        return None;
    }
    let (dist, ver, py, abi, plat) = match seg.len() {
        5 => (seg[0], seg[1], seg[2], seg[3], seg[4]),
        6 if seg[2].starts_with(|c: char| c.is_ascii_digit()) => (seg[0], seg[1], seg[3], seg[4], seg[5]),
        _ => return None,
    };
    let split = |s: &str| s.split('.').map(str::to_string).collect::<Vec<_>>();
    Some(WheelTags { dist: norm(dist), version: ver.to_string(), py: split(py), abi: split(abi), plat: split(plat) })
}

fn plat_ok(tag: &str, platform: &str) -> bool {
    let (os, arch) = portable::split_platform(platform);
    if tag == "any" {
        return true;
    }
    match os {
        "darwin" => {
            tag.starts_with("macosx_")
                && (tag.ends_with("_universal2")
                    || tag.ends_with(if arch == "arm64" { "_arm64" } else { "_x86_64" })
                    || (arch == "amd64" && tag.ends_with("_intel")))
        }
        "linux" => {
            let a = match arch {
                "amd64" => "x86_64",
                "arm64" => "aarch64",
                other => other,
            };
            (tag.starts_with("manylinux") || tag.starts_with("musllinux") || tag.starts_with("linux_"))
                && tag.ends_with(&format!("_{a}"))
        }
        "windows" => match arch {
            "amd64" => tag == "win_amd64",
            "arm64" => tag == "win_arm64",
            _ => false,
        },
        _ => false,
    }
}

/// Pure wheels (py3/none), wheels for exactly this CPython, and abi3 wheels for this CPython or older.
fn py_ok(t: &WheelTags, py_tag: &str) -> Result<bool, DepsError> {
    let mine_s: String = py_tag.chars().skip(2).collect();
    let mine = py::int(&mine_s, 10)
        .ok_or_else(|| DepsError(format!("invalid literal for int() with base 10: {}", py::repr(&mine_s))))?;
    for p in &t.py {
        for a in &t.abi {
            if p.starts_with("py3") && a == "none" {
                return Ok(true);
            }
            if p == py_tag && (a == py_tag || a == "none" || a == "abi3") {
                return Ok(true);
            }
            if a == "abi3" && p.starts_with("cp3") && p[2..].bytes().all(|c| c.is_ascii_digit()) {
                if let Ok(v) = p[2..].parse::<i128>() {
                    if v <= mine {
                        return Ok(true);
                    }
                }
            }
        }
    }
    Ok(false)
}

/// Whether a wheel filename fits a platform token on the hosts' CPython (`cp312`).
pub fn wheel_fits(filename: &str, platform: &str) -> bool {
    wheel_fits_py(filename, platform, PY_TAG).unwrap_or(false)
}

/// `wheel_fits` for another CPython tag; Err where Python's `int(py[2:])` raises.
pub fn wheel_fits_py(filename: &str, platform: &str, py_tag: &str) -> Result<bool, DepsError> {
    let Some(t) = wheel_tags(filename) else { return Ok(false) };
    Ok(py_ok(&t, py_tag)? && t.plat.iter().any(|p| plat_ok(p, platform)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_and_hashes_are_required() {
        let h = "a".repeat(64);
        let r = parse_requirements(&format!("a==1 --hash=sha256:{h}")).unwrap();
        assert_eq!(r[0].version, "1");
        assert_eq!(r[0].hashes.iter().next().unwrap(), &h);
        for bad in ["a==1".to_string(), format!("a>=1 --hash=sha256:{h}"), "--extra-index-url https://x".into(),
                    format!("pydantic==2 --hash=sha256:{h}"), format!("a==1 ; python_version>'3' --hash=sha256:{h}"),
                    format!("-e . --hash=sha256:{h}"), format!("a[x==1 --hash=sha256:{h}"), format!("a== --hash=sha256:{h}")] {
            assert!(parse_requirements(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn requirement_file_shapes() {
        let (h1, h2) = ("0".repeat(64), "f".repeat(64));
        let text = format!(
            "# compiled\n\nFoo_Bar.baz[extra]==1.0.post1 \\\n    --hash=sha256:{h1} \\\n    --hash=sha256:{h2}  # via x\nqux==2!3+local --hash=sha256:{h1}\r\n"
        );
        let r = parse_requirements(&text).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].name, "foo-bar-baz");
        assert_eq!(r[0].version, "1.0.post1");
        assert_eq!(r[0].hashes.len(), 2);
        assert_eq!(r[1].version, "2!3+local");
        assert!(parse_requirements("").unwrap().is_empty());
        let e = parse_requirements(&format!("a==1\n--index-url x\nPydantic_Core==2 --hash=sha256:{h1}\n!!")).unwrap_err().0;
        assert_eq!(
            e,
            "line 1: a==1 has no --hash=sha256 (generate with `uv pip compile --generate-hashes`); \
             line 2: options are not allowed (--index-url): the host installs offline from wheels/; \
             line 3: pydantic-core is provided by the host; do not pin it; \
             line 4: '!!' is not `name==version --hash=sha256:...`"
        );
        // an uppercase or short hash is no hash
        assert!(parse_requirements(&format!("a==1 --hash=sha256:{}", "A".repeat(64))).is_err());
        assert!(parse_requirements(&format!("a==1 --hash=sha256:{}", "a".repeat(63))).is_err());
    }

    #[test]
    fn wheel_tags_and_fit() {
        let t = wheel_tags("Foo_Bar-1.0-1b-cp312-cp312-macosx_11_0_arm64.macosx_11_0_x86_64.whl").unwrap();
        assert_eq!(t.dist, "foo-bar");
        assert_eq!(t.plat, vec!["macosx_11_0_arm64", "macosx_11_0_x86_64"]);
        for bad in ["a-1-py3-none.whl", "a-1-b-py3-none-any.whl", "a-1-py3-none-any.tar.gz", "a--py3-none-any.whl",
                    "a-1-py3-none-any.whl\n", "a-1-2-3-py3-none-any.whl"] {
            assert!(wheel_tags(bad).is_none(), "{bad:?}");
        }
        let fits = |f: &str, p: &str| wheel_fits(f, p);
        assert!(fits("dep-1.0-cp312-cp312-macosx_11_0_arm64.whl", "darwin-arm64"));
        assert!(!fits("dep-1.0-cp312-cp312-macosx_11_0_arm64.whl", "linux-amd64"));
        assert!(fits("dep-1.0-py3-none-any.whl", "windows-arm64"));
        assert!(fits("dep-1.0-py2.py3-none-any.whl", "linux-arm64"));
        assert!(fits("dep-1.0-cp39-abi3-manylinux_2_17_x86_64.whl", "linux-amd64"));
        assert!(!fits("dep-1.0-cp313-abi3-manylinux_2_17_x86_64.whl", "linux-amd64"));
        assert!(!fits("dep-1.0-cp311-cp311-manylinux_2_17_x86_64.whl", "linux-amd64"));
        assert!(fits("dep-1.0-cp312-none-musllinux_1_2_aarch64.whl", "linux-arm64"));
        assert!(fits("dep-1.0-cp312-cp312-macosx_10_9_universal2.whl", "darwin-amd64"));
        assert!(fits("dep-1.0-cp312-cp312-macosx_10_9_intel.whl", "darwin-amd64"));
        assert!(!fits("dep-1.0-cp312-cp312-macosx_10_9_intel.whl", "darwin-arm64"));
        assert!(fits("dep-1.0-cp312-cp312-win_amd64.whl", "windows-amd64"));
        assert!(!fits("dep-1.0-cp312-cp312-win_amd64.whl", "windows-arm64"));
        assert!(!fits("dep-1.0-cp312-cp312-win_amd64.whl", "plan9-mips"));
        assert!(fits("dep-1.0-cp312-cp312-linux_riscv64.whl", "linux-riscv64"));
        assert!(wheel_fits_py("dep-1.0-cp313-abi3-any.whl", "linux-amd64", "cp313").unwrap());
        assert!(wheel_fits_py("dep-1.0-cp313-abi3-any.whl", "linux-amd64", "x").is_err());
        assert!(!wheel_fits_py("not-a-wheel", "linux-amd64", "x").unwrap());
    }
}
