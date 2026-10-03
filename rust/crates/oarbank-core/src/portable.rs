//! Cross-platform foundations (spec/platforms.md): platform tokens and portable paths, as the SDK's `portable.py`.
//!
//! Every path that crosses the protocol (bundle files, artifacts, mounts, dataset files, module files, move rules) is
//! a PortablePath: valid on macOS, Linux and Windows alike, so a bundle built on one OS unpacks safely on another and
//! no name can escape its directory or collide on a case-insensitive filesystem.
//!
//! One deliberate difference: the SDK's regexes end in `$`, which in Python also matches before a trailing newline,
//! so it accepts `"a\n"` as a path and `"linux-amd64\n"` as a platform token. Both are refused here.

use std::collections::HashMap;

use crate::py;

pub const OSES: [&str; 3] = ["darwin", "linux", "windows"];
pub const ARCHES: [&str; 2] = ["arm64", "amd64"];
pub const KNOWN_PLATFORMS: [&str; 6] =
    ["darwin-arm64", "darwin-amd64", "linux-arm64", "linux-amd64", "windows-arm64", "windows-amd64"];

/// `<os>-<arch>` (`^[a-z][a-z0-9]*-[a-z0-9_]+$`). Unknown but well-formed tokens are valid: they mean "no node of
/// this platform here".
pub fn is_platform_token(s: &str) -> bool {
    let Some((os, arch)) = s.split_once('-') else { return false };
    let mut oc = os.bytes();
    matches!(oc.next(), Some(b'a'..=b'z'))
        && oc.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && !arch.is_empty()
        && arch.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// `linux-amd64` -> (`linux`, `amd64`) (Python's `str.partition`: no dash gives an empty arch).
pub fn split_platform(token: &str) -> (&str, &str) {
    token.split_once('-').unwrap_or((token, ""))
}

/// `linux-amd64` -> `linux/amd64` (container image platforms use the OCI spelling).
pub fn oci_platform(token: &str) -> String {
    let (o, a) = split_platform(token);
    format!("{o}/{a}")
}

/// This build's platform token (the Rust target, the same answer the SDK's `host_platform()` gives natively).
pub fn host_platform() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other, // linux, windows, freebsd, ...
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{os}-{arch}")
}

pub const MAX_PATH_BYTES: usize = 200;
pub const MAX_SEGMENT: usize = 100;

/// Windows device names, refused as a segment's stem in any case (`con.txt`, `a/NUL`, `COM¹`).
pub const RESERVED: [&str; 32] = [
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
    "COM8", "COM9", "COM¹", "COM²", "COM³", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
    "LPT9", "LPT¹", "LPT²", "LPT³",
];

fn is_reserved(stem: &str) -> bool {
    RESERVED.contains(&stem.to_uppercase().as_str())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PathError(pub String);

/// `^[A-Za-z0-9_+@-][A-Za-z0-9._+@-]*\z`
fn segment_ok(body: &str) -> bool {
    let ok = |c: u8, first: bool| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'+' | b'@' | b'-') || (!first && c == b'.');
    let mut it = body.bytes();
    match it.next() {
        Some(c) if ok(c, true) => it.all(|c| ok(c, false)),
        _ => false,
    }
}

/// Err unless `path` is a PortablePath (spec/platforms.md, "Portable paths"); returns it.
pub fn check_portable_path(path: &str, allow_dotfiles: bool) -> Result<&str, PathError> {
    let r = py::repr(path);
    let fail = |m: String| Err(PathError(m));
    if path.is_empty() {
        return fail("empty path".into());
    }
    // ASCII strings are always NFC, so the SDK's NFC check never decides anything this one does not.
    if !path.is_ascii() {
        return fail(format!("{r}: only ASCII names are portable"));
    }
    if path.len() > MAX_PATH_BYTES {
        return fail(format!("{r}: longer than {MAX_PATH_BYTES} bytes"));
    }
    if path.starts_with('/') || path.contains('\\') || path.contains(':') {
        return fail(format!("{r}: must be relative and '/'-separated (no '\\', ':' or drive letters)"));
    }
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return fail(format!("{r}: empty, '.' or '..' segment"));
        }
        if seg.len() > MAX_SEGMENT {
            return fail(format!("{r}: segment longer than {MAX_SEGMENT}"));
        }
        let body = if allow_dotfiles && seg.starts_with('.') && seg.len() > 1 { &seg[1..] } else { seg };
        if !segment_ok(body) {
            return fail(format!("{r}: segment {} has a character that is not portable", py::repr(seg)));
        }
        if seg.ends_with('.') || seg.ends_with(' ') {
            return fail(format!("{r}: segment {} ends with '.' or a space", py::repr(seg)));
        }
        if is_reserved(seg.split('.').next().unwrap_or(seg)) {
            return fail(format!("{r}: {} is a reserved device name on Windows", py::repr(seg)));
        }
    }
    Ok(path)
}

pub fn is_portable_path(path: &str, allow_dotfiles: bool) -> bool {
    check_portable_path(path, allow_dotfiles).is_ok()
}

/// Python's `str.casefold` for the inputs that matter: exact for ASCII (every PortablePath); other characters use
/// Unicode lowercase plus the common full foldings, which is close to but not exactly casefold.
pub fn casefold(s: &str) -> String {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'ß' | 'ẞ' => out.push_str("ss"),
            'ſ' => out.push('s'),
            'ς' => out.push('σ'),
            c => out.extend(c.to_lowercase()),
        }
    }
    out
}

/// Pairs of paths that would collide on a case-insensitive filesystem (NTFS, APFS by default), first seen first.
pub fn casefold_collisions<S: AsRef<str>>(paths: &[S]) -> Vec<(String, String)> {
    let mut seen: HashMap<String, &str> = HashMap::new();
    let mut out = Vec::new();
    for p in paths {
        let p = p.as_ref();
        let k = casefold(p);
        match seen.get(&k) {
            Some(first) if *first != p => out.push((first.to_string(), p.to_string())),
            Some(_) => {}
            None => {
                seen.insert(k, p);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_tokens() {
        for ok in ["darwin-arm64", "linux-amd64", "windows-arm64", "freebsd-amd64", "linux-riscv64", "plan9-mips", "a-_"] {
            assert!(is_platform_token(ok), "{ok}");
        }
        for bad in ["darwin", "Darwin-arm64", "linux_amd64", "linux-", "-arm64", "linux-amd64-musl!", "", "linux-amd64\n", "1x-a", "linux-AMD64"] {
            assert!(!is_platform_token(bad), "{bad:?}");
        }
        assert!(KNOWN_PLATFORMS.iter().all(|p| is_platform_token(p)));
        assert_eq!(KNOWN_PLATFORMS.len(), OSES.len() * ARCHES.len());
        assert_eq!(oci_platform("linux-amd64"), "linux/amd64");
        assert_eq!(split_platform("linux-amd64-musl"), ("linux", "amd64-musl"));
        assert_eq!(split_platform("darwin"), ("darwin", ""));
        let h = host_platform();
        assert!(is_platform_token(&h), "{h}");
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            assert_eq!(h, "darwin-arm64");
        }
    }

    #[test]
    fn portable_path_rules_and_messages() {
        assert_eq!(check_portable_path("a/b.txt", false), Ok("a/b.txt"));
        assert!(!is_portable_path(".env", false) && is_portable_path(".env", true));
        assert!(!is_portable_path("..env", true));
        assert!(!is_portable_path(".", true) && !is_portable_path("..", true));
        assert!(!is_portable_path("a\n", false) && !is_portable_path("a\n/b", true));
        assert!(is_portable_path(&"x".repeat(100), false) && !is_portable_path(&"x".repeat(101), false));
        let long = vec!["y"; 101].join("/");
        assert!(long.len() > MAX_PATH_BYTES && !is_portable_path(&long, false));
        for dev in ["CON", "con.txt", "a/NUL", "lpt9.log", "Aux.tar.gz", "conin$", "COM0"] {
            assert!(!is_portable_path(dev, true), "{dev}");
        }
        assert!(is_portable_path("CONSOLE", false) && is_portable_path("com10", false) && is_portable_path("x.con", false));
        let m = |p: &str| check_portable_path(p, false).unwrap_err().0;
        assert_eq!(m(""), "empty path");
        assert_eq!(m("naïve"), "'naïve': only ASCII names are portable");
        assert_eq!(m("C:/x"), "'C:/x': must be relative and '/'-separated (no '\\', ':' or drive letters)");
        assert_eq!(m("a//b"), "'a//b': empty, '.' or '..' segment");
        assert_eq!(m("q?"), "'q?': segment 'q?' has a character that is not portable");
        assert_eq!(m("trail."), "'trail.': segment 'trail.' ends with '.' or a space");
        assert_eq!(m("a/con.txt"), "'a/con.txt': 'con.txt' is a reserved device name on Windows");
        assert_eq!(m("it's"), "\"it's\": segment \"it's\" has a character that is not portable");
    }

    #[test]
    fn collisions() {
        assert_eq!(casefold_collisions(&["Readme.md", "README.md"]), vec![("Readme.md".into(), "README.md".into())]);
        assert!(casefold_collisions(&["a", "a", "b"]).is_empty());
        assert_eq!(casefold_collisions(&["a/B", "x", "a/b", "A/b"]).len(), 2);
        assert_eq!(casefold("Straße"), "strasse");
    }
}
