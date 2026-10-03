//! A sandboxed interpreter reached through symlinks, the way Homebrew's Python is: bin/python3 and opt/python@3.x are
//! links into the Cellar, and that CPython realpath()s its own location at startup with realpath(3), which gives up at
//! the first lstat refused on the way. The links and the directories above them must be resolvable inside the sandbox
//! (macOS: metadata rules on each hop and its ancestors; Linux: Landlock does not govern lookups; Windows: junctions
//! are followed for the container), and nothing beside them may become readable.

mod common;

use common::{python, sandboxed, scratch};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Prints what the interpreter could resolve and read; argv: a directory holding a link, a file beside a link.
const PROBE: &str = r#"
import json, os, sys
r = {"stat": os.stat(sys.executable).st_size > 0}
if os.name != "nt":                                      # an AppContainer cannot ask for any final path, links or not
    r["real"] = os.path.realpath(sys.executable, strict=True)
for n, f in (("list", lambda: os.listdir(sys.argv[1])), ("beside", lambda: open(sys.argv[2]).read())):
    try:
        f()
        r[n] = True
    except OSError:
        r[n] = False
print(json.dumps(r))
"#;

/// Homebrew's layout under `brew`, ending at the interpreter `real`: bin/python3 -> ../opt/python@9/bin/python3,
/// opt/python@9 -> ../Cellar/python@9/9.0, Cellar/python@9/9.0/bin/python3 -> `real`. Returns argv[0], a directory
/// holding a link, and a file beside a link.
#[cfg(unix)]
fn brew_layout(brew: &Path, real: &Path) -> (PathBuf, PathBuf, PathBuf) {
    use std::os::unix::fs::symlink;
    let keg = brew.join("Cellar/python@9/9.0");
    for d in [keg.join("bin"), brew.join("opt"), brew.join("bin")] {
        std::fs::create_dir_all(d).unwrap();
    }
    symlink(real, keg.join("bin/python3")).unwrap();
    symlink("../Cellar/python@9/9.0", brew.join("opt/python@9")).unwrap();
    symlink("../opt/python@9/bin/python3", brew.join("bin/python3")).unwrap();
    std::fs::write(brew.join("bin/secret"), "s").unwrap();
    (brew.join("bin/python3"), brew.join("bin"), brew.join("bin/secret"))
}

/// The same chain with junctions (no privilege needed): opt\python@9 -> Cellar\python@9\9.0 -> the interpreter's
/// directory.
#[cfg(windows)]
fn brew_layout(brew: &Path, real: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let junction = |link: &Path, target: &Path| {
        let st = Command::new("cmd").arg("/c").arg("mklink").arg("/J").arg(link).arg(target).output().unwrap();
        assert!(st.status.success(), "mklink /J {}: {}", link.display(), String::from_utf8_lossy(&st.stderr));
    };
    std::fs::create_dir_all(brew.join(r"Cellar\python@9")).unwrap();
    std::fs::create_dir_all(brew.join("opt")).unwrap();
    junction(&brew.join(r"Cellar\python@9\9.0"), real.parent().unwrap());
    junction(&brew.join(r"opt\python@9"), &brew.join(r"Cellar\python@9\9.0"));
    std::fs::write(brew.join(r"opt\secret.txt"), "s").unwrap();
    (brew.join(r"opt\python@9").join(real.file_name().unwrap()), brew.join("opt"), brew.join(r"opt\secret.txt"))
}

/// `canonicalize` without Windows' `\\?\` prefix, which mklink and the sandbox policy take as written.
fn real_path(p: &str) -> PathBuf {
    let r = std::fs::canonicalize(p).unwrap().display().to_string();
    PathBuf::from(r.strip_prefix(r"\\?\").unwrap_or(&r))
}

#[test]
fn an_interpreter_behind_symlink_hops_starts_and_reads_no_more() {
    let (py, roots) = python();
    let real = real_path(&py);
    let (brew, bundle, ws) = (scratch("brew"), scratch("links-bundle"), scratch("links-ws"));
    let (exe, link_dir, beside) = brew_layout(&brew, &real);
    std::fs::write(bundle.join("probe.py"), PROBE).unwrap();
    let exe = exe.display().to_string();
    let argv = sandboxed("dev.test.links", &bundle, &ws, &exe, roots, &[exe.clone(), "-I".into(), bundle.join("probe.py").display().to_string(),
                                                                       link_dir.display().to_string(), beside.display().to_string()]);
    let out = Command::new(&argv[0]).args(&argv[1..]).current_dir(&ws).output().unwrap();
    assert!(out.status.success(), "{:?}\n{}", out.status, String::from_utf8_lossy(&out.stderr));
    let got: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let mut want = serde_json::json!({"stat": true, "list": false, "beside": false});
    if cfg!(unix) {
        want["real"] = real.display().to_string().into();
    }
    assert_eq!(got, want);
    for d in [&brew, &bundle, &ws] {
        let _ = std::fs::remove_dir_all(d);
    }
}
