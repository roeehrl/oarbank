//! What the sandboxed-process tests share: the test's Python, found as the agent finds the node's, and the argv that
//! runs a process under the module sandbox.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A fresh directory under the system temp dir: (what removes it when dropped, its path).
pub fn scratch(name: &str) -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::Builder::new().prefix(&format!("oarbank-test-{name}-")).tempdir().unwrap();
    let p = d.path().to_path_buf();
    (d, p)
}

/// The test's Python, found the way runtime.rs finds the node's: OARBANK_TEST_PYTHON (an absolute path), else the node
/// runtime's (Windows), else the first python3 or python on PATH that can run the SDK (3.12+: macOS's /usr/bin/python3
/// is an older Xcode stub). Its path as found, symlinks and all, is argv[0], as for real modules (Homebrew's
/// bin/python3 is a chain of links into the Cellar), and the roots are those runtime.rs's probe reports.
pub fn python() -> (String, Vec<String>) {
    let exe_name = |n: &str| format!("{n}{}", std::env::consts::EXE_SUFFIX);
    let on_path = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect::<Vec<_>>()).unwrap_or_default().into_iter()
        .flat_map(|d| [d.join(exe_name("python3")), d.join(exe_name("python"))]);
    let candidates: Vec<PathBuf> = match std::env::var_os("OARBANK_TEST_PYTHON") {
        Some(p) => vec![PathBuf::from(p)],
        None => cfg!(windows).then(|| PathBuf::from(r"C:\Program Files\Oarbank\runtime\python.exe")).into_iter().chain(on_path).collect(),
    };
    let probe = "import json, os, sys\nassert sys.version_info >= (3, 12)\n\
                 r = {sys.prefix, sys.base_prefix, sys.exec_prefix, sys.executable, os.path.dirname(os.path.realpath(sys.executable))}\n\
                 print(json.dumps(sorted(r | {os.path.realpath(x) for x in r})))";
    for exe in candidates.iter().filter(|p| p.is_file()) {
        let Ok(out) = Command::new(exe).args(["-I", "-c", probe]).output() else { continue };
        if let (true, Ok(roots)) = (out.status.success(), serde_json::from_slice::<Vec<String>>(&out.stdout)) {
            return (exe.display().to_string(), roots);
        }
    }
    panic!("no Python 3.12+ among {candidates:?} (set OARBANK_TEST_PYTHON)");
}

/// argv run under the module sandbox through `oarbank-agent sandbox-exec`, as sandbox.rs `wrap` builds it: `bundle`
/// and `roots` read-only (the profile or policy file is written to `bundle`), `ws` read-write, `py` as argv[0].
pub fn sandboxed(module: &str, bundle: &Path, ws: &Path, py: &str, roots: Vec<String>, argv: &[String]) -> Vec<String> {
    let mut pol = oarbank_core::sandbox::Policy::new(module);
    pol.ro = [vec![bundle.display().to_string()], roots].concat();
    pol.rw = vec![ws.display().to_string()];
    pol.exe = Some(py.to_string());
    let agent = env!("CARGO_BIN_EXE_oarbank-agent").to_string();
    let mut out = vec![agent, "sandbox-exec".into()];
    if cfg!(target_os = "macos") {
        let (text, params) = oarbank_core::sandbox::render(&pol).unwrap();
        let profile = bundle.join("runner.sb");
        std::fs::write(&profile, text).unwrap();
        out.push(profile.display().to_string());
        out.extend(params.iter().map(|(k, v)| format!("{k}={v}")));
    } else {
        let policy = bundle.join("policy.json");
        std::fs::write(&policy, serde_json::to_vec(&pol).unwrap()).unwrap();
        out.push(policy.display().to_string());
    }
    out.push("--".into());
    out.extend(argv.iter().cloned());
    out
}
