//! The module sandbox, per OS (spec/sandbox.md; docs/design/architecture.md, "The module sandbox"): one policy
//! (oarbank-core's `Policy`), three backends. Every module process starts through `oarbank-agent sandbox-exec`, which
//! confines itself (macOS Seatbelt, Linux Landlock + seccomp) and then execs the module, or (Windows) starts it inside
//! an AppContainer and waits for it. The parent verifies the confinement after the spawn and kills a process that is
//! not confined.

use oarbank_core::sandbox::Policy;
use serde_json::{json, Value};
use std::path::Path;

/// Whether this node can confine module processes at all (else it reports no backend and gets no module work).
pub fn available() -> bool {
    #[cfg(target_os = "macos")]
    return true;
    #[cfg(target_os = "linux")]
    return crate::sandbox_linux::available();
    #[cfg(windows)]
    return crate::sandbox_windows::available();
    #[allow(unreachable_code)]
    false
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_file_name(format!(".{}.{:?}.tmp", path.file_name().and_then(|n| n.to_str()).unwrap_or("p"),
                                          std::thread::current().id()));
    std::fs::write(&tmp, data).and_then(|_| std::fs::rename(&tmp, path)).map_err(|e| format!("sandbox policy {}: {e}", path.display()))
}

/// This executable, which every module process starts through.
pub fn me() -> String {
    std::env::current_exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| "oarbank-agent".into())
}

/// Write what the launcher needs for `pol` to `path` (a Seatbelt profile, or the policy as JSON) and return the argv
/// that runs `argv` confined.
#[cfg(target_os = "macos")]
pub fn wrap(pol: &Policy, path: &Path, argv: &[String]) -> Result<Vec<String>, String> {
    let (text, params) = oarbank_core::sandbox::render(pol).map_err(|e| format!("sandbox: {}", e.0))?;
    write_atomic(path, text.as_bytes())?;
    Ok(crate::seatbelt::launch_argv(path, &params, argv))
}

#[cfg(not(target_os = "macos"))]
pub fn wrap(pol: &Policy, path: &Path, argv: &[String]) -> Result<Vec<String>, String> {
    write_atomic(path, &serde_json::to_vec(pol).map_err(|e| e.to_string())?)?;
    let mut out = vec![me(), "sandbox-exec".into(), path.to_string_lossy().to_string(), "--".into()];
    out.extend(argv.iter().cloned());
    Ok(out)
}

/// Whether the process started through `wrap` is confined (on Windows: the AppContainer child of the launcher shim).
pub fn is_confined(pid: i32) -> bool {
    #[cfg(target_os = "macos")]
    return crate::seatbelt::is_sandboxed(pid as u32);
    #[cfg(target_os = "linux")]
    return crate::sandbox_linux::is_confined(pid);
    #[cfg(windows)]
    return crate::sandbox_windows::is_confined(pid);
    #[allow(unreachable_code)]
    {
        let _ = pid;
        false
    }
}

/// `oarbank-agent sandbox-exec …`: never returns.
pub fn exec(args: &[String]) -> ! {
    #[cfg(target_os = "macos")]
    crate::seatbelt::exec(args);
    #[cfg(target_os = "linux")]
    crate::sandbox_linux::exec(args);
    #[cfg(windows)]
    crate::sandbox_windows::exec(args);
    #[allow(unreachable_code)]
    {
        let _ = args;
        eprintln!("sandbox launch: no sandbox backend on this OS");
        std::process::exit(70)
    }
}

/// The facts' `sandbox`: the backend and, per capability, `enforced`, `cooperative` or `unavailable`.
pub fn report() -> Value {
    #[cfg(target_os = "macos")]
    return json!({"backend": "seatbelt", "enforcement": {
        "filesystem": "enforced", "ipc": "enforced", "net.none": "enforced", "net.egress-allowlist": "enforced",
        "net.egress-any": "enforced", "no_loopback": "enforced", "gpu.compute": "enforced",
        "exec_writable_deny": "enforced", "no_link_local": "unavailable"}});
    #[cfg(target_os = "linux")]
    return crate::sandbox_linux::report();
    #[cfg(windows)]
    return crate::sandbox_windows::report();
    #[allow(unreachable_code)]
    {
        json!({"backend": null, "enforcement": {}})
    }
}
