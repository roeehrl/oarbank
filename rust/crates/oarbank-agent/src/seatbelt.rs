//! The macOS sandbox backend (spec/sandbox/backends/macos.md): `oarbank-agent sandbox-exec PROFILE K=V ... -- argv`
//! applies a profile to itself and then execs the module, so the module never runs unconfined; the parent checks
//! the child with `sandbox_check`. Exit codes: 70 the profile could not be applied, 71 exec failed, 64 usage.

use std::ffi::{CStr, CString};
use std::path::Path;

unsafe extern "C" {
    fn sandbox_init_with_parameters(profile: *const libc::c_char, flags: u64, params: *const *const libc::c_char,
                                    errorbuf: *mut *mut libc::c_char) -> libc::c_int;
    fn sandbox_check(pid: libc::pid_t, operation: *const libc::c_char, kind: libc::c_int, ...) -> libc::c_int;
}

/// argv that runs `argv` (absolute argv[0]) under the profile, through this executable.
pub fn launch_argv(profile: &Path, params: &[(String, String)], argv: &[String]) -> Vec<String> {
    let mut out = vec![crate::sandbox::me(), "sandbox-exec".into(), profile.to_string_lossy().to_string()];
    out.extend(params.iter().map(|(k, v)| format!("{k}={v}")));
    out.push("--".into());
    out.extend(argv.iter().cloned());
    out
}

/// The `sandbox-exec` subcommand: never returns.
pub fn exec(args: &[String]) -> ! {
    fn die(code: i32, msg: &str) -> ! {
        eprintln!("sandbox launch: {msg}");
        std::process::exit(code)
    }
    let Some(sep) = args.iter().position(|a| a == "--") else { die(64, "usage: sandbox-exec PROFILE K=V ... -- argv") };
    if sep < 1 || args.len() <= sep + 1 || !args[sep + 1].starts_with('/') {
        die(64, "needs a profile and an absolute argv[0]");
    }
    let launcher = crate::sandbox::Launcher::take();
    let profile = match std::fs::read_to_string(&args[0]) {
        Ok(p) => p,
        Err(e) => die(70, &format!("profile {}: {e}", args[0])),
    };
    let mut flat: Vec<CString> = Vec::new();
    for kv in &args[1..sep] {
        let (k, v) = kv.split_once('=').unwrap_or((kv.as_str(), ""));
        flat.push(CString::new(k).unwrap_or_default());
        flat.push(CString::new(v).unwrap_or_default());
    }
    let mut ptrs: Vec<*const libc::c_char> = flat.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let prof = CString::new(profile).unwrap_or_default();
    let mut err: *mut libc::c_char = std::ptr::null_mut();
    let rc = unsafe { sandbox_init_with_parameters(prof.as_ptr(), 0, ptrs.as_ptr(), &mut err) };
    if rc != 0 {
        let m = if err.is_null() { "?".to_string() } else { unsafe { CStr::from_ptr(err) }.to_string_lossy().to_string() };
        die(70, &format!("sandbox_init failed: {m}"));
    }
    if let Some(l) = launcher {
        l.confined();
    }
    let argv: Vec<CString> = args[sep + 1..].iter().map(|a| CString::new(a.as_str()).unwrap_or_default()).collect();
    let mut aptr: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    aptr.push(std::ptr::null());
    unsafe { libc::execv(argv[0].as_ptr(), aptr.as_ptr()) };
    die(71, &format!("exec {}: {}", args[sep + 1], std::io::Error::last_os_error()))
}

/// Whether a process runs under a sandbox (`sandbox_check(pid, NULL, 0) == 1`).
pub fn is_sandboxed(pid: u32) -> bool {
    unsafe { sandbox_check(pid as libc::pid_t, std::ptr::null(), 0) == 1 }
}
