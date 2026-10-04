//! The Linux sandbox backend (spec/sandbox.md; PLAN D30: full parity on kernel 6.12+). `oarbank-agent sandbox-exec
//! POLICY.json -- argv` confines itself and then execs the module:
//!
//! 1. no_new_privs;
//! 2. Landlock for the detected ABI: read and execute the policy's read-only roots and the base system, everything
//!    in the read-write roots (execute only with `exec_writable`), the null/zero/random devices and, with the GPU
//!    grant, the render nodes; with ABI 4+ TCP connect only to the egress proxy's port and no bind; with ABI 6+ no
//!    abstract unix sockets or signals outside the sandbox;
//! 3. seccomp: no UDP, raw, netlink or other socket families, no IPv4/IPv6 at all without a network grant, no unix
//!    sockets without the broker (socketpair stays: event loops need it), never listen, no ptrace, mounts,
//!    namespaces, keyrings, BPF or kernel modules (clone3 answers ENOSYS so libc falls back to a filterable clone).
//!
//! A step that cannot be applied in full ends the launch (exit 70): the module never runs unconfined. The parent
//! checks `NoNewPrivs: 1` and `Seccomp: 2` in /proc/<pid>/status, which only this launcher sets before the exec.

use landlock::{Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
               Scope, ABI};
use oarbank_core::sandbox::Policy;
use seccompiler::{BpfProgram, SeccompAction, SeccompCmpArgLen as Len, SeccompCmpOp as Op, SeccompCondition as Cond, SeccompFilter,
                  SeccompRule, TargetArch};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The kernel's Landlock ABI (0: none), from `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`.
pub fn landlock_abi() -> i32 {
    let v = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u8>(), 0usize, 1u32) };
    if v < 0 { 0 } else { v as i32 }
}

fn seccomp_available() -> bool {
    unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) >= 0 }
}

/// Landlock 3 (truncation covered) and seccomp: enough for the filesystem, IPC by socket family, and no network.
pub fn available() -> bool {
    landlock_abi() >= 3 && seccomp_available()
}

pub fn report() -> Value {
    let abi = landlock_abi();
    if !available() {
        return json!({"backend": null, "enforcement": {}, "landlock_abi": abi});
    }
    let e = |ok: bool| if ok { "enforced" } else { "unavailable" };
    json!({"backend": "landlock", "landlock_abi": abi, "enforcement": {
        "filesystem": "enforced",
        // unix sockets by family (seccomp) and, from ABI 6, abstract sockets and signals scoped to the sandbox
        "ipc": e(abi >= 6),
        "net.none": "enforced",
        // TCP connect only to the proxy's port needs Landlock's network rules (ABI 4)
        "net.egress-allowlist": e(abi >= 4),
        // Landlock filters ports, not addresses: loopback and link-local cannot be refused for any-destination egress
        "net.egress-any": "unavailable",
        "no_loopback": e(abi >= 4),
        "no_link_local": e(abi >= 4),
        "gpu.compute": "enforced",
        "exec_writable_deny": "enforced"}})
}

pub fn is_confined(pid: i32) -> bool {
    let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/status")) else { return false };
    let field = |k: &str| s.lines().find_map(|l| l.strip_prefix(k)).map(str::trim).map(str::to_string);
    field("NoNewPrivs:").as_deref() == Some("1") && field("Seccomp:").as_deref() == Some("2")
}

fn die(code: i32, msg: &str) -> ! {
    eprintln!("sandbox launch: {msg}");
    std::process::exit(code)
}

/// The base system a process needs to start and resolve its libraries (read and execute).
const SYSTEM_RO: &[&str] = &["/usr", "/lib", "/lib32", "/lib64", "/bin", "/sbin", "/etc", "/opt", "/proc", "/sys/devices/system/cpu"];
const DEVICES_RW: &[&str] = &["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/full"];
const GPU_RW: &[&str] = &["/dev/dri", "/dev/nvidia0", "/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/kfd"];

fn landlock(pol: &Policy, abi_n: i32) -> Result<(), String> {
    let abi = ABI::from(abi_n);
    let read = AccessFs::from_read(abi);
    let all = AccessFs::from_all(abi);
    let rw = if pol.exec_rw { all } else { all & !AccessFs::Execute };
    let dev = AccessFs::ReadFile | AccessFs::WriteFile;
    let mut rs = Ruleset::default().handle_access(all).map_err(|e| e.to_string())?;
    let net = abi_n >= 4;
    if net {
        rs = rs.handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp).map_err(|e| e.to_string())?;
    } else if pol.net == "egress-allowlist" {
        return Err(format!("Landlock ABI {abi_n} has no network rules: an egress allowlist needs ABI 4 (Linux 6.7)"));
    }
    if abi_n >= 6 {
        rs = rs.scope(Scope::AbstractUnixSocket | Scope::Signal).map_err(|e| e.to_string())?;
    }
    let mut rules: Vec<PathBeneath<PathFd>> = vec![];
    for p in SYSTEM_RO {
        push(&mut rules, p, read, false, abi)?;
    }
    for p in &pol.ro {
        push(&mut rules, p, read, true, abi)?;
    }
    if let Some(exe) = &pol.exe {
        push(&mut rules, exe, read, true, abi)?;
    }
    for p in &pol.rw {
        push(&mut rules, p, rw, true, abi)?;
    }
    for p in DEVICES_RW {
        push(&mut rules, p, dev, false, abi)?;
    }
    if pol.gpu {
        for p in GPU_RW {
            push(&mut rules, p, dev | AccessFs::ReadDir, false, abi)?;
        }
    }
    let mut created = rs.create().map_err(|e| e.to_string())?
        .add_rules(rules.into_iter().map(Ok::<_, landlock::RulesetError>)).map_err(|e| e.to_string())?;
    if let (true, Some(port), "egress-allowlist") = (net, pol.proxy_port, pol.net.as_str()) {
        created = created.add_rule(NetPort::new(port, AccessNet::ConnectTcp)).map_err(|e| e.to_string())?;
    }
    let st = created.restrict_self().map_err(|e| e.to_string())?;
    if st.ruleset != RulesetStatus::FullyEnforced {
        return Err(format!("Landlock ABI {abi_n} only partly enforced ({:?})", st.ruleset));
    }
    Ok(())
}

/// A rule for `path` (a file gets only the rights a file can have); a missing optional path is skipped.
fn push(rules: &mut Vec<PathBeneath<PathFd>>, path: &str, access: enumflags2::BitFlags<AccessFs>, required: bool, abi: ABI)
        -> Result<(), String> {
    match PathFd::new(path) {
        Ok(fd) => {
            let is_dir = std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false);
            rules.push(PathBeneath::new(fd, if is_dir { access } else { access & AccessFs::from_file(abi) }));
            Ok(())
        }
        Err(_) if !required => Ok(()),
        Err(e) => Err(format!("{path}: {e}")),
    }
}

fn rule(conds: Vec<Cond>) -> Result<SeccompRule, String> {
    SeccompRule::new(conds).map_err(|e| e.to_string())
}

fn eq(arg: u8, v: u64) -> Result<Cond, String> {
    Cond::new(arg, Len::Dword, Op::Eq, v).map_err(|e| e.to_string())
}

fn arch() -> TargetArch {
    #[cfg(target_arch = "aarch64")]
    return TargetArch::aarch64;
    #[cfg(target_arch = "riscv64")]
    return TargetArch::riscv64;
    #[allow(unreachable_code)]
    TargetArch::x86_64
}

/// The socket and syscall rules (every match answers EPERM), and clone3's ENOSYS.
pub fn filters(pol: &Policy) -> Result<Vec<BpfProgram>, String> {
    let (unix, inet, inet6) = (libc::AF_UNIX as u64, libc::AF_INET as u64, libc::AF_INET6 as u64);
    let mut socket: Vec<SeccompRule> = vec![
        rule(vec![eq(0, 0)?])?,
        rule(vec![Cond::new(0, Len::Dword, Op::Ge, 3).map_err(|e| e.to_string())?, Cond::new(0, Len::Dword, Op::Le, 9).map_err(|e| e.to_string())?])?,
        rule(vec![Cond::new(0, Len::Dword, Op::Gt, 10).map_err(|e| e.to_string())?])?,
    ];
    if pol.broker_socket.is_none() {
        socket.push(rule(vec![eq(0, unix)?])?);
    }
    if pol.net == "none" {
        socket.push(rule(vec![eq(0, inet)?])?);
        socket.push(rule(vec![eq(0, inet6)?])?);
    } else {
        // streams only: the type's low bits (SOCK_NONBLOCK and SOCK_CLOEXEC sit above them). SOCK_PACKET (10) is the
        // obsolete packet type libc no longer names; the kernel still accepts it, so it stays denied.
        const SOCK_PACKET: i32 = 10;
        for fam in [inet, inet6] {
            for t in [libc::SOCK_DGRAM, libc::SOCK_RAW, libc::SOCK_RDM, libc::SOCK_SEQPACKET, SOCK_PACKET] {
                socket.push(rule(vec![eq(0, fam)?, Cond::new(1, Len::Dword, Op::MaskedEq(0xf), t as u64).map_err(|e| e.to_string())?])?);
            }
        }
    }
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_socket, socket);
    let ns = (libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWPID | libc::CLONE_NEWIPC
              | libc::CLONE_NEWUTS | libc::CLONE_NEWCGROUP) as u64;
    // clone's flags are its first argument on every architecture we build for
    let mut clone_rules = vec![];
    for bit in [libc::CLONE_NEWUSER, libc::CLONE_NEWNS, libc::CLONE_NEWNET, libc::CLONE_NEWPID, libc::CLONE_NEWIPC,
                libc::CLONE_NEWUTS, libc::CLONE_NEWCGROUP] {
        clone_rules.push(rule(vec![Cond::new(0, Len::Qword, Op::MaskedEq(bit as u64), bit as u64).map_err(|e| e.to_string())?])?);
    }
    let _ = ns;
    rules.insert(libc::SYS_clone, clone_rules);
    for sc in [libc::SYS_listen, libc::SYS_ptrace, libc::SYS_process_vm_readv, libc::SYS_process_vm_writev, libc::SYS_mount,
               libc::SYS_umount2, libc::SYS_pivot_root, libc::SYS_unshare, libc::SYS_setns, libc::SYS_keyctl, libc::SYS_add_key,
               libc::SYS_request_key, libc::SYS_bpf, libc::SYS_perf_event_open, libc::SYS_userfaultfd, libc::SYS_kexec_load,
               libc::SYS_init_module, libc::SYS_finit_module, libc::SYS_delete_module, libc::SYS_reboot, libc::SYS_swapon,
               libc::SYS_swapoff, libc::SYS_acct, libc::SYS_open_by_handle_at, libc::SYS_name_to_handle_at, libc::SYS_chroot,
               libc::SYS_fsopen, libc::SYS_fsmount, libc::SYS_move_mount, libc::SYS_open_tree] {
        rules.insert(sc, vec![]);
    }
    let main = SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::Errno(libc::EPERM as u32), arch())
        .map_err(|e| e.to_string())?;
    let mut c3 = BTreeMap::new();
    c3.insert(libc::SYS_clone3, vec![]);
    let clone3 = SeccompFilter::new(c3, SeccompAction::Allow, SeccompAction::Errno(libc::ENOSYS as u32), arch()).map_err(|e| e.to_string())?;
    Ok(vec![main.try_into().map_err(|e: seccompiler::BackendError| e.to_string())?,
            clone3.try_into().map_err(|e: seccompiler::BackendError| e.to_string())?])
}

/// The `sandbox-exec` subcommand on Linux: never returns.
pub fn exec(args: &[String]) -> ! {
    let Some(sep) = args.iter().position(|a| a == "--") else { die(64, "usage: sandbox-exec POLICY.json -- argv") };
    if sep != 1 || args.len() <= sep + 1 || !args[sep + 1].starts_with('/') {
        die(64, "needs a policy file and an absolute argv[0]");
    }
    let launcher = crate::sandbox::Launcher::take();
    let pol: Policy = match std::fs::read(&args[0]).map_err(|e| e.to_string()).and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string())) {
        Ok(p) => p,
        Err(e) => die(70, &format!("policy {}: {e}", args[0])),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        die(70, &format!("no_new_privs: {}", std::io::Error::last_os_error()));
    }
    let abi = landlock_abi();
    if abi < 3 {
        die(70, &format!("Landlock ABI {abi}: the sandbox needs ABI 3 (Linux 6.2) or later"));
    }
    if let Err(e) = landlock(&pol, abi) {
        die(70, &format!("landlock: {e}"));
    }
    match filters(&pol) {
        Ok(progs) => {
            for p in &progs {
                if let Err(e) = seccompiler::apply_filter(p) {
                    die(70, &format!("seccomp: {e}"));
                }
            }
        }
        Err(e) => die(70, &format!("seccomp: {e}")),
    }
    if let Some(l) = launcher {
        l.confined();
    }
    let argv: Vec<std::ffi::CString> = args[sep + 1..].iter().map(|a| std::ffi::CString::new(a.as_str()).unwrap_or_default()).collect();
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    unsafe { libc::execv(argv[0].as_ptr(), ptrs.as_ptr()) };
    die(71, &format!("exec {}: {}", args[sep + 1], std::io::Error::last_os_error()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filters_build_for_every_network_mode() {
        for (net, broker) in [("none", false), ("egress-allowlist", true), ("egress-any", false)] {
            let mut p = Policy::new("m");
            p.net = net.into();
            p.broker_socket = broker.then(|| "/run/b.sock".into());
            assert_eq!(filters(&p).unwrap().len(), 2);
        }
    }

    /// The test binary answers `sandbox-exec` itself, as the agent's main does (see services.rs for macOS).
    #[used]
    #[unsafe(link_section = ".init_array")]
    static LAUNCHER: extern "C" fn() = {
        extern "C" fn launcher() {
            let raw: Vec<String> = std::env::args().collect();
            if raw.get(1).map(String::as_str) == Some("sandbox-exec") {
                super::exec(&raw[2..]);
            }
        }
        launcher
    };

    /// Only meaningful on a kernel with Landlock: a confined child cannot read outside its roots, cannot open a
    /// UDP or unix socket, and reports itself confined.
    #[test]
    fn a_confined_child_is_confined() {
        if !available() {
            eprintln!("no Landlock here: skipped");
            return;
        }
        let dir = std::env::temp_dir().join(format!("oarbank-ll-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("rw")).unwrap();
        std::fs::write(dir.join("secret"), "x").unwrap();
        let mut p = Policy::new("m");
        p.rw = vec![dir.join("rw").display().to_string()];
        let pf = dir.join("p.json");
        std::fs::write(&pf, serde_json::to_vec(&p).unwrap()).unwrap();
        let me = std::env::current_exe().unwrap();
        let script = format!("cat {0}/secret && echo READ; echo ok > {0}/rw/f && echo WROTE; \
                              python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM)' 2>/dev/null && echo UDP; \
                              grep -E '^(NoNewPrivs|Seccomp):' /proc/self/status", dir.display());
        let out = std::process::Command::new(&me).args(["sandbox-exec", &pf.display().to_string(), "--", "/bin/sh", "-c", &script])
            .output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains("READ") && text.contains("WROTE") && !text.contains("UDP"), "{text}");
        assert!(text.contains("NoNewPrivs:\t1") && text.contains("Seccomp:\t2"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
