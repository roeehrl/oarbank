//! The AppContainer shim on a real Windows host (sandbox_windows.rs): what a contained program can and cannot do.
#![cfg(windows)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("oarbank-sbx-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn sandboxed(module: &str, rw: &std::path::Path, argv: &[&str]) -> Output {
    let policy = serde_json::json!({"module": module, "ro": [], "rw": [rw.display().to_string()], "net": "none",
                                    "proxy_port": null, "broker_socket": null, "gpu": false, "exec_rw": false,
                                    "kind": "runner", "exe": argv[0]});
    let p = rw.with_extension("policy.json");
    std::fs::write(&p, policy.to_string()).unwrap();
    Command::new(env!("CARGO_BIN_EXE_oarbank-agent")).arg("sandbox-exec").arg(&p).arg("--").args(argv).output().unwrap()
}

fn system32(exe: &str) -> String {
    format!(r"{}\System32\{exe}", std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
}

#[test]
fn a_contained_program_can_load_user32() {
    // whoami.exe imports user32: without read access to the window station and desktop it inherits, a contained
    // process dies at start with 0xC0000142 (and Python's ctypes, COM and platform module fail the same way)
    let d = scratch("user32");
    let out = sandboxed("dev.test.user32", &d, &[&system32("whoami.exe")]);
    assert!(out.status.success(), "{:?}\n{}", out.status, String::from_utf8_lossy(&out.stderr));
    assert!(!out.stdout.is_empty());
}

#[test]
fn a_contained_program_writes_its_rw_root_only() {
    let d = scratch("rw");
    let inside = d.join("inside.txt");
    let outside = std::env::temp_dir().join(format!("oarbank-sbx-outside-{}.txt", std::process::id()));
    let cmd = system32("cmd.exe");
    // no quotes around the paths: the shim quotes argv the CRT way, which cmd does not unquote (temp paths have no spaces)
    let ok = sandboxed("dev.test.rw", &d, &[&cmd, "/c", &format!("echo x> {}", inside.display())]);
    assert!(ok.status.success() && inside.exists(), "{}", String::from_utf8_lossy(&ok.stderr));
    let denied = sandboxed("dev.test.rw", &d, &[&cmd, "/c", &format!("echo x> {}", outside.display())]);
    assert!(!denied.status.success() && !outside.exists());
}

/// The test's Python (OARBANK_TEST_PYTHON, else the node runtime's, else the one on PATH) and the directories the
/// sandbox must let it read.
fn python() -> (String, Vec<String>) {
    let runtime = r"C:\Program Files\Oarbank\runtime\python.exe";
    let exe = std::env::var("OARBANK_TEST_PYTHON").ok()
        .or_else(|| std::path::Path::new(runtime).exists().then(|| runtime.to_string())).unwrap_or_else(|| "python".into());
    let probe = "import json, os, sys\nr = {sys.prefix, sys.base_prefix, os.path.dirname(os.path.realpath(sys.executable))}\n\
                 print(json.dumps({'exe': sys.executable, 'roots': sorted(r)}))";
    let out = Command::new(&exe).args(["-I", "-c", probe]).output().unwrap_or_else(|e| panic!("{exe}: {e}"));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("the Python probe");
    (v["exe"].as_str().unwrap().into(), v["roots"].as_array().unwrap().iter().map(|r| r.as_str().unwrap().into()).collect())
}

fn is_app_container(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenIsAppContainer, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        let mut tok: HANDLE = std::ptr::null_mut();
        let opened = !p.is_null() && OpenProcessToken(p, TOKEN_QUERY, &mut tok) != 0;
        if !p.is_null() {
            CloseHandle(p);
        }
        let (mut v, mut len) = (0u32, 0u32);
        let got = opened && GetTokenInformation(tok, TokenIsAppContainer, &mut v as *mut u32 as *mut _, 4, &mut len) != 0;
        if opened {
            CloseHandle(tok);
        }
        got && v != 0
    }
}

#[test]
fn a_contained_runner_is_alone_in_its_job_with_the_shim() {
    // the agent's steps (jobs.rs, sys.rs): the shim starts with no console (DETACHED_PROCESS) in a new process group
    // and is put in a Job Object; the runner is confined once every other member of the job is an AppContainer
    // (sandbox_windows.rs is_confined). A console host beside the shim or the runner would never be.
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicProcessIdList,
                                                 QueryInformationJobObject, TerminateJobObject, JOBOBJECT_BASIC_PROCESS_ID_LIST};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};
    let d = scratch("job");
    let (py, roots) = python();
    let policy = serde_json::json!({"module": "dev.test.job", "ro": roots, "rw": [d.display().to_string()], "net": "none",
                                    "proxy_port": null, "broker_socket": null, "gpu": false, "exec_rw": false,
                                    "kind": "runner", "exe": py});
    let p = d.with_extension("policy.json");
    std::fs::write(&p, policy.to_string()).unwrap();
    let mut shim = Command::new(env!("CARGO_BIN_EXE_oarbank-agent")).arg("sandbox-exec").arg(&p).arg("--")
        .args([py.as_str(), "-I", "-c", "import pathlib, sys, time; pathlib.Path(sys.argv[1]).write_text('up'); time.sleep(60)",
               &d.join("up").display().to_string()])
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .creation_flags(0x0000_0200 | 0x0000_0008).spawn().unwrap();
    let shim_pid = shim.id();
    let job: HANDLE = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    unsafe {
        let h = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, shim_pid);
        assert!(AssignProcessToJobObject(job, h) != 0);
        CloseHandle(h);
    }
    let members = || -> Vec<u32> {
        let mut buf = vec![0usize; 2 + 64];
        let ok = unsafe { QueryInformationJobObject(job, JobObjectBasicProcessIdList, buf.as_mut_ptr() as *mut _,
                                                    (buf.len() * std::mem::size_of::<usize>()) as u32, std::ptr::null_mut()) };
        assert!(ok != 0);
        let n = unsafe { &*(buf.as_ptr() as *const JOBOBJECT_BASIC_PROCESS_ID_LIST) }.NumberOfProcessIdsInList as usize;
        let first = std::mem::offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList) / std::mem::size_of::<usize>();
        buf[first..first + n].iter().map(|&p| p as u32).collect()
    };
    // judge once the runner runs its own code: a console host, if one came, came with its start (a loaded host may
    // take seconds to get there)
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !d.join("up").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let others: Vec<u32> = members().into_iter().filter(|p| *p != shim_pid).collect();
    let contained: Vec<bool> = others.iter().map(|p| is_app_container(*p)).collect();
    unsafe {
        TerminateJobObject(job, 1);
        CloseHandle(job);
    }
    let _ = shim.wait();
    assert!(!others.is_empty() && contained.iter().all(|c| *c), "members besides the shim {others:?}: AppContainer {contained:?}");
}
