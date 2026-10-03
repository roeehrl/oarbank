//! Event-driven job control end to end (runner protocol 1, "Control"): a sandboxed Python runner using the SDK's
//! reference Control, vendored as modules vendor it, reacts to nudges (SIGUSR1 on POSIX; on Windows the inherited
//! control event, passed through the AppContainer shim) within 200 ms. The agent's steps (jobs.rs ControlFile,
//! sys.rs Nudge) are repeated here, as the agent is a binary: replace control.json atomically, then nudge.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const SDK_CONTROL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../vendor/oarbank-sdk/src/oarbank_sdk/control.py");
const LATENCY: Duration = Duration::from_millis(200);

/// Reports each control state it reaches on stdout. It ends itself after 60 s, so a failed test leaves nothing behind
/// (killing the shim does not end its child outside a Job Object).
const RUNNER: &str = r#"
import os, sys, threading, time
deadline = threading.Timer(60, os._exit, (9,))
deadline.daemon = True
deadline.start()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from control import Control, Stopped
ctl = Control(sys.argv[1])
print("ready", flush=True)
try:
    while True:
        ctl.check()
        if ctl.pause:
            print("paused", flush=True)
            ctl.safe_point()
            print("resumed", flush=True)
        time.sleep(0.005)                                # a work chunk between safe points
except Stopped:
    print("stopped", flush=True)
    sys.exit(3)
"#;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("oarbank-ctl-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The test's Python: OARBANK_TEST_PYTHON, else the node runtime's (Windows), the SDK's environment (a real CPython,
/// where macOS's /usr/bin/python3 is an Xcode stub), or the one on PATH. Its absolute path and the roots the sandbox
/// must let it read, found the way runtime.rs finds them.
fn python() -> (String, Vec<String>) {
    let sdk = Path::new(SDK_CONTROL).ancestors().nth(3).unwrap().join(".venv");
    let found = [cfg!(windows).then(|| PathBuf::from(r"C:\Program Files\Oarbank\runtime\python.exe")),
                 Some(sdk.join(if cfg!(windows) { r"Scripts\python.exe" } else { "bin/python" }))]
        .into_iter().flatten().find(|p| p.exists()).map(|p| p.display().to_string());
    let exe = std::env::var("OARBANK_TEST_PYTHON").ok().or(found).unwrap_or_else(|| if cfg!(windows) { "python" } else { "python3" }.into());
    let probe = "import json, os, sys\nr = {sys.prefix, sys.base_prefix, sys.exec_prefix, os.path.dirname(os.path.realpath(sys.executable))}\n\
                 print(json.dumps({'exe': sys.executable, 'roots': sorted(r | {os.path.realpath(x) for x in r})}))";
    let out = Command::new(&exe).args(["-I", "-c", probe]).output().unwrap_or_else(|e| panic!("{exe}: {e}"));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("the Python probe");
    let roots = v["roots"].as_array().unwrap().iter().map(|r| r.as_str().unwrap().to_string()).collect();
    (v["exe"].as_str().unwrap().to_string(), roots)
}

/// argv run under the module sandbox through `oarbank-agent sandbox-exec`, as sandbox.rs `wrap` builds it.
fn sandboxed(bundle: &Path, ws: &Path, py: &str, roots: Vec<String>, argv: &[String]) -> Vec<String> {
    let mut pol = oarbank_core::sandbox::Policy::new("dev.test.control");
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

fn write_control(ws: &Path, seq: u64, mut doc: serde_json::Value) {
    doc["seq"] = seq.into();
    std::fs::write(ws.join("control.json.tmp"), doc.to_string()).unwrap();
    std::fs::rename(ws.join("control.json.tmp"), ws.join("control.json")).unwrap();
}

#[cfg(unix)]
mod nudge {
    use std::process::Command;

    pub struct Nudge {
        pid: i32,
    }

    impl Nudge {
        pub fn new() -> Nudge {
            Nudge { pid: 0 }
        }

        /// sys.rs `Nudge::prepare` and `new_group`: its own process group, SIGUSR1 ignored until a handler.
        pub fn prepare(&self, cmd: &mut Command) {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
            unsafe {
                cmd.pre_exec(|| {
                    libc::signal(libc::SIGUSR1, libc::SIG_IGN);
                    Ok(())
                });
            }
        }

        pub fn started(&mut self, pid: u32) {
            self.pid = pid as i32;
        }

        pub fn send(&self) {
            assert_eq!(unsafe { libc::kill(self.pid, libc::SIGUSR1) }, 0);
        }
    }
}

#[cfg(windows)]
mod nudge {
    use std::process::Command;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent};

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryObject(h: HANDLE, class: u32, info: *mut std::ffi::c_void, len: u32, ret: *mut u32) -> i32;
    }

    fn inheritable_event() -> HANDLE {
        let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: std::ptr::null_mut(),
                                       bInheritHandle: 1 };
        let h = unsafe { CreateEventW(&sa, 0, 0, std::ptr::null()) };
        assert!(!h.is_null());
        h
    }

    /// sys.rs `Nudge`; and a decoy, an inheritable event the runner is not given, that the shim's handle list must keep
    /// from it.
    pub struct Nudge {
        event: HANDLE,
        decoy: HANDLE,
    }

    impl Nudge {
        pub fn new() -> Nudge {
            Nudge { event: inheritable_event(), decoy: inheritable_event() }
        }

        pub fn prepare(&self, cmd: &mut Command) {
            cmd.env("OARBANK_CONTROL_EVENT", (self.event as usize).to_string());
        }

        pub fn started(&mut self, _pid: u32) {}

        pub fn send(&self) {
            assert!(unsafe { SetEvent(self.event) } != 0);
        }

        /// How many handles to the decoy are open, in every process (ObjectBasicInformation's HandleCount).
        pub fn decoy_handles(&self) -> u32 {
            let mut info = [0u32; 14];
            let st = unsafe { NtQueryObject(self.decoy, 0, info.as_mut_ptr() as *mut _, std::mem::size_of_val(&info) as u32, std::ptr::null_mut()) };
            assert_eq!(st, 0, "NtQueryObject");
            info[2]
        }
    }

    impl Drop for Nudge {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.event);
                CloseHandle(self.decoy);
            }
        }
    }
}

/// The shim, killed if the test ends early.
struct Runner(Child);

impl Drop for Runner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn lines(child: &mut Child) -> mpsc::Receiver<(String, Instant)> {
    let out = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for l in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send((l.trim().to_string(), Instant::now())).is_err() {
                break;
            }
        }
    });
    rx
}

/// The runner's next line, which must be `want` (`""`: nothing yet); otherwise its exit and stderr.
fn expect_line(rx: &mpsc::Receiver<(String, Instant)>, child: &mut Child, want: &str, within: Duration) -> Instant {
    match rx.recv_timeout(within) {
        Ok((line, at)) if line == want => at,
        Err(mpsc::RecvTimeoutError::Timeout) if want.is_empty() => Instant::now(),
        got => {
            let _ = child.kill();
            let st = child.wait();
            let mut err = String::new();
            let _ = std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err);
            panic!("expected {want:?}, got {got:?}; the runner: {st:?}\n{err}");
        }
    }
}

#[test]
fn a_sandboxed_runner_pauses_resumes_and_stops_on_the_agents_nudges() {
    let (bundle, ws) = (scratch("bundle"), scratch("ws"));
    std::fs::copy(SDK_CONTROL, bundle.join("control.py")).expect("the SDK's control.py (vendor/oarbank-sdk)");
    std::fs::write(bundle.join("runner.py"), RUNNER).unwrap();
    write_control(&ws, 0, serde_json::json!({}));
    let (py, roots) = python();
    let argv = sandboxed(&bundle, &ws, &py, roots, &[py.clone(), "-I".into(), bundle.join("runner.py").display().to_string(),
                                                     ws.display().to_string()]);
    let mut nudge = nudge::Nudge::new();
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).current_dir(&ws).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    nudge.prepare(&mut cmd);
    let mut runner = Runner(cmd.spawn().unwrap());
    nudge.started(runner.0.id());
    let rx = lines(&mut runner.0);
    let mut expect = |want: &str, within: Duration| expect_line(&rx, &mut runner.0, want, within);
    expect("ready", Duration::from_secs(60));
    // this test's and the shim's (the agent's CreateProcess passes every inheritable handle); a third is the runner's
    #[cfg(windows)]
    assert_eq!(nudge.decoy_handles(), 2, "the runner inherited a handle besides its event and standard handles");
    let mut took = vec![];
    for (seq, doc, want) in [(1, serde_json::json!({"pause": true}), "paused"), (2, serde_json::json!({"pause": false}), "resumed"),
                               (3, serde_json::json!({"pause": true}), "paused"), (4, serde_json::json!({"stop": true}), "stopped")] {
        std::thread::sleep(Duration::from_millis(300));
        expect("", Duration::ZERO);                                      // nothing happens without a nudge
        write_control(&ws, seq, doc);
        let t = Instant::now();
        nudge.send();
        took.push((want, expect(want, Duration::from_secs(5)) - t));
    }
    let code = runner.0.wait().unwrap().code();
    eprintln!("reaction latency: {}", took.iter().map(|(e, d)| format!("{e} {:.1} ms", d.as_secs_f64() * 1e3)).collect::<Vec<_>>().join(", "));
    assert_eq!(code, Some(3));
    assert!(took.iter().all(|(_, d)| *d < LATENCY), "{took:?}");
    let _ = std::fs::remove_dir_all(&bundle);
    let _ = std::fs::remove_dir_all(&ws);
}
