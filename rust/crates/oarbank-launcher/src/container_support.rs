//! Container support on Windows, installed after the installer (docs/design/node-enrollment.md, "Windows MSI
//! properties"; docs/design/windows-containers.md, "Packaging"). The WSL package that container jobs need is itself a
//! Windows Installer package, and Windows Installer runs one installation at a time: a custom action that installs it
//! from inside the agent's MSI is a nested installation, which Microsoft deprecates and which fails both (error 2755
//! with 1622 on a real PC: a nested installation shares the outer one's logging). So the MSI only asks for it:
//!
//! - `container-support schedule` (the MSI's deferred action when CONTAINERS=1 or the join code asks for container
//!   jobs; `oarbank-node join --containers` while another installation runs) registers the task
//!   `\OarbankContainerSupport`, run as LocalSystem when the installer logs that it installed or reconfigured the
//!   Oarbank agent (MsiInstaller event 1033 or 1035: the installation has ended) and at every start of Windows;
//! - `container-support run` (the task) runs `oarbank-agent containers install --wait 1800` (which waits until no
//!   Windows Installer installation runs), records the outcome and deletes the task once it is done or has failed for
//!   good; a restart that is still needed, or an installation that kept running, leaves it for the next start;
//! - `container-support cancel` (an uninstall, a rolled-back install) ends and deletes the task and the record.
//!
//! The outcome is recorded in `HKLM\SOFTWARE\Codonic\Oarbank\ContainerSupport` (`State`, `Detail`, `Attempts`,
//! `Updated`): readable by everyone (the tray app, `oarbank-node doctor`), writable only by administrators and SYSTEM
//! (the status directory in ProgramData lets every user create files, which a SYSTEM task must not write through).

use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::path::Path;

/// The task's name (at the root of the Task Scheduler library: nothing is left behind when it goes).
pub const TASK: &str = "OarbankContainerSupport";
/// Where the outcome is recorded (HKLM, 64-bit view).
pub const KEY: &str = r"SOFTWARE\Codonic\Oarbank\ContainerSupport";
/// The agent MSI's product name, which its MsiInstaller events carry (deploy/windows/oarbank-agent.wxs, Package Name).
pub const PRODUCT: &str = "Oarbank agent";
/// How long one run waits for another installation to finish.
pub const WAIT_S: u64 = 1800;
/// Runs (starts of Windows) after which a restart that is still needed, or an installation that kept running, fails.
pub const MAX_ATTEMPTS: u32 = 5;

/// The recorded outcome.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Record {
    /// scheduled, installing, waiting, restart, done, failed
    pub state: String,
    pub detail: String,
    pub attempts: u32,
    pub updated: u64,
}

impl Record {
    pub fn json(&self) -> Value {
        json!({"state": self.state, "detail": self.detail, "attempts": self.attempts, "updated_at": self.updated})
    }
}

/// What a person is told about a record (the tray app has the same lines, deploy/windows/NodeTray.cs); None: nothing.
pub fn line(state: &str, detail: &str) -> Option<String> {
    Some(match state {
        "scheduled" => "Container support installs when setup has finished".into(),
        "installing" => "Installing container support…".into(),
        "waiting" => "Container support waits for another installation; it continues when Windows restarts".into(),
        "restart" => "Restart Windows to finish container support".into(),
        "failed" if detail.is_empty() => "Container support failed".into(),
        "failed" => format!("Container support failed: {detail}"),
        _ => return None,
    })
}

/// The record a run of `oarbank-agent containers install` leaves (its exit code and output), on its `attempts`th run.
pub fn outcome(code: Option<i32>, output: &str, attempts: u32) -> (&'static str, String) {
    let last = output.lines().map(str::trim).rfind(|l| !l.is_empty()).unwrap_or("");
    let last = last.strip_prefix("Error: ").unwrap_or(last).to_string();
    let (state, detail) = match code {
        Some(0) => ("done", last),
        Some(3010) => ("restart", "restart Windows to finish installing the Virtual Machine Platform".to_string()),
        Some(1618) => ("waiting", "another installation was running; container support continues when Windows restarts".to_string()),
        Some(c) => ("failed", if last.is_empty() { format!("oarbank-agent containers install exited {c}") } else { last }),
        None => ("failed", "oarbank-agent containers install was stopped".to_string()),
    };
    if matches!(state, "restart" | "waiting") && attempts >= MAX_ATTEMPTS {
        return ("failed", format!("not finished after {attempts} starts of Windows ({detail}); run `oarbank-agent containers install` as an administrator"));
    }
    (state, detail)
}

/// Whether a run that ended in `state` is the last one (the task goes).
pub fn final_state(state: &str) -> bool {
    matches!(state, "done" | "failed")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The MsiInstaller events of the agent's MSI that end an installation: 1033 installed (a first install, an upgrade),
/// 1035 reconfigured (a repair or a change with CONTAINERS=1). Logged once the installation has ended, with its status
/// (a rolled-back install also logs 1033, but its rollback has deleted the task by then).
pub fn subscription() -> String {
    format!("<QueryList><Query Id=\"0\" Path=\"Application\"><Select Path=\"Application\">*[System[Provider[@Name='MsiInstaller'] and \
             (EventID=1033 or EventID=1035)]] and *[EventData[Data='{PRODUCT}']]</Select></Query></QueryList>")
}

/// The task (Task Scheduler schema 1.2): LocalSystem, at the agent MSI's end and at every start of Windows, on battery
/// too, one run at a time, two hours at most.
pub fn task_xml(launcher: &Path) -> String {
    let command = launcher.display().to_string();
    // the directory as written (a Windows path is checked on every OS)
    let dir = command.rfind(['\\', '/']).map(|i| &command[..i]).unwrap_or(&command);
    format!(r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Oarbank</Author>
    <Description>Installs what Oarbank's container jobs need (WSL) once the Oarbank agent's installer has finished, then deletes itself.</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>{subscription}</Subscription>
    </EventTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT1M</Delay>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="System">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="System">
    <Exec>
      <Command>{command}</Command>
      <Arguments>container-support run</Arguments>
      <WorkingDirectory>{dir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"#, subscription = xml_escape(&subscription()), command = xml_escape(&command),
            dir = xml_escape(dir))
}

/// UTF-16 LE with a byte order mark, as schtasks reads a task definition.
pub fn utf16_bom(s: &str) -> Vec<u8> {
    [0xFFu8, 0xFE].into_iter().chain(s.encode_utf16().flat_map(u16::to_le_bytes)).collect()
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `oarbank-launcher container-support schedule|run|cancel|status`.
pub fn main(rest: &[String]) -> Result<i32> {
    match rest.get(1).map(String::as_str) {
        Some("schedule") => imp::schedule().map(|_| 0),
        Some("run") => imp::run(),
        Some("cancel") => {
            imp::cancel();
            Ok(0)
        }
        Some("status") => {
            println!("{}", read().map(|r| r.json()).unwrap_or(Value::Null));
            Ok(0)
        }
        _ => bail!("usage: oarbank-launcher container-support schedule | run | cancel | status"),
    }
}

/// The recorded outcome, if any (Windows).
pub fn read() -> Option<Record> {
    imp::read()
}

/// Record an outcome (Windows; `oarbank-node join --containers` records its own).
pub fn record(state: &str, detail: &str, attempts: u32) {
    imp::write(&Record { state: state.into(), detail: detail.into(), attempts, updated: now() });
}

/// Register the task (Windows).
pub fn schedule() -> Result<()> {
    imp::schedule()
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    pub fn schedule() -> Result<()> {
        bail!("container support is installed this way on Windows only")
    }
    pub fn run() -> Result<i32> {
        schedule().map(|_| 0)
    }
    pub fn cancel() {}
    pub fn read() -> Option<Record> {
        None
    }
    pub fn write(_: &Record) {}
}

#[cfg(windows)]
mod imp {
    use super::*;
    use anyhow::Context;
    use std::process::Command;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{RegCloseKey, RegCreateKeyExW, RegDeleteKeyExW, RegDeleteTreeW, RegGetValueW, RegOpenKeyExW,
                                               RegQueryInfoKeyW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY,
                                               KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    fn schtasks(args: &[&str]) -> Result<std::process::Output> {
        let root = std::env::var_os("SystemRoot").map(std::path::PathBuf::from).unwrap_or_else(|| "C:\\Windows".into());
        Command::new(root.join("System32").join("schtasks.exe")).args(args).output().context("running schtasks.exe")
    }

    fn task_exists() -> bool {
        schtasks(&["/query", "/tn", TASK]).map(|o| o.status.success()).unwrap_or(false)
    }

    fn delete_task() {
        if task_exists() {
            let _ = schtasks(&["/delete", "/tn", TASK, "/f"]);
        }
    }

    /// The launcher the task runs: this program under its own name (`oarbank-node.exe` is a copy of it).
    fn launcher() -> Result<std::path::PathBuf> {
        let me = std::env::current_exe()?;
        let l = me.with_file_name("oarbank-launcher.exe");
        Ok(if l.is_file() { l } else { me })
    }

    pub fn schedule() -> Result<()> {
        let launcher = launcher()?;
        // the definition goes beside the launcher (Program Files: administrators only), never through a temporary
        // directory other users can write, from which a swapped file would become a LocalSystem task
        let file = launcher.with_file_name(format!("container-support-{}.xml", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let made = (|| -> Result<()> {
            use std::io::Write;
            std::fs::OpenOptions::new().write(true).create_new(true).open(&file)?.write_all(&utf16_bom(&task_xml(&launcher)))?;
            let o = schtasks(&["/create", "/tn", TASK, "/xml", &file.display().to_string(), "/f"])?;
            if !o.status.success() {
                bail!("{}", String::from_utf8_lossy(&o.stderr).trim());
            }
            Ok(())
        })();
        let _ = std::fs::remove_file(&file);
        match made {
            Ok(()) => {
                record("scheduled", "", 0);
                Ok(())
            }
            Err(e) => {
                record("failed", &format!("could not register the task {TASK}: {e:#}; run `oarbank-agent containers install` as an administrator"), 0);
                Err(e)
            }
        }
    }

    pub fn run() -> Result<i32> {
        let agent = launcher()?.with_file_name("oarbank-agent.exe");
        if !agent.is_file() {
            // the agent is gone (uninstalled without the task): nothing to do any more
            delete_task();
            forget();
            return Ok(0);
        }
        let attempts = read().map(|r| r.attempts).unwrap_or(0) + 1;
        record("installing", "", attempts);
        let (code, output) = match Command::new(&agent).args(["containers", "install", "--wait", &WAIT_S.to_string()]).output() {
            Ok(o) => (o.status.code(), format!("{}\n{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))),
            Err(e) => (Some(1), format!("{}: {e}", agent.display())),
        };
        let (state, detail) = outcome(code, &output, attempts);
        record(state, &detail, attempts);
        if final_state(state) {
            delete_task();
        }
        Ok(code.unwrap_or(1))
    }

    pub fn cancel() {
        if task_exists() {
            let _ = schtasks(&["/end", "/tn", TASK]);
            let _ = schtasks(&["/delete", "/tn", TASK, "/f"]);
        }
        forget();
    }

    fn open(path: &str, access: u32) -> Option<HKEY> {
        let mut k: HKEY = std::ptr::null_mut();
        let p = wide(path);
        (unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, p.as_ptr(), 0, access | KEY_WOW64_64KEY, &mut k) } == ERROR_SUCCESS).then_some(k)
    }

    fn get(k: HKEY, name: &str) -> Option<String> {
        let n = wide(name);
        let mut size = 0u32;
        if unsafe { RegGetValueW(k, std::ptr::null(), n.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), std::ptr::null_mut(), &mut size) } != ERROR_SUCCESS {
            return None;
        }
        let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
        let mut size = (buf.len() * 2) as u32;
        if unsafe { RegGetValueW(k, std::ptr::null(), n.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut size) } != ERROR_SUCCESS {
            return None;
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..end]))
    }

    pub fn read() -> Option<Record> {
        let k = open(KEY, KEY_READ)?;
        let r = Record { state: get(k, "State").unwrap_or_default(), detail: get(k, "Detail").unwrap_or_default(),
                         attempts: get(k, "Attempts").and_then(|a| a.parse().ok()).unwrap_or(0),
                         updated: get(k, "Updated").and_then(|a| a.parse().ok()).unwrap_or(0) };
        unsafe { RegCloseKey(k) };
        (!r.state.is_empty()).then_some(r)
    }

    pub fn write(r: &Record) {
        let mut k: HKEY = std::ptr::null_mut();
        let p = wide(KEY);
        let made = unsafe { RegCreateKeyExW(HKEY_LOCAL_MACHINE, p.as_ptr(), 0, std::ptr::null(), REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY,
                                            std::ptr::null(), &mut k, std::ptr::null_mut()) };
        if made != ERROR_SUCCESS {
            eprintln!("container support: cannot record {} in HKLM\\{KEY} (error {made})", r.state);
            return;
        }
        for (name, value) in [("State", r.state.clone()), ("Detail", r.detail.clone()), ("Attempts", r.attempts.to_string()), ("Updated", r.updated.to_string())] {
            let n = wide(name);
            let v = wide(&value);
            unsafe { RegSetValueExW(k, n.as_ptr(), 0, REG_SZ, v.as_ptr().cast(), (v.len() * 2) as u32) };
        }
        unsafe { RegCloseKey(k) };
    }

    /// Delete the record, and its parent keys while nothing else is in them (the coordinator's MSI keeps its own under
    /// `SOFTWARE\Codonic\Oarbank`).
    fn forget() {
        let p = wide(KEY);
        unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, p.as_ptr()) };
        if let Some(k) = open(KEY, KEY_READ) {
            unsafe { RegCloseKey(k) };
            let _ = unsafe { RegDeleteKeyExW(HKEY_LOCAL_MACHINE, p.as_ptr(), KEY_WOW64_64KEY, 0) };
        }
        for parent in [r"SOFTWARE\Codonic\Oarbank", r"SOFTWARE\Codonic"] {
            let Some(k) = open(parent, KEY_READ) else { continue };
            let (mut keys, mut values) = (0u32, 0u32);
            let ok = unsafe { RegQueryInfoKeyW(k, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), &mut keys, std::ptr::null_mut(),
                                               std::ptr::null_mut(), &mut values, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
                                               std::ptr::null_mut()) } == ERROR_SUCCESS;
            unsafe { RegCloseKey(k) };
            if !ok || keys != 0 || values != 0 {
                break;
            }
            let w = wide(parent);
            unsafe { RegDeleteKeyExW(HKEY_LOCAL_MACHINE, w.as_ptr(), KEY_WOW64_64KEY, 0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_of_the_agents_install() {
        assert_eq!(outcome(Some(0), "nothing to install: the WSL components are in place\n", 1),
                   ("done", "nothing to install: the WSL components are in place".to_string()));
        assert_eq!(outcome(Some(3010), "installed; restart Windows to finish\n", 1).0, "restart");
        assert_eq!(outcome(Some(1618), "", 2).0, "waiting");
        // anyhow's "Error: " goes; the last line is the reason
        assert_eq!(outcome(Some(1), "\nError: installing the WSL components failed (0x80004005)\n\n", 1),
                   ("failed", "installing the WSL components failed (0x80004005)".to_string()));
        assert_eq!(outcome(Some(7), "", 1), ("failed", "oarbank-agent containers install exited 7".to_string()));
        assert_eq!(outcome(None, "", 1).0, "failed");
        // a restart that never finishes it, or an installation that never ends, fails in the end
        assert_eq!(outcome(Some(3010), "", MAX_ATTEMPTS).0, "failed");
        assert_eq!(outcome(Some(1618), "", MAX_ATTEMPTS).0, "failed");
        assert_eq!(outcome(Some(1618), "", MAX_ATTEMPTS - 1).0, "waiting");
        assert!(final_state("done") && final_state("failed") && !final_state("restart") && !final_state("waiting"));
    }

    #[test]
    fn what_a_person_is_told() {
        assert_eq!(line("restart", "x").as_deref(), Some("Restart Windows to finish container support"));
        assert_eq!(line("failed", "no virtualization").as_deref(), Some("Container support failed: no virtualization"));
        assert_eq!(line("done", ""), None);
        assert_eq!(line("", ""), None);
        assert!(line("installing", "").is_some() && line("scheduled", "").is_some() && line("waiting", "").is_some());
    }

    #[test]
    fn the_task_runs_as_system_after_the_agents_installer_and_at_boot() {
        let xml = task_xml(Path::new(r"C:\Program Files\Oarbank & Co\oarbank-launcher.exe"));
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-16\"?>"));
        assert!(xml.contains("<UserId>S-1-5-18</UserId>") && xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
        assert!(xml.contains("<BootTrigger>") && xml.contains("<EventTrigger>"));
        assert!(xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
        assert!(xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
        assert!(xml.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
        assert!(xml.contains("<Command>C:\\Program Files\\Oarbank &amp; Co\\oarbank-launcher.exe</Command>"));
        assert!(xml.contains("<Arguments>container-support run</Arguments>"));
        assert!(xml.contains("<WorkingDirectory>C:\\Program Files\\Oarbank &amp; Co</WorkingDirectory>"));
        // the subscription is escaped once inside the definition, and names this product's end-of-install events
        assert!(xml.contains("&lt;QueryList&gt;") && !xml.contains("<QueryList>"));
        let q = subscription();
        assert!(q.contains("Provider[@Name='MsiInstaller']") && q.contains("EventID=1033 or EventID=1035"));
        assert!(q.contains("Data='Oarbank agent'"));
        let bytes = utf16_bom("<a/>");
        assert_eq!(&bytes[..4], &[0xFF, 0xFE, b'<', 0]);
    }
}
