//! The session helper on Windows. The elevated helper service starts one in each person's session
//! (`oarbank-agent session-helper`, with no window); it reports to the system service over the named pipe
//! `\\.\pipe\oarbank-session` (`OARBANK_SESSION_PIPE` overrides it), whose client session the pipe names. It tells
//! what session 0 cannot read: the person's processes' command lines, the foreground window and the last input.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::io::FromRawHandle;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_INBOUND};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientSessionId, PIPE_READMODE_BYTE,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

use super::front::front;
use super::presence::{own_idle_s, own_session};
use super::procs::{command_line, own_user, process_user, processes};
use crate::session::{
    Described, FrontClaim, Principal, ProcClaim, Report, SessionHub, INTERVAL, MAX_LINE, PROTOCOL,
};

/// SYSTEM and the service's own account in full; interactive users (each session's helper) may write.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;OW)(A;;GRGW;;;IU)";
const ERROR_PIPE_CONNECTED: i32 = 535;

pub fn pipe_name() -> String {
    std::env::var("OARBANK_SESSION_PIPE").unwrap_or_else(|_| r"\\.\pipe\oarbank-session".into())
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// Serve helpers (the system service): the pipe's first instance is ours (no other process may have created it),
/// each connection is read on a thread of its own.
pub fn serve(hub: Arc<SessionHub>) -> std::io::Result<()> {
    let sddl = wide(PIPE_SDDL);
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL; the descriptor is kept for the process's life (every instance uses it).
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let sd = sd as usize;
    let name = wide(&pipe_name());
    let instance = move |first: bool| {
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd as PSECURITY_DESCRIPTOR,
            bInheritHandle: 0,
        };
        let flags = PIPE_ACCESS_INBOUND
            | if first {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
        // SAFETY: a NUL-terminated name and live security attributes.
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                flags,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                0,
                64 << 10,
                0,
                &sa,
            )
        };
        // kept as an address: a HANDLE may not cross to the serving thread, the number may
        if h == INVALID_HANDLE_VALUE {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(h as usize)
        }
    };
    let mut next = Some(instance(true)?);
    std::thread::Builder::new()
        .name("session-hub".into())
        .spawn(move || loop {
            let Some(h) = next.take().or_else(|| instance(false).ok()) else {
                std::thread::sleep(INTERVAL);
                continue;
            };
            let h = h as HANDLE;
            // SAFETY: a pipe instance we own.
            let connected = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) } != 0
                || std::io::Error::last_os_error().raw_os_error() == Some(ERROR_PIPE_CONNECTED);
            if !connected {
                // SAFETY: we own the handle.
                unsafe { CloseHandle(h) };
                continue;
            }
            let mut session = 0u32;
            // SAFETY: a connected instance and a valid out-pointer.
            let known = unsafe { GetNamedPipeClientSessionId(h, &mut session) } != 0;
            // SAFETY: the File owns the handle from here and closes it.
            let file = unsafe { File::from_raw_handle(h as _) };
            if !known || session == 0 {
                continue; // session 0 is the services', no person's
            }
            let hub = hub.clone();
            let _ = std::thread::Builder::new()
                .name("session-helper".into())
                .spawn(move || take_reports(&hub, session, file));
        })?;
    Ok(())
}

fn take_reports(hub: &SessionHub, session: u32, file: File) {
    let who = Principal::Session(session);
    let mut r = BufReader::new(file);
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut r).take(MAX_LINE as u64).read_line(&mut line) {
            Ok(n) if n > 0 && line.ends_with('\n') => {}
            _ => break,
        }
        let Ok(report) = serde_json::from_str::<Report>(&line) else {
            continue;
        };
        // a process is the session's when the process list puts it there, with the start time claimed
        let procs = processes().unwrap_or_default();
        hub.accept(who, report, |pid, start| {
            procs.iter().any(|p| {
                p.pid as i32 == pid
                    && p.session == session
                    && (start == 0 || p.start_us() == Some(start))
            })
        });
    }
    hub.gone(who);
}

fn report(session: u32, user: Option<&[u8]>, described: &mut Described) -> Report {
    // this person's processes in the session: those whose token is this account's (not the system's own session
    // processes, nor an elevated one, which this account may not open)
    let mine: Vec<_> = processes()
        .unwrap_or_default()
        .into_iter()
        .filter(|p| {
            p.session == session && user.is_some() && process_user(p.pid).as_deref() == user
        })
        .filter_map(|p| Some((p.pid, p.start_us()?)))
        .collect();
    let live: Vec<(i32, u64)> = mine.iter().map(|&(pid, s)| (pid as i32, s)).collect();
    described.retain_live(&live);
    let procs = mine
        .iter()
        .filter(|&&(pid, s)| described.is_new((pid as i32, s)))
        .map(|&(pid, start_us)| ProcClaim {
            pid: pid as i32,
            start_us,
            path: None, // the service reads paths itself
            argv: command_line(pid),
        })
        .collect();
    Report {
        v: PROTOCOL,
        live,
        procs,
        idle_s: own_idle_s(),
        front: Some(FrontClaim::of(&front(None))),
        ..Report::default()
    }
}

/// The helper: report this session's processes, front window and last input to the system service every
/// interval, connecting again (every interval) while it is not there. Never returns.
pub fn run_helper() -> ! {
    let session = own_session();
    let user = own_user();
    loop {
        if let Ok(mut pipe) = OpenOptions::new().write(true).open(pipe_name()) {
            let mut described = Described::default();
            loop {
                let mut line =
                    serde_json::to_string(&report(session, user.as_deref(), &mut described))
                        .unwrap_or_default();
                line.push('\n');
                if pipe.write_all(line.as_bytes()).is_err() {
                    break;
                }
                std::thread::sleep(INTERVAL);
            }
        }
        std::thread::sleep(INTERVAL);
    }
}
