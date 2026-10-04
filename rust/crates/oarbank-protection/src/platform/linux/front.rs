//! What is in front on a Linux machine's seat. logind names the session there. An X11 session's front window
//! comes from its X server (EWMH: the root's `_NET_ACTIVE_WINDOW`, then that window's `_NET_WM_PID`), opened
//! with the cookie from the session's Xauthority, which only the session's own account may read. A text
//! console's front is its terminal's foreground process group. A Wayland compositor tells no other program
//! which window is in front.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use super::procs::reader;
use crate::presence::logind::{front_session, Session};
use crate::session::{Principal, SessionHub};
use crate::signals::{Front, FrontReading};
use crate::x11;

/// An open connection to one X server.
struct Conn {
    display: String,
    stream: UnixStream,
    root: u32,
    active_window: u32,
    wm_pid: u32,
}

/// What the active window tells.
enum Window {
    Pid(i32),
    None,
    /// The window publishes no `_NET_WM_PID`.
    NoPid,
}

impl Conn {
    /// One request and its reply; Ok(None) is an X error (a vanished window), Err a broken connection.
    fn round_trip(&mut self, req: &[u8]) -> std::io::Result<Option<([u8; 32], Vec<u8>)>> {
        self.stream.write_all(req)?;
        let mut r = [0u8; 32];
        // no events are selected; an error is 32 bytes like a reply's head
        self.stream.read_exact(&mut r)?;
        let Some(extra) = x11::reply_extra(&r) else {
            return Ok(None);
        };
        let mut more = vec![0u8; extra];
        self.stream.read_exact(&mut more)?;
        Ok(Some((r, more)))
    }

    fn atom(&mut self, name: &str) -> Option<u32> {
        let (r, _) = self.round_trip(&x11::intern_atom(name)).ok()??;
        Some(x11::atom_of(&r)).filter(|a| *a != 0)
    }

    fn property(&mut self, window: u32, property: u32) -> std::io::Result<Option<u32>> {
        Ok(self
            .round_trip(&x11::get_property(window, property))?
            .and_then(|(r, value)| x11::property_u32(&r, &value)))
    }

    fn open(display: &str, xauthority: Option<&std::path::Path>) -> Result<Self, String> {
        let n = x11::display_number(display)
            .ok_or_else(|| format!("display {display} is not local"))?;
        let stream = UnixStream::connect(format!("/tmp/.X11-unix/X{n}"))
            .map_err(|e| format!("cannot reach display {display}: {e}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(1))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(1))).ok();
        let entries = xauthority
            .and_then(|p| std::fs::read(p).ok())
            .map(|b| x11::parse_xauthority(&b))
            .unwrap_or_default();
        let host = hostname();
        let (name, data) = match x11::cookie(&entries, &host, n) {
            Some(c) => (x11::MIT_MAGIC_COOKIE, c.to_vec()),
            None => ("", vec![]),
        };
        let mut c = Conn {
            display: display.to_string(),
            stream,
            root: 0,
            active_window: 0,
            wm_pid: 0,
        };
        c.stream
            .write_all(&x11::setup_request(name, &data))
            .map_err(|e| e.to_string())?;
        let mut h = [0u8; 8];
        c.stream.read_exact(&mut h).map_err(|e| e.to_string())?;
        let (Ok(len) | Err(len)) = x11::setup_header(&h);
        let mut more = vec![0u8; len];
        c.stream.read_exact(&mut more).map_err(|e| e.to_string())?;
        if x11::setup_header(&h).is_err() {
            return Err(format!(
                "display {display} refused the connection (no usable Xauthority cookie)"
            ));
        }
        c.root = x11::root_window(&more).ok_or("no screen")?;
        c.active_window = c.atom("_NET_ACTIVE_WINDOW").ok_or_else(|| {
            format!("display {display} has no window manager that publishes _NET_ACTIVE_WINDOW")
        })?;
        c.wm_pid = c
            .atom("_NET_WM_PID")
            .ok_or_else(|| format!("no window on display {display} publishes _NET_WM_PID"))?;
        Ok(c)
    }

    /// The active window and its process.
    fn front(&mut self) -> std::io::Result<Window> {
        let w = self.property(self.root, self.active_window)?.unwrap_or(0);
        if w == 0 {
            return Ok(Window::None);
        }
        Ok(
            match self
                .property(w, self.wm_pid)?
                .and_then(|p| i32::try_from(p).ok())
            {
                Some(pid) if pid > 0 => Window::Pid(pid),
                _ => Window::NoPid,
            },
        )
    }
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is 256 bytes and gethostname NUL-terminates within it.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return String::new();
    }
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// What is in front on an X display, read with the cookie in `xauthority`.
pub fn x11_front(display: &str, xauthority: Option<&std::path::Path>) -> FrontReading {
    match Conn::open(display, xauthority) {
        Ok(mut c) => describe(&c.display.clone(), c.front()),
        Err(e) => FrontReading::new(Front::Unknown, format!("unknown: {e}")),
    }
}

fn describe(display: &str, w: std::io::Result<Window>) -> FrontReading {
    match w {
        Ok(Window::Pid(pid)) => FrontReading::new(Front::App(pid), format!("x11 {display}")),
        Ok(Window::None) => {
            FrontReading::new(Front::Nothing, format!("no active window on {display}"))
        }
        Ok(Window::NoPid) => FrontReading::new(
            Front::Unknown,
            format!("unknown: the active window on {display} publishes no _NET_WM_PID"),
        ),
        Err(e) => FrontReading::new(Front::Unknown, format!("unknown: display {display}: {e}")),
    }
}

/// `KEY=value` from a process's environment (only the process's own account may read it).
fn environ(pid: i32) -> Option<HashMap<String, String>> {
    let b = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    Some(
        b.split(|&c| c == 0)
            .filter_map(|kv| {
                let s = String::from_utf8_lossy(kv);
                let (k, v) = s.split_once('=')?;
                Some((k.to_string(), v.to_string()))
            })
            .collect(),
    )
}

/// The Xauthority a display's clients use: XAUTHORITY in the environment of one of the account's processes on
/// that display (the session's own processes carry it, wherever the display manager put the file), else the
/// usual places.
fn find_xauthority(uid: u32, display: &str) -> Option<PathBuf> {
    let r = reader();
    let owned: Vec<i32> = r
        .list(|u| u == uid, &Default::default())
        .unwrap_or_default()
        .into_iter()
        .map(|e| e.pid)
        .collect();
    for pid in owned {
        if let Some(env) = environ(pid) {
            if env.get("DISPLAY").map(String::as_str) == Some(display) {
                if let Some(x) = env.get("XAUTHORITY") {
                    return Some(PathBuf::from(x));
                }
            }
        }
    }
    let gdm = PathBuf::from(format!("/run/user/{uid}/gdm/Xauthority"));
    if gdm.exists() {
        return Some(gdm);
    }
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".Xauthority"))
        .filter(|p| p.exists())
}

/// The front app, from logind's sessions and the X server of an X11 session in front; another account's display
/// through that account's session helper.
pub struct FrontReader {
    conn: Option<Conn>,
    hub: Option<Arc<SessionHub>>,
}

impl FrontReader {
    pub fn new(hub: Option<Arc<SessionHub>>) -> Self {
        Self { conn: None, hub }
    }

    pub fn read(&mut self, sessions: Option<&[Session]>) -> FrontReading {
        let Some(sessions) = sessions else {
            return FrontReading::new(
                Front::Unknown,
                "unknown: systemd-logind is not running here",
            );
        };
        let Some(s) = front_session(sessions) else {
            self.conn = None;
            return FrontReading::new(Front::Nothing, "no one at seat0");
        };
        match s.kind.as_str() {
            "x11" => self.x11(s),
            "tty" => {
                let tpgid = reader().stat(s.leader).map_or(-1, |st| st.tpgid);
                if tpgid > 0 {
                    FrontReading::new(Front::App(tpgid), format!("terminal of session {}", s.id))
                } else {
                    FrontReading::new(Front::Unknown, format!("unknown: session {} has no terminal", s.id))
                }
            }
            "wayland" => FrontReading::new(
                Front::Unknown,
                format!("unknown: session {} is Wayland, whose compositor tells no other program which window is in front", s.id),
            ),
            k => FrontReading::new(Front::Unknown, format!("unknown: session {} is of type {k}", s.id)),
        }
    }

    fn x11(&mut self, s: &Session) -> FrontReading {
        // SAFETY: getuid cannot fail.
        if s.uid != unsafe { libc::getuid() } {
            return self
                .hub
                .as_ref()
                .and_then(|h| h.front(Principal::Uid(s.uid)))
                .unwrap_or_else(|| {
                    FrontReading::new(
                        Front::Unknown,
                        format!(
                            "unknown: session {} belongs to another account, whose display only it may open, and \
                             no session helper of that account reports",
                            s.id
                        ),
                    )
                });
        }
        if self.conn.as_ref().is_some_and(|c| c.display != s.display) {
            self.conn = None;
        }
        let kept = self.conn.is_some();
        let mut w = match self.front_on(s) {
            Ok(w) => w,
            Err(r) => return r,
        };
        // a connection kept from an earlier tick may have broken (the server restarted): open it once more
        if w.is_err() && kept {
            self.conn = None;
            w = match self.front_on(s) {
                Ok(w) => w,
                Err(r) => return r,
            };
        }
        if w.is_err() {
            self.conn = None;
        }
        describe(&s.display, w)
    }

    /// The active window on the session's display, opening a connection when there is none.
    fn front_on(&mut self, s: &Session) -> Result<std::io::Result<Window>, FrontReading> {
        let c = match self.conn.take() {
            Some(c) => c,
            None => Conn::open(&s.display, find_xauthority(s.uid, &s.display).as_deref())
                .map_err(|e| FrontReading::new(Front::Unknown, format!("unknown: {e}")))?,
        };
        let c = self.conn.insert(c);
        Ok(c.front())
    }
}
