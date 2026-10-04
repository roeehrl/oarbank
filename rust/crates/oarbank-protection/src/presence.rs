//! Who is using the machine, from the platform's sessions. The parsing and the combination are
//! platform-neutral so that every OS tests them; the platform backends only do the reading.

use crate::signals::PresenceReading;

/// Linux: the login sessions systemd-logind tracks (`loginctl show-session`), and whether a person is using the
/// machine through one of them: a desktop session (x11, wayland, mir) that is active and whose desktop does not say
/// idle, or a text session (a local console, or a remote login) that has a terminal with recent input. Sessions
/// that are not a person at the machine never count: user managers, greeters, lock screens, background and closing
/// sessions, sessions switched away from on a seat, and ssh commands or automation without a terminal.
pub mod logind {
    use super::*;

    /// A terminal one of a session's processes has as its controlling terminal.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Terminal {
        /// Its name under /dev ("pts/0", "tty3").
        pub name: String,
        /// Its last input: the device's access time, which the kernel moves when the terminal is read (in steps of
        /// 8 s), CLOCK_REALTIME microseconds.
        pub input_us: u64,
    }

    /// The controlling terminals of a session's processes, which the platform reads where logind has no input
    /// time: OpenSSH opens a login's PAM session before it allocates the pty, so logind records no terminal (and
    /// no idle time) for any ssh session, with a pty or without.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub enum Terminals {
        /// Not read: not needed, or the session's processes could not be listed.
        #[default]
        NotRead,
        /// The most recently read controlling terminal among the session's processes; None: none of them has one.
        Read(Option<Terminal>),
    }

    /// What one session says about a person using the machine.
    #[derive(Debug, Clone, PartialEq)]
    pub enum Activity {
        /// A person's interactive session: seconds since its last input.
        Idle(f64),
        /// A person's interactive session whose last input cannot be read: why.
        Unknown(String),
        /// Not a person using the machine: what it is ("user manager", "no terminal", …).
        Ignored(&'static str),
    }

    /// One login session.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Session {
        pub id: String,
        pub uid: u32,
        pub user: String,
        pub service: String,
        /// user, user-early, user-incomplete, user-light, greeter, lock-screen, background, manager,
        /// manager-early, …
        pub class: String,
        /// x11, wayland, mir, tty, web, unspecified (an ssh session is tty, with or without a pty)
        pub kind: String,
        /// online (logged in, not in front on its seat), active, closing (logged out, processes left behind)
        pub state: String,
        pub active: bool,
        pub remote: bool,
        pub remote_host: String,
        pub seat: String,
        /// The terminal logind recorded ("tty2", "pts/0"); empty when it recorded none.
        pub tty: String,
        /// The X11 display (":0") of an X11 session.
        pub display: String,
        /// The session's leading process.
        pub leader: i32,
        /// The session's scope unit ("session-5.scope").
        pub scope: String,
        pub idle_hint: bool,
        /// CLOCK_REALTIME microseconds; 0: never tracked.
        pub idle_since_us: u64,
        pub locked: bool,
        /// Its processes' controlling terminals (filled in by the platform, see `needs_terminals`).
        pub terminals: Terminals,
    }

    impl Session {
        /// A person's session: not a user manager, greeter, lock screen or background job.
        pub fn is_person(&self) -> bool {
            self.class.starts_with("user")
        }

        pub fn graphical(&self) -> bool {
            matches!(self.kind.as_str(), "x11" | "wayland" | "mir")
        }

        /// A person's session in front of them: active (on its seat; a session at no seat is always active), and
        /// not one left closing after its person logged out.
        fn in_front(&self) -> bool {
            self.is_person() && self.active && self.state != "closing"
        }

        /// Whether the platform should read its processes' terminals: a person's text session in front whose input
        /// time logind does not know.
        pub fn needs_terminals(&self) -> bool {
            self.in_front() && !self.graphical() && self.idle_since_us == 0
        }

        /// Whether a person is using the machine through this session, and how long since their last input.
        /// A desktop's idle hint decides a graphical session (IdleSinceHint is when it went idle). A text
        /// session's last input is its terminal's: the one logind recorded or the leader's controlling terminal
        /// (logind reports its access time as IdleSinceHint, whether or not it counts as idle yet), else the most
        /// recently read controlling terminal of its processes. A text session with no terminal is no person at
        /// the machine (an ssh command, automation); one whose terminal's input time cannot be read is unknown.
        pub fn activity(&self, now_us: u64) -> Activity {
            if !self.is_person() {
                return Activity::Ignored(match self.class.as_str() {
                    c if c.starts_with("manager") => "user manager",
                    c if c.starts_with("greeter") => "greeter",
                    c if c.starts_with("lock-screen") => "lock screen",
                    c if c.starts_with("background") => "background",
                    _ => "not a user session",
                });
            }
            if self.state == "closing" {
                return Activity::Ignored("closing");
            }
            if !self.active {
                return Activity::Ignored("switched away");
            }
            let ago = |us: u64| now_us.saturating_sub(us) as f64 / 1e6;
            if self.graphical() {
                return Activity::Idle(if self.idle_hint && self.idle_since_us > 0 {
                    ago(self.idle_since_us)
                } else {
                    0.0
                });
            }
            let theirs = match &self.terminals {
                Terminals::Read(Some(t)) => Some(t.input_us),
                _ => None,
            };
            let logind = (self.idle_since_us > 0).then_some(self.idle_since_us);
            match (logind.max(theirs), &self.terminals) {
                (Some(input), _) => Activity::Idle(ago(input)),
                _ if !self.tty.is_empty() => Activity::Unknown(format!(
                    "logind has no input time for its terminal {}",
                    self.tty
                )),
                (None, Terminals::Read(_)) => Activity::Ignored("no terminal"),
                (None, Terminals::NotRead) => Activity::Unknown(
                    "logind records no terminal for it and its processes could not be read".into(),
                ),
            }
        }

        fn label(&self) -> String {
            let mut parts = vec![if self.service.is_empty() {
                self.kind.clone()
            } else {
                self.service.clone()
            }];
            if self.graphical() {
                parts.push(self.kind.clone());
                parts.extend((!self.seat.is_empty()).then(|| self.seat.clone()));
            } else if !self.tty.is_empty() {
                parts.push(self.tty.clone());
            } else if let Terminals::Read(Some(t)) = &self.terminals {
                parts.push(t.name.clone());
            }
            if !self.remote_host.is_empty() {
                parts.push(format!("from {}", self.remote_host));
            }
            format!("session {} ({})", self.id, parts.join(", "))
        }
    }

    /// The session ids from `loginctl list-sessions --no-legend` (the first column).
    pub fn parse_list(text: &str) -> Vec<String> {
        text.lines()
            .filter_map(|l| l.split_whitespace().next())
            .map(str::to_string)
            .collect()
    }

    /// The sessions from `loginctl show-session <ids…> -p …`: one `Key=Value` block per session, separated
    /// by blank lines. A property this systemd does not have is left out of the block, and an empty value is
    /// printed as `Key=`: either way the field keeps its empty default (no terminal, no remote host, no idle time).
    pub fn parse_show(text: &str) -> Vec<Session> {
        let mut out = vec![];
        let mut cur: Option<Session> = None;
        for line in text.lines().chain([""]) {
            let Some((k, v)) = line.split_once('=') else {
                if line.trim().is_empty() {
                    out.extend(cur.take());
                }
                continue;
            };
            let s = cur.get_or_insert_with(Session::default);
            let yes = v == "yes";
            match k {
                "Id" => s.id = v.to_string(),
                "User" => s.uid = v.parse().unwrap_or(u32::MAX),
                "Name" => s.user = v.to_string(),
                "Service" => s.service = v.to_string(),
                "Class" => s.class = v.to_string(),
                "Type" => s.kind = v.to_string(),
                "State" => s.state = v.to_string(),
                "Active" => s.active = yes,
                "Remote" => s.remote = yes,
                "RemoteHost" => s.remote_host = v.to_string(),
                "Seat" => s.seat = v.to_string(),
                "TTY" => s.tty = v.strip_prefix("/dev/").unwrap_or(v).to_string(),
                "Display" => s.display = v.to_string(),
                "Leader" => s.leader = v.parse().unwrap_or(0),
                "Scope" => s.scope = v.to_string(),
                "IdleHint" => s.idle_hint = yes,
                "IdleSinceHint" => s.idle_since_us = v.parse().unwrap_or(0),
                "LockedHint" => s.locked = yes,
                _ => {}
            }
        }
        out.retain(|s| !s.id.is_empty());
        out
    }

    /// The cgroup of a session's processes from its leader's `/proc/<pid>/cgroup`: the unified hierarchy's
    /// (`0::/user.slice/user-501.slice/session-5.scope`), else systemd's own v1 hierarchy (`name=systemd`).
    pub fn session_cgroup(proc_cgroup: &str) -> Option<String> {
        let path = |prefix: &str| {
            proc_cgroup
                .lines()
                .find_map(|l| l.split_once(prefix).map(|(_, p)| p.to_string()))
                .filter(|p| p.len() > 1)
        };
        path("0::").or_else(|| path(":name=systemd:"))
    }

    /// A terminal's name under /dev from its device number: the Unix 98 ptys (major 136), the virtual consoles
    /// (major 4, minors below 64) and the serial ports (major 4 from 64). None: another kind of terminal.
    pub fn tty_name(major: u32, minor: u32) -> Option<String> {
        match (major, minor) {
            (136, n) => Some(format!("pts/{n}")),
            (4, n @ 0..=63) => Some(format!("tty{n}")),
            (4, n) => Some(format!("ttyS{}", n - 64)),
            _ => None,
        }
    }

    /// The people logged in: their active sessions (a session switched away from on a seat is not in front of
    /// anyone; a session with no seat, such as ssh, is always active).
    pub fn people(sessions: &[Session]) -> impl Iterator<Item = &Session> {
        sessions.iter().filter(|s| s.is_person() && s.active)
    }

    /// The machine's presence: the least idle of the sessions a person is using, infinite when nobody is. A
    /// person's session whose last input cannot be read makes the whole reading unknown (counted as present).
    pub fn presence(sessions: &[Session], now_us: u64) -> PresenceReading {
        let mut least: Option<(f64, &Session)> = None;
        let mut using = 0;
        let mut unknown = vec![];
        let mut ignored: Vec<(&str, Vec<&str>)> = vec![];
        for s in sessions {
            match s.activity(now_us) {
                Activity::Idle(x) => {
                    using += 1;
                    if least.is_none_or(|(l, _)| x < l) {
                        least = Some((x, s));
                    }
                }
                Activity::Unknown(why) => unknown.push(format!("{}: {why}", s.label())),
                Activity::Ignored(what) => match ignored.iter_mut().find(|(w, _)| *w == what) {
                    Some((_, ids)) => ids.push(&s.id),
                    None => ignored.push((what, vec![&s.id])),
                },
            }
        }
        let n: usize = ignored.iter().map(|(_, ids)| ids.len()).sum();
        let note = if n == 0 {
            String::new()
        } else {
            let groups: Vec<String> = ignored
                .iter()
                .map(|(what, ids)| format!("{what}: {}", ids.join(", ")))
                .collect();
            format!(
                "; ignored {n} non-interactive session{} ({})",
                if n == 1 { "" } else { "s" },
                groups.join("; ")
            )
        };
        if !unknown.is_empty() {
            return PresenceReading::new(None, format!("unknown: {}{note}", unknown.join("; ")));
        }
        match least {
            None => PresenceReading::new(
                Some(f64::INFINITY),
                format!("logind: nobody is using the machine{note}"),
            ),
            Some((x, s)) => {
                let of = if using > 1 {
                    format!(", the least idle of {using}")
                } else {
                    String::new()
                };
                PresenceReading::new(Some(x), format!("logind: {}{of}{note}", s.label()))
            }
        }
    }

    /// The session in front on the machine's seat (seat0): the active person's session there, if any.
    pub fn front_session(sessions: &[Session]) -> Option<&Session> {
        people(sessions).find(|s| s.seat == "seat0")
    }
}

/// Windows: the sessions the Remote Desktop Services API (WTS) lists. The system service runs in session 0, which
/// has no input of its own, and WTS keeps no last-input time for the console session; the idle time comes from
/// the user's own session (GetLastInputInfo there).
pub mod wts {
    use super::*;

    /// WTS_CONNECTSTATE_CLASS: WTSActive (a person is at it, at the console or over Remote Desktop).
    pub const ACTIVE: u32 = 0;

    /// One session.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Session {
        pub id: u32,
        /// WTS_CONNECTSTATE_CLASS
        pub state: u32,
        pub user: String,
        /// WTSINFOEX's SessionFlags: Some(true) locked, Some(false) unlocked, None unknown.
        pub locked: Option<bool>,
    }

    impl Session {
        /// A person logged on and connected (not a disconnected or switched-away session).
        pub fn is_person(&self) -> bool {
            self.state == ACTIVE && !self.user.is_empty()
        }
    }

    /// The sessions in the elevated helper's reply to `{"op": "sessions"}` (oarbank-launcher, `helper_sessions.rs`):
    /// `{"ok": true, "sessions": [{"id", "state", "user", "locked"}]}`. The helper reads WTS as LocalSystem for the
    /// system service, whose virtual account WTS refuses. None for anything but a complete, well-formed list.
    pub fn parse_helper_reply(line: &str) -> Option<Vec<Session>> {
        use serde_json::Value;
        let v: Value = serde_json::from_str(line).ok()?;
        if v.get("ok")?.as_bool()? {
            v.get("sessions")?
                .as_array()?
                .iter()
                .map(|s| {
                    Some(Session {
                        id: u32::try_from(s.get("id")?.as_u64()?).ok()?,
                        state: u32::try_from(s.get("state")?.as_u64()?).ok()?,
                        user: s.get("user")?.as_str()?.to_string(),
                        locked: match s.get("locked")? {
                            Value::Null => None,
                            Value::Bool(b) => Some(*b),
                            _ => return None,
                        },
                    })
                })
                .collect()
        } else {
            None
        }
    }

    /// The session whose desktop is on the screen: the console session when a person is at it, else the first
    /// person's session (a Remote Desktop session).
    pub fn front_session(sessions: &[Session], console: u32) -> Option<&Session> {
        let people = || sessions.iter().filter(|s| s.is_person());
        people()
            .find(|s| s.id == console)
            .or_else(|| people().next())
    }

    /// The machine's presence: the least idle of the people's sessions, infinite with nobody logged on.
    /// `idle(id)` is a session's idle time where it can be read; a locked session has been idle at least since
    /// it was first seen locked (`locked_for(id)`); any other session makes the reading unknown (counted as
    /// present).
    pub fn presence(
        sessions: &[Session],
        idle: impl Fn(u32) -> Option<f64>,
        locked_for: impl Fn(u32) -> Option<f64>,
    ) -> PresenceReading {
        let mut least = f64::INFINITY;
        let mut unknown = vec![];
        let mut any = false;
        for s in sessions.iter().filter(|s| s.is_person()) {
            any = true;
            let known =
                idle(s.id).or_else(|| (s.locked == Some(true)).then(|| locked_for(s.id)).flatten());
            match known {
                Some(x) => least = least.min(x),
                None => unknown.push(format!("session {} ({})", s.id, s.user)),
            }
        }
        if !any {
            return PresenceReading::new(Some(f64::INFINITY), "wts: nobody logged on");
        }
        if !unknown.is_empty() {
            return PresenceReading::new(
                None,
                format!(
                    "unknown: no idle time for {} (it is read in the user's own session)",
                    unknown.join(", ")
                ),
            );
        }
        PresenceReading::new(Some(least), "wts")
    }
}

#[cfg(test)]
mod tests {
    use super::logind::*;

    const NOW: u64 = 1_790_000_100_000_000;

    /// What `loginctl show-session 1 2 5 10 7 3 12 -p Id -p User … -p LockedHint` prints on Ubuntu 26.04
    /// (systemd 259). 1, 5 and 10 are the oarbank-ubuntu VM's: a service account's user manager, an ssh command
    /// without a terminal and an ssh login with a pty, which logind cannot tell apart (no TTY, no idle time); 2 is a
    /// person's user manager, 7 a GNOME session on seat0 whose desktop has been idle for 100 s, 3 a text console on
    /// the same seat switched away from, 12 an ssh login from another machine whose pty logind recorded (an
    /// OpenSSH that sets the terminal before it opens the PAM session), idle for two hours.
    const SHOW: &str = "Id=1\nUser=999\nName=oarbank\nSeat=\nTTY=\nDisplay=\nRemote=no\nRemoteHost=\nService=systemd-user\n\
        Scope=\nLeader=1596\nType=unspecified\nClass=manager-early\nActive=yes\nState=active\nIdleHint=no\n\
        IdleSinceHint=0\nLockedHint=no\n\n\
        Id=2\nUser=501\nName=tnt\nSeat=\nTTY=\nDisplay=\nRemote=no\nRemoteHost=\nService=systemd-user\nScope=\n\
        Leader=1600\nType=unspecified\nClass=manager\nActive=yes\nState=active\nIdleHint=no\nIdleSinceHint=0\n\
        LockedHint=no\n\n\
        Id=5\nUser=501\nName=tnt\nSeat=\nTTY=\nDisplay=\nRemote=no\nRemoteHost=\nService=sshd\nScope=session-5.scope\n\
        Leader=2261\nType=tty\nClass=user\nActive=yes\nState=active\nIdleHint=no\nIdleSinceHint=0\nLockedHint=no\n\n\
        Id=10\nUser=501\nName=tnt\nSeat=\nTTY=\nDisplay=\nRemote=no\nRemoteHost=\nService=sshd\n\
        Scope=session-10.scope\nLeader=95009\nType=tty\nClass=user\nActive=yes\nState=active\nIdleHint=no\n\
        IdleSinceHint=0\nLockedHint=no\n\n\
        Id=7\nUser=1000\nName=ada\nSeat=seat0\nTTY=tty2\nDisplay=:0\nRemote=no\nRemoteHost=\nService=gdm-password\n\
        Scope=session-7.scope\nLeader=1690\nType=x11\nClass=user\nActive=yes\nState=active\nIdleHint=yes\n\
        IdleSinceHint=1790000000000000\nLockedHint=yes\n\n\
        Id=3\nUser=1000\nName=ada\nSeat=seat0\nTTY=tty3\nDisplay=\nRemote=no\nRemoteHost=\nService=login\n\
        Scope=session-3.scope\nLeader=1412\nType=tty\nClass=user\nActive=no\nState=online\nIdleHint=no\n\
        IdleSinceHint=1790000060000000\nLockedHint=no\n\n\
        Id=12\nUser=501\nName=tnt\nSeat=\nTTY=pts/1\nDisplay=\nRemote=yes\nRemoteHost=192.0.2.7\nService=sshd\n\
        Scope=session-12.scope\nLeader=3310\nType=tty\nClass=user\nActive=yes\nState=active\nIdleHint=no\n\
        IdleSinceHint=1789992900000000\nLockedHint=no\n";

    /// GDM's login screen on seat0 with nobody logged in.
    const GREETER: &str = "Id=c1\nUser=120\nName=gdm\nSeat=seat0\nTTY=tty1\nDisplay=\nRemote=no\nRemoteHost=\n\
        Service=gdm-launch-environment\nScope=session-c1.scope\nLeader=1042\nType=wayland\nClass=greeter\nActive=yes\n\
        State=active\nIdleHint=no\nIdleSinceHint=0\nLockedHint=no\n";

    /// The sessions of `SHOW`, their processes' terminals read as the platform reads them: none of the ssh
    /// command's processes has a terminal, the ssh login's shell is on pts/0, last read 3 s ago.
    fn sessions() -> Vec<Session> {
        let mut s = parse_show(SHOW);
        for x in s.iter_mut().filter(|x| x.needs_terminals()) {
            x.terminals = Terminals::Read((x.id == "10").then(|| Terminal {
                name: "pts/0".into(),
                input_us: NOW - 3_000_000,
            }));
        }
        s
    }

    fn get(s: &[Session], id: &str) -> Session {
        s.iter().find(|x| x.id == id).cloned().unwrap()
    }

    fn pick(s: &[Session], ids: &[&str]) -> Vec<Session> {
        ids.iter().map(|id| get(s, id)).collect()
    }

    #[test]
    fn parses_sessions_and_session_ids() {
        assert_eq!(
            parse_list("1 999 oarbank - 1534 manager-early - no -\n5 501 tnt     - 2171 user          - no -\n"),
            ["1", "5"]
        );
        let s = parse_show(SHOW);
        assert_eq!(s.len(), 7);
        let ssh = get(&s, "5");
        assert_eq!(
            (
                ssh.uid,
                ssh.kind.as_str(),
                ssh.service.as_str(),
                ssh.state.as_str(),
                ssh.scope.as_str()
            ),
            (501, "tty", "sshd", "active", "session-5.scope")
        );
        // empty values stay empty: no terminal, no remote host, no idle time
        assert!(
            ssh.tty.is_empty()
                && ssh.remote_host.is_empty()
                && !ssh.remote
                && ssh.idle_since_us == 0
        );
        let g = get(&s, "7");
        assert!(g.graphical() && g.is_person() && g.idle_hint && g.active);
        assert_eq!(
            (g.seat.as_str(), g.tty.as_str(), g.idle_since_us),
            ("seat0", "tty2", NOW - 100_000_000)
        );
        let r = get(&s, "12");
        assert!(r.remote);
        assert_eq!(
            (r.tty.as_str(), r.remote_host.as_str()),
            ("pts/1", "192.0.2.7")
        );
        assert_eq!(get(&s, "3").state, "online");
        assert!(!get(&s, "1").is_person() && !get(&s, "2").is_person());
        // a systemd without some of the properties leaves them out of the block: nothing is misread
        let old = parse_show(
            "Id=4\nUser=501\nName=tnt\nService=sshd\nType=tty\nClass=user\nActive=yes\n",
        );
        assert_eq!(
            (
                old[0].tty.as_str(),
                old[0].state.as_str(),
                old[0].idle_since_us
            ),
            ("", "", 0)
        );
        // an older logind's "/dev/"-prefixed terminal
        assert_eq!(parse_show("Id=4\nTTY=/dev/pts/2\n")[0].tty, "pts/2");
    }

    #[test]
    fn finds_a_sessions_cgroup_and_terminal_names() {
        assert_eq!(
            session_cgroup("0::/user.slice/user-501.slice/session-10.scope\n").as_deref(),
            Some("/user.slice/user-501.slice/session-10.scope")
        );
        // cgroup v1 (hybrid or legacy): systemd's own hierarchy
        let v1 = "12:pids:/user.slice/user-501.slice/session-3.scope\n1:name=systemd:/user.slice/user-501.slice/session-3.scope\n";
        assert_eq!(
            session_cgroup(v1).as_deref(),
            Some("/user.slice/user-501.slice/session-3.scope")
        );
        assert_eq!(session_cgroup("0::/\n"), None);
        assert_eq!(session_cgroup(""), None);
        assert_eq!(tty_name(136, 0).as_deref(), Some("pts/0"));
        assert_eq!(tty_name(136, 300).as_deref(), Some("pts/300"));
        assert_eq!(tty_name(4, 3).as_deref(), Some("tty3"));
        assert_eq!(tty_name(4, 65).as_deref(), Some("ttyS1"));
        assert_eq!(tty_name(188, 0), None);
    }

    #[test]
    fn what_each_session_says_about_a_person_at_the_machine() {
        let s = sessions();
        let act = |id: &str| get(&s, id).activity(NOW);
        // user managers are no person
        assert_eq!(act("1"), Activity::Ignored("user manager"));
        assert_eq!(act("2"), Activity::Ignored("user manager"));
        // an ssh command (or automation) has no terminal: not a person using the machine
        assert_eq!(act("5"), Activity::Ignored("no terminal"));
        // an ssh login with a pty: its shell's terminal had input 3 s ago
        assert_eq!(act("10"), Activity::Idle(3.0));
        // the desktop says idle since 100 s ago; a desktop that says active is present
        assert_eq!(act("7"), Activity::Idle(100.0));
        let busy = Session {
            idle_hint: false,
            ..get(&s, "7")
        };
        assert_eq!(busy.activity(NOW), Activity::Idle(0.0));
        // a console switched away from on the seat is in front of nobody
        assert_eq!(act("3"), Activity::Ignored("switched away"));
        // the same console in front: its terminal's last input, whether or not logind calls it idle yet
        let console = Session {
            active: true,
            state: "active".into(),
            ..get(&s, "3")
        };
        assert_eq!(console.activity(NOW), Activity::Idle(40.0));
        // a remote login logind recorded the pty of, untouched for two hours
        assert_eq!(act("12"), Activity::Idle(7200.0));
        // the most recent of logind's input time and the processes' terminals
        let both = Session {
            terminals: Terminals::Read(Some(Terminal {
                name: "pts/4".into(),
                input_us: NOW - 5_000_000,
            })),
            ..get(&s, "12")
        };
        assert_eq!(both.activity(NOW), Activity::Idle(5.0));
        // greeters, lock screens, background jobs (cron) and sessions left closing after a logout never count
        for (class, state, what) in [
            ("greeter", "active", "greeter"),
            ("lock-screen", "active", "lock screen"),
            ("background", "active", "background"),
            ("user", "closing", "closing"),
        ] {
            let x = Session {
                class: class.into(),
                state: state.into(),
                ..get(&s, "10")
            };
            assert_eq!(x.activity(NOW), Activity::Ignored(what), "{class} {state}");
            assert!(!x.needs_terminals());
        }
        // logind's terminal without an input time (its access time could not be read): unknown
        let no_input = Session {
            idle_since_us: 0,
            ..console.clone()
        };
        assert!(
            matches!(no_input.activity(NOW), Activity::Unknown(ref w) if w.contains("tty3")),
            "{:?}",
            no_input.activity(NOW)
        );
        // an ssh session whose processes could not be read: a pty cannot be ruled out
        let unread = Session {
            terminals: Terminals::NotRead,
            ..get(&s, "5")
        };
        assert!(matches!(unread.activity(NOW), Activity::Unknown(_)));
        // only a person's text session in front without logind's input time needs its processes read
        let need: Vec<String> = parse_show(SHOW)
            .into_iter()
            .filter(Session::needs_terminals)
            .map(|x| x.id)
            .collect();
        assert_eq!(need, ["5", "10"]);
    }

    #[test]
    fn presence_is_the_least_idle_person_and_unknown_counts_as_present() {
        let s = sessions();
        // the VM today: user managers and the ssh command running this: nobody is using the machine
        let r = presence(&pick(&s, &["1", "2", "5"]), NOW);
        assert_eq!(r.idle_s, Some(f64::INFINITY));
        assert_eq!(
            r.source,
            "logind: nobody is using the machine; ignored 3 non-interactive sessions (user manager: 1, 2; no terminal: 5)"
        );
        // someone logs in over ssh with a pty and types
        let r = presence(&pick(&s, &["1", "2", "5", "10"]), NOW);
        assert_eq!(r.idle_s, Some(3.0));
        assert_eq!(
            r.source,
            "logind: session 10 (sshd, pts/0); ignored 3 non-interactive sessions (user manager: 1, 2; no terminal: 5)"
        );
        // the least idle of several people: the GNOME desktop beats an ssh login idle for an hour
        let mut idle_ssh = get(&s, "10");
        idle_ssh.terminals = Terminals::Read(Some(Terminal {
            name: "pts/0".into(),
            input_us: NOW - 3_600_000_000,
        }));
        let r = presence(&[idle_ssh, get(&s, "7"), get(&s, "3")], NOW);
        assert_eq!(r.idle_s, Some(100.0));
        assert_eq!(
            r.source,
            "logind: session 7 (gdm-password, x11, seat0), the least idle of 2; ignored 1 non-interactive session \
             (switched away: 3)"
        );
        // a remote login left idle for two hours is far from present
        let r = presence(&pick(&s, &["12"]), NOW);
        assert_eq!(r.idle_s, Some(7200.0));
        assert_eq!(r.source, "logind: session 12 (sshd, pts/1, from 192.0.2.7)");
        // every session together
        assert_eq!(presence(&s, NOW).idle_s, Some(3.0));
        // nobody logged in at all
        let r = presence(&[], NOW);
        assert_eq!(
            (r.idle_s, r.source.as_str()),
            (Some(f64::INFINITY), "logind: nobody is using the machine")
        );
        // GDM's login screen with nobody logged in
        let greeter = parse_show(GREETER);
        let r = presence(&greeter, NOW);
        assert_eq!(r.idle_s, Some(f64::INFINITY));
        assert!(r.source.ends_with("(greeter: c1)"), "{}", r.source);
        // an ssh session whose processes could not be read: unknown, which capacity treats as someone present
        let mut unread = pick(&s, &["1", "5", "7"]);
        unread[1].terminals = Terminals::NotRead;
        let r = presence(&unread, NOW);
        assert_eq!(r.idle_s, None);
        assert_eq!(r.effective_idle_s(), 0.0);
        assert!(
            r.source
                .starts_with("unknown: session 5 (sshd): logind records no terminal"),
            "{}",
            r.source
        );
        assert!(r.source.ends_with("(user manager: 1)"), "{}", r.source);
        // a session switched away from on the seat is in front of nobody
        let away = Session {
            active: false,
            ..get(&s, "7")
        };
        assert_eq!(
            presence(std::slice::from_ref(&away), NOW).idle_s,
            Some(f64::INFINITY)
        );
        assert_eq!(front_session(&[away]), None);
        assert_eq!(front_session(&s).map(|f| f.id.as_str()), Some("7"));
    }

    #[test]
    fn windows_presence_from_sessions() {
        use super::wts::{self, Session};
        // what WTS lists on a Windows 11 machine with one person at the console: session 0 (services) and the
        // console session, active and unlocked
        let services = Session {
            id: 0,
            state: 4,
            user: String::new(),
            locked: None,
        };
        let console = Session {
            id: 1,
            state: wts::ACTIVE,
            user: "ada".into(),
            locked: Some(false),
        };
        let none = |_| None;
        // the system service in session 0 cannot read the console's input: unknown, counted as present
        let r = wts::presence(&[services.clone(), console.clone()], none, none);
        assert_eq!(r.idle_s, None);
        assert!(r.source.contains("session 1 (ada)"), "{}", r.source);
        // read in the user's own session
        let r = wts::presence(
            &[services.clone(), console.clone()],
            |id| (id == 1).then_some(42.0),
            none,
        );
        assert_eq!((r.idle_s, r.source.as_str()), (Some(42.0), "wts"));
        // locked: idle at least since the lock was seen
        let locked = Session {
            locked: Some(true),
            ..console.clone()
        };
        assert_eq!(
            wts::presence(&[locked], none, |_| Some(600.0)).idle_s,
            Some(600.0)
        );
        assert_eq!(
            wts::front_session(&[services.clone(), console.clone()], 1).map(|s| s.id),
            Some(1)
        );
        let rdp = Session {
            id: 3,
            ..console.clone()
        };
        assert_eq!(
            wts::front_session(&[rdp.clone(), console.clone()], 1).map(|s| s.id),
            Some(1)
        );
        assert_eq!(
            wts::front_session(&[services.clone(), rdp], 1).map(|s| s.id),
            Some(3)
        );
        assert_eq!(wts::front_session(std::slice::from_ref(&services), 1), None);
        // disconnected (switched away, or a dropped Remote Desktop session) and nobody else: nobody is present
        let away = Session {
            state: 4,
            ..console
        };
        assert_eq!(
            wts::presence(&[services, away], none, none).idle_s,
            Some(f64::INFINITY)
        );
    }

    /// The system service's virtual account may not ask WTS, so it asks the elevated helper, which reads WTS as
    /// LocalSystem. The reply's format is shared with the helper through vectors/helper-sessions-reply.json (the
    /// launcher's test holds its own serializer to the same file).
    #[test]
    fn windows_sessions_from_the_elevated_helper() {
        use super::wts::{self, Session};
        let line = include_str!("../vectors/helper-sessions-reply.json");
        let s = wts::parse_helper_reply(line).expect("the helper's reply parses");
        assert_eq!(
            s,
            [
                Session {
                    id: 0,
                    state: 4,
                    user: String::new(),
                    locked: None
                },
                Session {
                    id: 1,
                    state: wts::ACTIVE,
                    user: "ada".into(),
                    locked: Some(false)
                },
                Session {
                    id: 2,
                    state: wts::ACTIVE,
                    user: "bo".into(),
                    locked: Some(true)
                },
            ]
        );
        assert_eq!(wts::front_session(&s, 1).map(|x| x.id), Some(1));
        // a refusal, a partial list or a malformed entry is no list: the reading stays unknown
        for bad in [
            r#"{"ok": false, "error": "unknown op"}"#,
            r#"{"ok": true}"#,
            r#"{"ok": true, "sessions": [{"id": 1, "state": 0, "user": "ada"}]}"#,
            r#"{"ok": true, "sessions": [{"id": -1, "state": 0, "user": "ada", "locked": null}]}"#,
            r#"{"ok": true, "sessions": [{"id": 1, "state": 0, "user": "ada", "locked": "no"}]}"#,
            r#"{"ok": true, "sessions": [{"id": 4294967296, "state": 0, "user": "", "locked": null}]}"#,
            "not json",
        ] {
            assert_eq!(wts::parse_helper_reply(bad), None, "{bad}");
        }
        assert_eq!(
            wts::parse_helper_reply(r#"{"ok": true, "sessions": []}"#),
            Some(vec![])
        );
    }
}
