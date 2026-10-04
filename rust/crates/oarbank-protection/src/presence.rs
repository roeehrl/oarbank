//! Who is using the machine, from the platform's sessions. The parsing and the combination are
//! platform-neutral so that every OS tests them; the platform backends only do the reading.

use crate::signals::PresenceReading;

/// Linux: the login sessions systemd-logind tracks (`loginctl show-session`).
pub mod logind {
    use super::*;

    /// One login session.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Session {
        pub id: String,
        pub uid: u32,
        pub user: String,
        pub service: String,
        /// user, user-early, user-incomplete, greeter, lock-screen, background, manager, manager-early, …
        pub class: String,
        /// x11, wayland, mir, tty, web, unspecified
        pub kind: String,
        pub active: bool,
        pub remote: bool,
        pub seat: String,
        /// The X11 display (":0") of an X11 session.
        pub display: String,
        /// The session's leading process.
        pub leader: i32,
        pub idle_hint: bool,
        /// CLOCK_REALTIME microseconds; 0: never tracked.
        pub idle_since_us: u64,
        pub locked: bool,
    }

    impl Session {
        /// A person's session: not a user manager, greeter, lock screen or background job.
        pub fn is_person(&self) -> bool {
            self.class.starts_with("user")
        }

        pub fn graphical(&self) -> bool {
            matches!(self.kind.as_str(), "x11" | "wayland" | "mir")
        }

        /// Seconds since this session's last input; None when logind cannot tell. A graphical session's desktop
        /// sets the idle hint (IdleSinceHint is when it last changed); a text session's is the terminal's last
        /// access time, kept whether or not it counts as idle yet. A session with neither (no terminal, no
        /// desktop) has no idle time.
        pub fn idle_s(&self, now_us: u64) -> Option<f64> {
            let since = (self.idle_since_us > 0)
                .then(|| now_us.saturating_sub(self.idle_since_us) as f64 / 1e6);
            if self.graphical() {
                Some(if self.idle_hint {
                    since.unwrap_or(0.0)
                } else {
                    0.0
                })
            } else {
                since
            }
        }

        fn label(&self) -> String {
            let via = if self.service.is_empty() {
                &self.kind
            } else {
                &self.service
            };
            format!("session {} ({via})", self.id)
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
    /// by blank lines.
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
                "Active" => s.active = yes,
                "Remote" => s.remote = yes,
                "Seat" => s.seat = v.to_string(),
                "Display" => s.display = v.to_string(),
                "Leader" => s.leader = v.parse().unwrap_or(0),
                "IdleHint" => s.idle_hint = yes,
                "IdleSinceHint" => s.idle_since_us = v.parse().unwrap_or(0),
                "LockedHint" => s.locked = yes,
                _ => {}
            }
        }
        out.retain(|s| !s.id.is_empty());
        out
    }

    /// The people logged in: their active sessions (a session switched away from on a seat is not in front of
    /// anyone; a session with no seat, such as ssh, is always active).
    pub fn people(sessions: &[Session]) -> impl Iterator<Item = &Session> {
        sessions.iter().filter(|s| s.is_person() && s.active)
    }

    /// The machine's presence: the least idle of the people's sessions, infinite with nobody logged in. A
    /// session whose idle time logind cannot tell makes the whole reading unknown (counted as present).
    pub fn presence(sessions: &[Session], now_us: u64) -> PresenceReading {
        let mut idle = f64::INFINITY;
        let mut unknown = vec![];
        let mut any = false;
        for s in people(sessions) {
            any = true;
            match s.idle_s(now_us) {
                Some(x) => idle = idle.min(x),
                None => unknown.push(s.label()),
            }
        }
        if !any {
            return PresenceReading::new(Some(f64::INFINITY), "logind: nobody logged in");
        }
        if !unknown.is_empty() {
            return PresenceReading::new(
                None,
                format!(
                    "unknown: logind has no idle time for {}",
                    unknown.join(", ")
                ),
            );
        }
        PresenceReading::new(Some(idle), "logind")
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

    /// What `loginctl show-session 1 2 5 7 -p …` prints on Ubuntu 26.04 (systemd 259): a service account's user
    /// manager, a person's user manager, an ssh session without a terminal, and a GNOME session on seat0.
    const SHOW: &str = "Id=1\nUser=999\nName=oarbank\nSeat=\nTTY=\nDisplay=\nRemote=no\nType=unspecified\n\
        Class=manager-early\nActive=yes\nState=active\nIdleHint=no\nIdleSinceHint=0\nLockedHint=no\n\n\
        Id=2\nUser=501\nName=tnt\nSeat=\nTTY=\nDisplay=\nRemote=no\nType=unspecified\nClass=manager-early\n\
        Active=yes\nState=active\nIdleHint=no\nIdleSinceHint=0\nLockedHint=no\n\n\
        Id=5\nUser=501\nName=tnt\nService=sshd\nSeat=\nTTY=\nDisplay=\nRemote=no\nType=tty\nClass=user\n\
        Active=yes\nState=active\nIdleHint=no\nIdleSinceHint=0\nLockedHint=no\n\n\
        Id=7\nUser=1000\nName=ada\nService=gdm-password\nLeader=1690\nSeat=seat0\nTTY=tty2\nDisplay=:0\nRemote=no\nType=x11\n\
        Class=user\nActive=yes\nState=active\nIdleHint=yes\nIdleSinceHint=1790000000000000\nLockedHint=yes\n";

    #[test]
    fn parses_sessions_and_session_ids() {
        assert_eq!(
            parse_list("1 999 oarbank - 1534 manager-early - no -\n5 501 tnt     - 2171 user          - no -\n"),
            ["1", "5"]
        );
        let s = parse_show(SHOW);
        assert_eq!(s.len(), 4);
        assert_eq!(
            (
                s[2].id.as_str(),
                s[2].uid,
                s[2].kind.as_str(),
                s[2].service.as_str()
            ),
            ("5", 501, "tty", "sshd")
        );
        let g = &s[3];
        assert!(g.graphical() && g.is_person() && g.idle_hint && g.locked && g.active);
        assert_eq!(
            (
                g.seat.as_str(),
                g.display.as_str(),
                g.leader,
                g.idle_since_us
            ),
            ("seat0", ":0", 1690, 1_790_000_000_000_000)
        );
        assert!(!s[0].is_person() && !s[1].is_person());
    }

    #[test]
    fn idle_time_per_session_kind() {
        let now = 1_790_000_100_000_000;
        let s = parse_show(SHOW);
        // the desktop says idle since 100 s ago
        assert_eq!(s[3].idle_s(now), Some(100.0));
        // a desktop that says active is present, whenever its hint last changed
        let active = Session {
            idle_hint: false,
            ..s[3].clone()
        };
        assert_eq!(active.idle_s(now), Some(0.0));
        // a terminal's last access time counts whether or not logind calls it idle yet
        let tty = Session {
            idle_since_us: now - 30_000_000,
            ..s[2].clone()
        };
        assert_eq!(tty.idle_s(now), Some(30.0));
        // no terminal and no desktop: logind cannot tell
        assert_eq!(s[2].idle_s(now), None);
    }

    #[test]
    fn presence_is_the_least_idle_person_and_unknown_counts_as_present() {
        let now = 1_790_000_100_000_000;
        let s = parse_show(SHOW);
        // the ssh session has no idle time: unknown, which capacity treats as someone present
        let r = presence(&s, now);
        assert_eq!(r.idle_s, None);
        assert_eq!(r.effective_idle_s(), 0.0);
        assert!(r.source.contains("session 5 (sshd)"), "{}", r.source);
        // without it, the GNOME session decides
        let r = presence(&[s[0].clone(), s[3].clone()], now);
        assert_eq!((r.idle_s, r.source.as_str()), (Some(100.0), "logind"));
        // a typing ssh user is the least idle
        let typing = Session {
            idle_since_us: now - 2_000_000,
            ..s[2].clone()
        };
        assert_eq!(presence(&[typing, s[3].clone()], now).idle_s, Some(2.0));
        // only user managers (a service account's lingering manager): nobody is logged in
        let r = presence(&s[..2], now);
        assert_eq!(r.idle_s, Some(f64::INFINITY));
        // a session switched away from on the seat is in front of nobody
        let away = Session {
            active: false,
            ..s[3].clone()
        };
        assert_eq!(
            presence(std::slice::from_ref(&away), now).idle_s,
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
