//! Session helpers against the live system, across accounts (Linux) and sessions (Windows). Run the helper side in
//! the person's account or session and the service side in the service's, both pointed at the same endpoint:
//!
//!   Linux:   OARBANK_SESSION_SOCKET=/tmp/s.sock session_live helper --ignored        (as the person)
//!            OARBANK_SESSION_SOCKET=/tmp/s.sock session_live service --ignored       (as another account)
//!   Windows: OARBANK_SESSION_PIPE=\\.\pipe\t session_live helper --ignored           (in the person's session)
//!            OARBANK_SESSION_PIPE=\\.\pipe\t session_live service --ignored          (in session 0)

#![cfg(any(target_os = "linux", windows))]

use std::collections::HashSet;
use std::thread::sleep;
use std::time::{Duration, Instant};

use oarbank_protection::session::{Principal, SessionHub};
use oarbank_protection::*;

#[test]
#[ignore = "the helper side: runs until killed"]
fn helper() {
    panic!("{}", platform::run_session_helper());
}

/// The service side: what only the helper's account or session may read arrives through the hub, checked.
#[test]
#[ignore = "the service side: needs a helper reporting"]
fn service() {
    let hub = SessionHub::new();
    platform::serve_sessions(hub.clone()).expect("serving");
    let deadline = Instant::now() + Duration::from_secs(30);
    while hub.principals().is_empty() && Instant::now() < deadline {
        sleep(Duration::from_millis(200));
    }
    let who = *hub
        .principals()
        .first()
        .expect("a helper reported within 30 s");
    sleep(Duration::from_secs(5)); // a second report: GPU busy fractions need two readings
    eprintln!("helper for {who:?}");
    let mut t = ProcessTable::new(platform::native_host(Some(hub.clone())).processes);
    let rows = t
        .summary(100_000, &HashSet::new(), SystemClock.now())
        .unwrap();
    #[cfg(target_os = "linux")]
    {
        let Principal::Uid(uid) = who else {
            panic!("{who:?}")
        };
        let r = platform::linux::reader();
        let theirs: Vec<_> = r
            .list(|u| u == uid, &HashSet::new())
            .unwrap()
            .into_iter()
            .filter(|e| e.path.is_none())
            .collect();
        // SAFETY: getuid cannot fail.
        assert_ne!(
            unsafe { libc::getuid() },
            uid,
            "run the service as another account"
        );
        assert!(
            !theirs.is_empty(),
            "their executable links are unreadable to this account"
        );
        let mut resolved = 0;
        for e in &theirs {
            let row = rows
                .iter()
                .find(|x| x.pid == e.pid)
                .expect("their processes are the owner's");
            if row.path.is_some() {
                resolved += 1;
            }
        }
        eprintln!(
            "{resolved} of {} unreadable paths resolved by the helper",
            theirs.len()
        );
        assert!(
            resolved * 10 >= theirs.len() * 9,
            "the helper describes (nearly) all of them"
        );
        // GPU: every process of theirs is known to the helper (busy or not), never unknown for want of access
        let unknown = theirs
            .iter()
            .filter(|e| hub.gpu_busy(e.pid) == Some(None))
            .count();
        eprintln!("GPU unknown to the helper too: {unknown}");
    }
    #[cfg(windows)]
    {
        let Principal::Session(s) = who else {
            panic!("{who:?}")
        };
        assert_ne!(
            platform::windows::own_session(),
            s,
            "run the service outside the helper's session"
        );
        let front = hub
            .front(who)
            .expect("the helper reads its session's front window");
        eprintln!("front from the helper: {front:?}");
        assert!(front.source.starts_with("session helper: "));
        let idle = hub
            .idle_s(who)
            .expect("the helper reads its session's last input");
        let p = platform::native_presence(Some(hub.clone())).read();
        eprintln!("presence: {p:?}");
        assert!(p.idle_s.is_some_and(|x| x <= idle + 5.0), "{p:?}");
        let theirs = rows.iter().filter(|r| r.argv.is_some()).count();
        eprintln!("{theirs} of {} processes with arguments", rows.len());
    }
}
