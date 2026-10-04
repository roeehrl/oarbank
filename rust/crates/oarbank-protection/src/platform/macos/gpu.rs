//! Per-process accumulated GPU time from the AGX driver's user clients (undocumented; feature-detected, may
//! disappear in a macOS update, and then protection degrades to "unknown": no growth, guards intact). The
//! user clients are not registered services, so service matching never returns them (0 on macOS 26.5 and
//! 27.0); they are found by walking the service plane.

use std::collections::HashMap;
use std::ffi::CStr;

use super::cf;
use super::iokit::{
    property, IOIteratorNext, IOObjectConformsTo, IORegistryCreateIterator, IoObject, Object,
};

const SERVICE_PLANE: &CStr = c"IOService";
const USER_CLIENT_CLASS: &CStr = c"AGXDeviceUserClient";
/// kIORegistryIterateRecursively
const ITERATE_RECURSIVELY: u32 = 1;

/// "pid 1234, WindowServer" -> 1234.
pub fn creator_pid(creator: &str) -> Option<i32> {
    creator
        .split(',')
        .next()?
        .split(' ')
        .next_back()?
        .parse()
        .ok()
}

/// pid -> accumulated GPU nanoseconds, or None if the source is unavailable.
pub fn gpu_time_by_pid() -> Option<HashMap<i32, f64>> {
    let mut it: IoObject = 0;
    // SAFETY: 0 is the default main port; `it` receives an iterator we release below.
    if unsafe { IORegistryCreateIterator(0, SERVICE_PLANE.as_ptr(), ITERATE_RECURSIVELY, &mut it) }
        != 0
    {
        return None;
    }
    let it = Object(it);
    let mut out: HashMap<i32, f64> = HashMap::new();
    let mut seen = false;
    loop {
        // SAFETY: `it` is a valid iterator; each returned object is released by its guard.
        let svc = unsafe { IOIteratorNext(it.0) };
        if svc == 0 {
            break;
        }
        let svc = Object(svc);
        // SAFETY: svc is a live registry entry.
        if unsafe { IOObjectConformsTo(svc.0, USER_CLIENT_CLASS.as_ptr()) } == 0 {
            continue;
        }
        seen = true;
        let Some(pid) = property(svc.0, "IOUserClientCreator")
            .and_then(|c| cf::to_string(c.get()))
            .and_then(|s| creator_pid(&s))
        else {
            continue;
        };
        let Some(usage) = property(svc.0, "AppUsage") else {
            continue;
        };
        let t: f64 = cf::array_items(usage.get())
            .into_iter()
            .filter_map(|d| cf::to_f64(cf::dict_get_str(d, "accumulatedGPUTime")))
            .sum();
        *out.entry(pid).or_insert(0.0) += t;
    }
    seen.then_some(out)
}
