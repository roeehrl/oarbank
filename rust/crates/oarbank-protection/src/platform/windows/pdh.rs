//! Raw performance counters through PDH, for wildcard counter paths: each collection lists the instances that
//! exist then (a process that started using the GPU since the last one appears).

use std::ptr;

use windows_sys::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetRawCounterArrayW,
    PdhOpenQueryW, PDH_CSTATUS_NEW_DATA, PDH_CSTATUS_NO_INSTANCE, PDH_CSTATUS_VALID_DATA,
    PDH_HCOUNTER, PDH_HQUERY, PDH_MORE_DATA, PDH_NO_DATA, PDH_RAW_COUNTER_ITEM_W,
};

/// Every GPU engine's running time per process, adapter and engine. "Utilization Percentage" is a
/// Timer100Ns counter: its raw value is the engine's accumulated running time in 100 ns units (the same
/// number as "Running Time", whose unit is undocumented).
pub const GPU_ENGINE_RUNNING_TIME: &str = r"\GPU Engine(*)\Utilization Percentage";

/// One open query over one counter path.
pub struct RawCounter {
    query: PDH_HQUERY,
    counter: PDH_HCOUNTER,
}

// SAFETY: PDH query and counter handles are not tied to the thread that opened them; RawCounter is used from
// one thread at a time (&mut self).
unsafe impl Send for RawCounter {}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// The UTF-16 string at `p` (NUL-terminated).
///
/// # Safety
/// `p` is null or points at a NUL-terminated UTF-16 string.
unsafe fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

impl RawCounter {
    /// Open a query over an English counter path; None when the counter set does not exist (no WDDM 2 driver).
    pub fn open(path: &str) -> Option<Self> {
        let mut query: PDH_HQUERY = ptr::null_mut();
        // SAFETY: a null data source is the live system; `query` receives a handle closed on drop.
        if unsafe { PdhOpenQueryW(ptr::null(), 0, &mut query) } != 0 {
            return None;
        }
        let mut c = RawCounter {
            query,
            counter: ptr::null_mut(),
        };
        let p = wide(path);
        // SAFETY: a live query and a NUL-terminated path.
        if unsafe { PdhAddEnglishCounterW(c.query, p.as_ptr(), 0, &mut c.counter) } != 0 {
            return None;
        }
        Some(c)
    }

    /// Collect now: every instance's raw first value. None when the collection fails; no instances is an
    /// empty list.
    pub fn collect(&mut self) -> Option<Vec<(String, i64)>> {
        // SAFETY: a live query.
        match unsafe { PdhCollectQueryData(self.query) } {
            0 => {}
            PDH_NO_DATA => return Some(vec![]),
            _ => return None,
        }
        let (mut size, mut count) = (0u32, 0u32);
        // SAFETY: a size query (null buffer of size 0).
        let st =
            unsafe { PdhGetRawCounterArrayW(self.counter, &mut size, &mut count, ptr::null_mut()) };
        match st {
            PDH_MORE_DATA => {}
            0 | PDH_CSTATUS_NO_INSTANCE | PDH_NO_DATA => return Some(vec![]),
            _ => return None,
        }
        // u64 storage keeps the items aligned; the instance names live in the same buffer after them
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let items = buf.as_mut_ptr().cast::<PDH_RAW_COUNTER_ITEM_W>();
        // SAFETY: `buf` holds `size` bytes, as PDH asked for.
        if unsafe { PdhGetRawCounterArrayW(self.counter, &mut size, &mut count, items) } != 0 {
            return None;
        }
        // SAFETY: PDH wrote `count` items at the start of `buf`.
        let items = unsafe { std::slice::from_raw_parts(items, count as usize) };
        Some(
            items
                .iter()
                .filter(|i| {
                    matches!(
                        i.RawValue.CStatus,
                        PDH_CSTATUS_VALID_DATA | PDH_CSTATUS_NEW_DATA
                    )
                })
                // SAFETY: szName points at a NUL-terminated name inside `buf`.
                .map(|i| (unsafe { from_wide(i.szName) }, i.RawValue.FirstValue))
                .collect(),
        )
    }
}

impl Drop for RawCounter {
    fn drop(&mut self) {
        // SAFETY: we own the query; closing it frees its counters.
        unsafe { PdhCloseQuery(self.query) };
    }
}
