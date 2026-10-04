//! Per-process GPU time: what a platform [`Meter`](crate::Meter) reports, the busy fractions the `gpu_active`
//! trigger and the `gpu_share` metric read, and the parsers for the Linux and Windows sources. The parsers are
//! platform-neutral so that every OS tests them; the platform backends only do the reading.
//!
//! | OS | Source | Unit |
//! |---|---|---|
//! | macOS | the AGX user clients' `accumulatedGPUTime` (IORegistry) | ns |
//! | Linux | `/proc/<pid>/fdinfo/<fd>` of DRM device files: `drm-engine-<engine>`, or `drm-cycles-<engine>` over `drm-total-cycles-<engine>` (xe) | ns, cycles |
//! | Linux, NVIDIA | NVML: the processes holding a context on each GPU and their SM utilization over the driver's last sample period | per cent |
//! | Windows | the raw `\GPU Engine(*)\Utilization Percentage` counters (Timer100Ns: running time) | 100 ns |

use std::collections::{BTreeMap, HashMap, HashSet};

/// One reading of every process's accumulated GPU time.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GpuTimes {
    /// pid -> accumulated GPU busy nanoseconds, summed over the GPU's engines. A process missing here holds no
    /// GPU client.
    pub ns: HashMap<i32, f64>,
    /// Processes that hold a GPU whose usage cannot be read (a driver without per-client counters, or a
    /// process whose open files are not readable).
    pub unknown: HashSet<i32>,
}

impl GpuTimes {
    /// A reading in which every process's usage is known.
    pub fn known(ns: HashMap<i32, f64>) -> Self {
        Self {
            ns,
            unknown: HashSet::new(),
        }
    }
}

/// Each process's GPU busy fraction over one sample interval: GPU busy seconds per second, summed over the
/// GPU's engines (so it can exceed 1 when several engines work for the process at once).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GpuBusy {
    pub by_pid: HashMap<i32, f64>,
    pub unknown: HashSet<i32>,
}

impl GpuBusy {
    /// The busy fractions between two readings `seconds` apart (None unless `seconds` is positive). A process
    /// absent from the earlier reading opened its GPU client since then, so all of its time is new; one that
    /// was unknown then has no baseline and stays unknown.
    pub fn between(prev: &GpuTimes, cur: &GpuTimes, seconds: f64) -> Option<Self> {
        if seconds <= 0.0 {
            return None;
        }
        let mut b = GpuBusy {
            by_pid: HashMap::new(),
            unknown: cur.unknown.clone(),
        };
        for (&pid, &ns) in &cur.ns {
            if cur.unknown.contains(&pid) {
                continue;
            }
            if prev.unknown.contains(&pid) {
                b.unknown.insert(pid);
                continue;
            }
            let base = prev.ns.get(&pid).copied().unwrap_or(0.0);
            b.by_pid.insert(pid, (ns - base).max(0.0) / (seconds * 1e9));
        }
        Some(b)
    }

    /// The group's busy fraction, or None when any of its processes' usage is unknown.
    pub fn group(&self, pids: impl IntoIterator<Item = i32>) -> Option<f64> {
        let mut sum = 0.0;
        for pid in pids {
            if self.unknown.contains(&pid) {
                return None;
            }
            sum += self.by_pid.get(&pid).copied().unwrap_or(0.0);
        }
        Some(sum)
    }

    /// Every known process's busy fraction together.
    pub fn total(&self) -> f64 {
        self.by_pid.values().sum()
    }
}

/// Linux DRM client usage from `fdinfo` (the kernel's drm-usage-stats format, written by amdgpu, i915, xe,
/// msm, panfrost, panthor, v3d, nouveau and others).
pub mod drm {
    use super::*;

    /// One DRM client (an open DRM file description) as its `fdinfo` describes it.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Client {
        pub pdev: String,
        pub client_id: String,
        /// `drm-engine-<engine>: <ns> ns`: busy time per engine.
        pub engine_ns: BTreeMap<String, u64>,
        /// `drm-cycles-<engine>` with `drm-total-cycles-<engine>` (xe): busy and elapsed GPU clock cycles, for
        /// engines without a nanosecond counter.
        pub cycles: BTreeMap<String, (u64, u64)>,
    }

    impl Client {
        /// Does the driver report this client's engine usage?
        pub fn has_counters(&self) -> bool {
            !self.engine_ns.is_empty() || !self.cycles.is_empty()
        }
    }

    fn number(v: &str) -> Option<u64> {
        v.split_whitespace().next()?.parse().ok()
    }

    /// Parse one `fdinfo` file; None when it is not a DRM client's.
    pub fn parse(fdinfo: &str) -> Option<Client> {
        let mut c = Client::default();
        let mut drm = false;
        let mut busy: BTreeMap<&str, u64> = BTreeMap::new();
        let mut total: BTreeMap<&str, u64> = BTreeMap::new();
        for line in fdinfo.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let v = v.trim();
            if k == "drm-driver" {
                drm = true;
            } else if k == "drm-pdev" {
                c.pdev = v.to_string();
            } else if k == "drm-client-id" {
                c.client_id = v.to_string();
            } else if let Some(e) = k.strip_prefix("drm-total-cycles-") {
                total.extend(number(v).map(|n| (e, n)));
            } else if let Some(e) = k.strip_prefix("drm-cycles-") {
                busy.extend(number(v).map(|n| (e, n)));
            } else if let Some(e) = k.strip_prefix("drm-engine-") {
                // drm-engine-capacity-<engine> counts the engines of a class; it is not a time
                if !e.starts_with("capacity-") {
                    c.engine_ns.extend(number(v).map(|n| (e.to_string(), n)));
                }
            }
        }
        // msm and panfrost also write drm-cycles-<engine>, without a total: their nanoseconds count instead
        for (e, b) in busy {
            if let Some(&t) = total.get(e) {
                if !c.engine_ns.contains_key(e) {
                    c.cycles.insert(e.to_string(), (b, t));
                }
            }
        }
        drm.then_some(c)
    }

    /// What one process holds: its DRM clients that report usage, whether it holds an NVIDIA GPU's device file
    /// (whose use only NVML tells), and whether it also holds a GPU whose usage cannot be read.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct ProcessGpu {
        pub clients: Vec<Client>,
        pub nvidia: bool,
        pub unknown: bool,
    }

    /// (pid, pdev, client id): one process's handle on one DRM client.
    type ClientKey = (i32, String, String);

    /// A client's last (busy, total) cycles per engine, and the busy nanoseconds accumulated from them.
    #[derive(Debug, Clone, Default)]
    struct CycleState {
        last: BTreeMap<String, (u64, u64)>,
        busy_ns: f64,
    }

    /// Readings over time. Cycle counters (xe) become nanoseconds only between two readings, so the busy time
    /// they add is accumulated here, per client.
    #[derive(Debug, Clone, Default)]
    pub struct Usage {
        cycles: HashMap<ClientKey, CycleState>,
    }

    impl Usage {
        pub fn new() -> Self {
            Self::default()
        }

        /// One reading of every process; `seconds` since the previous reading (None on the first).
        pub fn fold(&mut self, procs: Vec<(i32, ProcessGpu)>, seconds: Option<f64>) -> GpuTimes {
            let mut out = GpuTimes::default();
            let mut seen = HashSet::new();
            for (pid, p) in procs {
                if p.unknown {
                    out.unknown.insert(pid);
                }
                let mut clients = HashSet::new();
                let mut ns = 0.0;
                for c in p.clients {
                    let key = (pid, c.pdev.clone(), c.client_id.clone());
                    // a client open on several descriptors (dup, fork) is one client
                    if !clients.insert(key.clone()) {
                        continue;
                    }
                    ns += c.engine_ns.values().map(|&n| n as f64).sum::<f64>();
                    if !c.cycles.is_empty() {
                        let st = self.cycles.entry(key.clone()).or_default();
                        for (e, &(b, t)) in &c.cycles {
                            if let (Some(&(b0, t0)), Some(s)) = (st.last.get(e), seconds) {
                                if t > t0 && b >= b0 {
                                    st.busy_ns += (b - b0) as f64 / (t - t0) as f64 * s * 1e9;
                                }
                            }
                        }
                        st.last = c.cycles;
                        ns += st.busy_ns;
                        seen.insert(key);
                    }
                }
                if !clients.is_empty() {
                    out.ns.insert(pid, ns);
                }
            }
            self.cycles.retain(|k, _| seen.contains(k));
            out
        }
    }
}

/// Windows GPU engine counters (PDH `\GPU Engine(*)\...`, one instance per process, adapter and engine).
pub mod pdh {
    use super::*;

    /// "pid_1212_luid_0x00000000_0x00005C30_phys_0_eng_0_engtype_3D" -> 1212.
    pub fn instance_pid(instance: &str) -> Option<i32> {
        instance
            .strip_prefix("pid_")?
            .split('_')
            .next()?
            .parse()
            .ok()
    }

    /// Raw `Utilization Percentage` items (instance, cumulative running time in 100 ns) -> each process's
    /// accumulated GPU time, summed over adapters and engines.
    pub fn by_pid<'a>(items: impl IntoIterator<Item = (&'a str, i64)>) -> GpuTimes {
        let mut ns: HashMap<i32, f64> = HashMap::new();
        for (instance, ticks) in items {
            if let Some(pid) = instance_pid(instance) {
                *ns.entry(pid).or_insert(0.0) += ticks.max(0) as f64 * 100.0;
            }
        }
        GpuTimes::known(ns)
    }
}

/// NVIDIA's proprietary driver writes no per-client `fdinfo` counters; NVML (`libnvidia-ml.so.1`, loaded at run time
/// by the Linux backend) tells instead which processes hold a context on each GPU (its compute and graphics
/// processes) and each one's SM utilization over the driver's last sample period. The entry points are a table, so
/// a test can stand in for the library.
pub mod nvml {
    use super::*;
    use std::ffi::c_void;

    /// `nvmlReturn_t`.
    pub type Return = i32;
    pub const SUCCESS: Return = 0;
    pub const ERROR_NOT_FOUND: Return = 6;
    pub const ERROR_INSUFFICIENT_SIZE: Return = 7;
    /// `nvmlDevice_t`.
    pub type Device = *mut c_void;

    /// `nvmlProcessInfo_t` (the `_v2` and `_v3` running-process calls).
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct ProcessInfo {
        pub pid: u32,
        pub used_gpu_memory: u64,
        pub gpu_instance_id: u32,
        pub compute_instance_id: u32,
    }

    /// `nvmlProcessUtilizationSample_t`.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct UtilizationSample {
        pub pid: u32,
        /// CPU time of the sample, microseconds.
        pub time_stamp: u64,
        /// Per cent of the sample period the SMs worked for the process.
        pub sm_util: u32,
        pub mem_util: u32,
        pub enc_util: u32,
        pub dec_util: u32,
    }

    pub type RunningProcesses = unsafe extern "C" fn(Device, *mut u32, *mut ProcessInfo) -> Return;

    /// The NVML entry points the meter calls.
    #[derive(Clone, Copy)]
    pub struct Api {
        pub device_get_count: unsafe extern "C" fn(*mut u32) -> Return,
        pub device_get_handle_by_index: unsafe extern "C" fn(u32, *mut Device) -> Return,
        pub device_get_compute_running_processes: RunningProcesses,
        pub device_get_graphics_running_processes: RunningProcesses,
        pub device_get_process_utilization:
            unsafe extern "C" fn(Device, *mut UtilizationSample, *mut u32, u64) -> Return,
    }

    /// One reading of every GPU: the processes holding a context, each one's SM busy fraction over the driver's last
    /// sample period (summed over GPUs; a holder without a sample was idle), and the holders of a GPU that keeps no
    /// per-process utilization (before Maxwell), whose use is unknown.
    #[derive(Debug, Clone, Default, PartialEq)]
    pub struct Reading {
        pub holders: HashSet<i32>,
        pub busy: HashMap<i32, f64>,
        pub unknown: HashSet<i32>,
    }

    /// NVML's count-then-fill calls: ask with no buffer, then with one of the size asked for (larger, for what
    /// started in between), again while it is too small. None: the call failed.
    fn fill<T: Default + Clone>(
        mut call: impl FnMut(*mut u32, *mut T) -> Return,
    ) -> Option<Vec<T>> {
        let mut buf: Vec<T> = vec![];
        for _ in 0..4 {
            let mut n = buf.len() as u32;
            let ptr = if buf.is_empty() {
                std::ptr::null_mut()
            } else {
                buf.as_mut_ptr()
            };
            match call(&mut n, ptr) {
                SUCCESS => {
                    buf.truncate(n as usize);
                    return Some(buf);
                }
                ERROR_NOT_FOUND => return Some(vec![]),
                ERROR_INSUFFICIENT_SIZE => buf = vec![T::default(); n as usize + 16],
                _ => return None,
            }
        }
        None
    }

    /// The meter's view of NVML: the library's entry points and, per GPU, the time stamp of the last sample read.
    pub struct Nvml {
        api: Api,
        last_seen: HashMap<u32, u64>,
    }

    impl Nvml {
        pub fn new(api: Api) -> Self {
            Self {
                api,
                last_seen: HashMap::new(),
            }
        }

        /// Read every GPU; None when NVML does not answer (the GPUs cannot be counted, or a GPU's processes cannot
        /// be listed). A GPU with no new samples (every process idle) adds no busy time.
        pub fn read(&mut self) -> Option<Reading> {
            let a = self.api;
            let mut count = 0u32;
            // SAFETY: an out-pointer; every call below passes buffers `fill` sized as NVML asked.
            if unsafe { (a.device_get_count)(&mut count) } != SUCCESS {
                return None;
            }
            let mut r = Reading::default();
            for i in 0..count {
                let mut dev: Device = std::ptr::null_mut();
                if unsafe { (a.device_get_handle_by_index)(i, &mut dev) } != SUCCESS {
                    return None;
                }
                let mut holders = HashSet::new();
                for list in [
                    a.device_get_compute_running_processes,
                    a.device_get_graphics_running_processes,
                ] {
                    let procs = fill(|n, p| unsafe { list(dev, n, p) })?;
                    holders.extend(procs.iter().map(|p| p.pid as i32));
                }
                r.holders.extend(&holders);
                let since = self.last_seen.get(&i).copied().unwrap_or(0);
                let Some(samples) =
                    fill(|n, p| unsafe { (a.device_get_process_utilization)(dev, p, n, since) })
                else {
                    r.unknown.extend(holders);
                    continue;
                };
                // a process may have several samples since the last reading: its mean over them
                let mut per: HashMap<i32, (f64, f64)> = HashMap::new();
                for s in samples.iter().filter(|s| s.time_stamp > since) {
                    let e = per.entry(s.pid as i32).or_default();
                    e.0 += f64::from(s.sm_util.min(100)) / 100.0;
                    e.1 += 1.0;
                }
                for (pid, (sum, n)) in per {
                    *r.busy.entry(pid).or_insert(0.0) += sum / n;
                    r.holders.insert(pid);
                }
                if let Some(t) = samples.iter().map(|s| s.time_stamp).max() {
                    self.last_seen.insert(i, t.max(since));
                }
            }
            Some(r)
        }
    }

    /// Accumulated GPU time from successive readings: each holder's busy fraction over the interval since the
    /// previous reading (None on the first, which adds nothing).
    #[derive(Debug, Clone, Default)]
    pub struct Usage {
        ns: HashMap<i32, f64>,
    }

    impl Usage {
        /// Every holder's accumulated busy nanoseconds.
        pub fn fold(&mut self, r: &Reading, seconds: Option<f64>) -> HashMap<i32, f64> {
            self.ns.retain(|pid, _| r.holders.contains(pid));
            for &pid in &r.holders {
                let ns = self.ns.entry(pid).or_insert(0.0);
                if let Some(s) = seconds {
                    *ns += r.busy.get(&pid).copied().unwrap_or(0.0) * s * 1e9;
                }
            }
            self.ns.clone()
        }
    }
}

/// Linux GPU time: DRM `fdinfo` for the drivers that write usage stats, and NVML for NVIDIA's (when its library
/// loads). Without NVML a process holding an NVIDIA device file is unknown.
pub struct LinuxGpu {
    drm: drm::Usage,
    nvml: Option<(nvml::Nvml, nvml::Usage)>,
}

impl LinuxGpu {
    pub fn new(nvml: Option<nvml::Api>) -> Self {
        Self {
            drm: drm::Usage::new(),
            nvml: nvml.map(|api| (nvml::Nvml::new(api), nvml::Usage::default())),
        }
    }

    /// One reading of every process; `seconds` since the previous reading (None on the first).
    pub fn fold(&mut self, procs: Vec<(i32, drm::ProcessGpu)>, seconds: Option<f64>) -> GpuTimes {
        let nvidia: Vec<i32> = procs
            .iter()
            .filter(|(_, p)| p.nvidia)
            .map(|(pid, _)| *pid)
            .collect();
        let mut t = self.drm.fold(procs, seconds);
        let reading = self.nvml.as_mut().and_then(|(n, u)| {
            let r = n.read()?;
            Some((u.fold(&r, seconds), r.unknown))
        });
        let Some((ns, unknown)) = reading else {
            t.unknown.extend(nvidia);
            return t;
        };
        // a device file held without a context is no GPU work
        for pid in nvidia {
            t.ns.entry(pid).or_insert(0.0);
        }
        for (pid, v) in ns {
            *t.ns.entry(pid).or_insert(0.0) += v;
        }
        t.unknown.extend(unknown);
        t
    }
}
