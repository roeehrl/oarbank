//! Per-process GPU time: what a platform [`Meter`](crate::Meter) reports, the busy fractions the `gpu_active`
//! trigger and the `gpu_share` metric read, and the parsers for the Linux and Windows sources. The parsers are
//! platform-neutral so that every OS tests them; the platform backends only do the reading.
//!
//! | OS | Source | Unit |
//! |---|---|---|
//! | macOS | the AGX user clients' `accumulatedGPUTime` (IORegistry) | ns |
//! | Linux | `/proc/<pid>/fdinfo/<fd>` of DRM device files: `drm-engine-<engine>`, or `drm-cycles-<engine>` over `drm-total-cycles-<engine>` (xe) | ns, cycles |
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

    /// What one process holds: its DRM clients that report usage, and whether it also holds a GPU whose
    /// usage cannot be read.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct ProcessGpu {
        pub clients: Vec<Client>,
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
