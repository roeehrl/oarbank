//! Per-process GPU time: the DRM fdinfo and PDH parsers on real-shaped samples, cycle counters becoming
//! nanoseconds, and the busy fractions between two readings.

use std::collections::{HashMap, HashSet};

use oarbank_protection::gpu::{drm, pdh};
use oarbank_protection::{GpuBusy, GpuTimes};

/// amdgpu on a Radeon RX 7900 (kernel 6.8): memory regions, a PASID and nanoseconds per engine ring.
const AMDGPU: &str = "pos:\t0\nflags:\t02100002\nmnt_id:\t26\nino:\t1123\ndrm-driver:\tamdgpu\n\
drm-client-id:\t14\ndrm-pdev:\t0000:03:00.0\npasid:\t32770\ndrm-memory-vram:\t65536 KiB\n\
drm-memory-gtt: \t2048 KiB\ndrm-memory-cpu: \t0 KiB\namd-memory-visible-vram:\t0 KiB\n\
drm-engine-gfx:\t1203400000 ns\ndrm-engine-compute:\t5000000 ns\ndrm-engine-dma:\t0 ns\ndrm-engine-dec:\t0 ns\n\
drm-engine-enc:\t0 ns\ndrm-engine-enc_1:\t0 ns\ndrm-engine-jpeg:\t0 ns\n";

/// i915 (Tiger Lake): two video engines, so a capacity line that is a count, not a time.
const I915: &str = "pos:\t0\nflags:\t02100002\nmnt_id:\t24\nino:\t685\ndrm-driver:\ti915\ndrm-client-id:\t7\n\
drm-pdev:\t0000:00:02.0\ndrm-total-system0:\t2048 KiB\ndrm-shared-system0:\t0\ndrm-active-system0:\t0\n\
drm-resident-system0:\t2048 KiB\ndrm-purgeable-system0:\t0\ndrm-engine-render:\t25662044495 ns\n\
drm-engine-copy:\t0 ns\ndrm-engine-video:\t0 ns\ndrm-engine-capacity-video:\t2\ndrm-engine-video-enhance:\t0 ns\n";

/// xe (Lunar Lake): busy and total GPU clock cycles per engine class, no nanoseconds; memory regions whose
/// keys also start with drm-total-.
fn xe(rcs: u64, total: u64) -> String {
    format!(
        "pos:\t0\nflags:\t02100002\nmnt_id:\t26\nino:\t1201\ndrm-driver:\txe\ndrm-client-id:\t21\n\
         drm-pdev:\t0000:00:02.0\ndrm-total-system:\t4096 KiB\ndrm-shared-system:\t0\ndrm-active-system:\t0\n\
         drm-resident-system:\t4096 KiB\ndrm-total-gtt:\t0\ndrm-cycles-rcs:\t{rcs}\ndrm-total-cycles-rcs:\t{total}\n\
         drm-cycles-bcs:\t0\ndrm-total-cycles-bcs:\t{total}\ndrm-cycles-vcs:\t0\ndrm-engine-capacity-vcs:\t2\n\
         drm-total-cycles-vcs:\t{total}\ndrm-cycles-vecs:\t0\ndrm-total-cycles-vecs:\t{total}\n\
         drm-cycles-ccs:\t0\ndrm-total-cycles-ccs:\t{total}\n"
    )
}

/// msm (Adreno 690): nanoseconds and cycles for the one engine, no total cycles.
const MSM: &str =
    "pos:\t0\nflags:\t02100002\nmnt_id:\t23\nino:\t518\ndrm-driver:\tmsm\ndrm-client-id:\t3\n\
drm-engine-gpu:\t4093522000 ns\ndrm-cycles-gpu:\t2421009173\ndrm-maxfreq-gpu:\t710000000 Hz\n\
drm-resident-memory:\t32 MiB\n";

/// panfrost (Mali-G52): two job slots, with cycles and clock frequencies beside the nanoseconds.
const PANFROST: &str = "pos:\t0\nflags:\t02100002\nmnt_id:\t22\nino:\t401\ndrm-driver:\tpanfrost\n\
drm-client-id:\t9\ndrm-engine-fragment:\t1000 ns\ndrm-cycles-fragment:\t800\ndrm-maxfreq-fragment:\t800000000 Hz\n\
drm-curfreq-fragment:\t800000000 Hz\ndrm-engine-vertex-tiler:\t500 ns\ndrm-cycles-vertex-tiler:\t400\n\
drm-maxfreq-vertex-tiler:\t800000000 Hz\ndrm-curfreq-vertex-tiler:\t800000000 Hz\n";

/// An ordinary file's fdinfo, and a DRM file on a driver without usage stats.
const REGULAR: &str = "pos:\t4096\nflags:\t0100000\nmnt_id:\t28\nino:\t3141\n";
const NO_STATS: &str =
    "pos:\t0\nflags:\t02100002\nmnt_id:\t26\nino:\t77\ndrm-driver:\tvirtio_gpu\ndrm-client-id:\t2\n";

#[test]
fn fdinfo_parses_every_drivers_engine_counters() {
    let a = drm::parse(AMDGPU).unwrap();
    assert_eq!(
        (a.pdev.as_str(), a.client_id.as_str()),
        ("0000:03:00.0", "14")
    );
    assert_eq!(a.engine_ns["gfx"], 1_203_400_000);
    assert_eq!(a.engine_ns["compute"], 5_000_000);
    assert_eq!(a.engine_ns.len(), 7);
    assert!(a.cycles.is_empty());

    let i = drm::parse(I915).unwrap();
    assert_eq!(i.engine_ns["render"], 25_662_044_495);
    assert_eq!(
        i.engine_ns.keys().collect::<Vec<_>>(),
        ["copy", "render", "video", "video-enhance"]
    );

    let x = drm::parse(&xe(28_257_900, 7_655_183_225)).unwrap();
    assert!(x.engine_ns.is_empty());
    assert_eq!(x.cycles["rcs"], (28_257_900, 7_655_183_225));
    assert_eq!(x.cycles.len(), 5);

    // the nanoseconds count; cycles without a total are ignored
    let m = drm::parse(MSM).unwrap();
    assert_eq!(m.engine_ns, [("gpu".to_string(), 4_093_522_000)].into());
    assert!(m.cycles.is_empty());
    let p = drm::parse(PANFROST).unwrap();
    assert_eq!(
        p.engine_ns,
        [
            ("fragment".to_string(), 1000),
            ("vertex-tiler".to_string(), 500)
        ]
        .into()
    );
    assert!(p.cycles.is_empty());
    assert!(p.has_counters());

    assert_eq!(drm::parse(REGULAR), None);
    let v = drm::parse(NO_STATS).unwrap();
    assert!(!v.has_counters());
}

fn holds(clients: &[&str]) -> drm::ProcessGpu {
    drm::ProcessGpu {
        clients: clients.iter().map(|t| drm::parse(t).unwrap()).collect(),
        unknown: false,
    }
}

#[test]
fn usage_sums_a_processs_distinct_clients() {
    let mut u = drm::Usage::new();
    let t = u.fold(
        vec![
            // the same client on two descriptors (dup) counts once; a second device adds its own
            (100, holds(&[AMDGPU, AMDGPU, I915])),
            (
                200,
                drm::ProcessGpu {
                    clients: vec![],
                    unknown: true,
                },
            ),
            (300, holds(&[])),
        ],
        None,
    );
    let amd: f64 = 1_203_400_000.0 + 5_000_000.0;
    assert_eq!(t.ns[&100], amd + 25_662_044_495.0);
    assert_eq!(t.unknown, HashSet::from([200]));
    assert!(!t.ns.contains_key(&300)); // no GPU client: zero, and known
}

#[test]
fn xe_cycles_become_nanoseconds_between_readings() {
    let mut u = drm::Usage::new();
    // the first reading has no baseline
    let t = u.fold(vec![(42, holds(&[&xe(1_000, 10_000)]))], None);
    assert_eq!(t.ns[&42], 0.0);
    // 2 s later: busy 3,000 of 12,000 elapsed cycles is a quarter of the time, 0.5 s
    let t = u.fold(vec![(42, holds(&[&xe(4_000, 22_000)]))], Some(2.0));
    assert!((t.ns[&42] - 0.5e9).abs() < 1.0);
    // idle for 1 s: the accumulated time stays
    let t = u.fold(vec![(42, holds(&[&xe(4_000, 28_000)]))], Some(1.0));
    assert!((t.ns[&42] - 0.5e9).abs() < 1.0);
    // a closed client is forgotten: a new one with the same id starts from nothing
    u.fold(vec![(42, holds(&[]))], Some(1.0));
    let t = u.fold(vec![(42, holds(&[&xe(9_000, 40_000)]))], Some(1.0));
    assert_eq!(t.ns[&42], 0.0);
}

/// Instance names as the Windows 11 test VM lists them (`Get-Counter "\GPU Engine(*)\Running Time"`).
#[test]
fn pdh_instances_sum_per_process() {
    assert_eq!(
        pdh::instance_pid("pid_1212_luid_0x00000000_0x00005c30_phys_0_eng_0_engtype_3d"),
        Some(1212)
    );
    assert_eq!(
        pdh::instance_pid("pid_4752_luid_0x00000000_0x0000C9A5_phys_0_eng_4_engtype_VideoDecode"),
        Some(4752)
    );
    assert_eq!(pdh::instance_pid("_Total"), None);
    assert_eq!(pdh::instance_pid("pid_x_luid"), None);
    let t = pdh::by_pid([
        (
            "pid_1212_luid_0x00000000_0x00005c30_phys_0_eng_0_engtype_3d",
            30_705_727,
        ),
        (
            "pid_1212_luid_0x00000000_0x00005c30_phys_0_eng_1_engtype_3d",
            0,
        ),
        (
            "pid_4752_luid_0x00000000_0x00005c30_phys_0_eng_3_engtype_3d",
            7_166,
        ),
        (
            "pid_4752_luid_0x00000000_0x00005c30_phys_0_eng_4_engtype_3d",
            80_883,
        ),
        (
            "pid_4752_luid_0x00000000_0x0000d1e2_phys_0_eng_0_engtype_Copy",
            1,
        ),
        ("garbage", 5),
    ]);
    // 100 ns units, summed over engines and adapters
    assert_eq!(
        t.ns,
        HashMap::from([(1212, 3_070_572_700.0), (4752, 8_805_000.0)])
    );
    assert!(t.unknown.is_empty());
}

#[test]
fn busy_fractions_between_two_readings() {
    let prev = GpuTimes {
        ns: HashMap::from([(1, 1e9), (2, 5e9), (3, 0.0), (6, 2e9)]),
        unknown: HashSet::from([4]),
    };
    let cur = GpuTimes {
        // 1 gained 1 s, 2 restarted its client (never negative), 4 was unknown, 5 is new, 6 closed its GPU
        ns: HashMap::from([(1, 2e9), (2, 1e9), (3, 0.0), (4, 9e9), (5, 0.4e9)]),
        unknown: HashSet::from([7]),
    };
    let b = GpuBusy::between(&prev, &cur, 2.0).unwrap();
    assert_eq!(
        b.by_pid,
        HashMap::from([(1, 0.5), (2, 0.0), (3, 0.0), (5, 0.2)])
    );
    assert_eq!(b.unknown, HashSet::from([4, 7]));
    assert!((b.group([1, 5, 6]).unwrap() - 0.7).abs() < 1e-12); // 6 holds no GPU now: zero
    assert_eq!(b.group([1, 4]), None);
    assert_eq!(b.group([]), Some(0.0));
    assert!((b.total() - 0.7).abs() < 1e-12);
    assert_eq!(GpuBusy::between(&prev, &cur, 0.0), None);
}
