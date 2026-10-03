//! The Linux GPU meter against the live /proc: DRM clients from fdinfo, unknown where the files cannot be read.

#![cfg(target_os = "linux")]

use std::thread::sleep;
use std::time::Duration;

use oarbank_protection::platform::linux;
use oarbank_protection::*;

#[test]
#[ignore = "reads every process's open files"]
fn gpu_time_comes_from_drm_fdinfo() {
    let mut meter = linux::NativeMeter::new();
    let a = meter.gpu_times().expect("/proc lists");
    sleep(Duration::from_secs(1));
    let b = meter.gpu_times().unwrap();
    let busy = GpuBusy::between(&a, &b, 1.0).unwrap();
    // this test holds no GPU: known, and zero
    let me = std::process::id() as i32;
    assert_eq!(linux::process_gpu(me), Some(Default::default()));
    assert_eq!(busy.group([me]), Some(0.0));
    // another user's open files cannot be read (without root): unknown, never zero
    // SAFETY: geteuid cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        assert!(b.unknown.contains(&1), "pid 1 belongs to root");
        assert_eq!(busy.group([1]), None);
    }
    let gpus = std::fs::read_dir("/dev/dri")
        .map(|d| d.count())
        .unwrap_or(0);
    eprintln!(
        "/dev/dri entries: {gpus}; GPU clients: {:?}; unknown: {}",
        b.ns,
        b.unknown.len()
    );
}
