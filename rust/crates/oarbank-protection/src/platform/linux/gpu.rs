//! Per-process GPU time from DRM `fdinfo` (Documentation/gpu/drm-usage-stats.rst): every DRM file a process
//! holds open reports its client's busy time per engine. A process holding a GPU that reports no such
//! counters (a kernel before 5.19, a driver without usage stats, NVIDIA's proprietary device files, AMD's
//! compute interface) or whose open files cannot be read (another user's, without root) is unknown.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use crate::gpu::drm::{self, ProcessGpu};
use crate::gpu::GpuTimes;

/// A GPU device file whose per-client usage no `fdinfo` reports: NVIDIA's proprietary driver
/// (`/dev/nvidia<N>`; not nvidiactl, nvidia-uvm or nvidia-modeset, which every CUDA process also opens) and
/// AMD's compute interface (`/dev/kfd`: ROCm queues bypass the DRM scheduler).
fn uncounted_gpu(target: &Path) -> bool {
    let Some(name) = target.to_str() else {
        return false;
    };
    name == "/dev/kfd"
        || name
            .strip_prefix("/dev/nvidia")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The GPU clients one process holds; None when it is gone.
pub fn process_gpu(pid: i32) -> Option<ProcessGpu> {
    let mut p = ProcessGpu::default();
    let fds = match fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(d) => d,
        Err(e) if e.kind() == ErrorKind::NotFound => return None,
        Err(_) => {
            p.unknown = true;
            return Some(p);
        }
    };
    for fd in fds.flatten() {
        let Ok(target) = fs::read_link(fd.path()) else {
            continue;
        };
        if target.starts_with("/dev/dri") {
            let info = fs::read_to_string(format!(
                "/proc/{pid}/fdinfo/{}",
                fd.file_name().to_string_lossy()
            ));
            match info.ok().as_deref().and_then(drm::parse) {
                Some(c) if c.has_counters() => p.clients.push(c),
                _ => p.unknown = true,
            }
        } else if uncounted_gpu(&target) {
            p.unknown = true;
        }
    }
    Some(p)
}

/// Every process's GPU time (None when /proc cannot be listed); `seconds` since the previous reading.
pub fn gpu_times(usage: &mut drm::Usage, seconds: Option<f64>) -> Option<GpuTimes> {
    let procs = fs::read_dir("/proc")
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter_map(|pid| Some((pid, process_gpu(pid)?)))
        .collect();
    Some(usage.fold(procs, seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncounted_gpu_device_files() {
        for (path, want) in [
            ("/dev/nvidia0", true),
            ("/dev/nvidia12", true),
            ("/dev/kfd", true),
            ("/dev/nvidiactl", false),
            ("/dev/nvidia-uvm", false),
            ("/dev/nvidia-modeset", false),
            ("/dev/nvidia", false),
            ("/dev/null", false),
        ] {
            assert_eq!(uncounted_gpu(Path::new(path)), want, "{path}");
        }
    }
}
