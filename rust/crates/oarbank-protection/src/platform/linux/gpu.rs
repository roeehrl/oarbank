//! Per-process GPU time from DRM `fdinfo` (Documentation/gpu/drm-usage-stats.rst): every DRM file a process
//! holds open reports its client's busy time per engine. NVIDIA's proprietary driver writes no such counters: its
//! processes' use comes from NVML (`libnvidia-ml.so.1`, opened at run time, so the agent links nothing of it). A
//! process holding a GPU that reports neither (a kernel before 5.19, a driver without usage stats, AMD's compute
//! interface, NVIDIA without NVML) or whose open files cannot be read (another user's, without root) is unknown.

use std::ffi::{c_void, CStr};
use std::fs;
use std::io::ErrorKind;
use std::sync::OnceLock;

use crate::gpu::drm::{self, ProcessGpu};
use crate::gpu::{nvml, GpuTimes, LinuxGpu};

/// An NVIDIA GPU's device file (`/dev/nvidia<N>`; not nvidiactl, nvidia-uvm or nvidia-modeset, which every CUDA
/// process also opens).
fn nvidia_gpu(name: &str) -> bool {
    name.strip_prefix("/dev/nvidia")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// NVML's entry points from the driver's library, initialized once for the process's life; None without the
/// NVIDIA driver (or one older than the `_v2` running-process calls, 2021).
pub fn nvml() -> Option<nvml::Api> {
    static API: OnceLock<Option<nvml::Api>> = OnceLock::new();
    *API.get_or_init(|| {
        // SAFETY: a NUL-terminated library name; the handle is kept open for the process's life.
        let lib = unsafe {
            libc::dlopen(
                c"libnvidia-ml.so.1".as_ptr(),
                libc::RTLD_NOW | libc::RTLD_LOCAL,
            )
        };
        if lib.is_null() {
            return None;
        }
        let sym = |names: &[&CStr]| -> Option<*mut c_void> {
            names.iter().find_map(|n| {
                // SAFETY: a live handle and a NUL-terminated symbol name.
                let p = unsafe { libc::dlsym(lib, n.as_ptr()) };
                (!p.is_null()).then_some(p)
            })
        };
        // SAFETY: each symbol is NVML's function of that name, whose C signature is the field's type.
        let api = unsafe {
            nvml::Api {
                device_get_count: as_fn(sym(&[c"nvmlDeviceGetCount_v2"])?),
                device_get_handle_by_index: as_fn(sym(&[c"nvmlDeviceGetHandleByIndex_v2"])?),
                device_get_compute_running_processes: as_fn(sym(&[
                    c"nvmlDeviceGetComputeRunningProcesses_v3",
                    c"nvmlDeviceGetComputeRunningProcesses_v2",
                ])?),
                device_get_graphics_running_processes: as_fn(sym(&[
                    c"nvmlDeviceGetGraphicsRunningProcesses_v3",
                    c"nvmlDeviceGetGraphicsRunningProcesses_v2",
                ])?),
                device_get_process_utilization: as_fn(sym(&[c"nvmlDeviceGetProcessUtilization"])?),
            }
        };
        // SAFETY: nvmlInit_v2 takes nothing and returns nvmlReturn_t.
        let init: unsafe extern "C" fn() -> nvml::Return =
            unsafe { as_fn(sym(&[c"nvmlInit_v2"])?) };
        (unsafe { init() } == nvml::SUCCESS).then_some(api)
    })
}

/// A library symbol as a function pointer of type `F`.
///
/// # Safety
/// The symbol must be a function whose C signature `F` is.
unsafe fn as_fn<F: Copy>(p: *mut c_void) -> F {
    debug_assert_eq!(std::mem::size_of::<F>(), std::mem::size_of::<*mut c_void>());
    std::mem::transmute_copy(&p)
}

/// This machine's GPU time readers: DRM `fdinfo`, and NVML where the NVIDIA driver is installed.
pub fn reader() -> LinuxGpu {
    LinuxGpu::new(nvml())
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
        let name = target.to_str().unwrap_or_default();
        if target.starts_with("/dev/dri") {
            let info = fs::read_to_string(format!(
                "/proc/{pid}/fdinfo/{}",
                fd.file_name().to_string_lossy()
            ));
            match info.ok().as_deref().and_then(drm::parse) {
                Some(c) if c.has_counters() => p.clients.push(c),
                _ => p.unknown = true,
            }
        } else if nvidia_gpu(name) {
            p.nvidia = true;
        } else if name == "/dev/kfd" {
            // AMD's compute interface: ROCm queues bypass the DRM scheduler, so no fdinfo counts them
            p.unknown = true;
        }
    }
    Some(p)
}

/// Every process's GPU time (None when /proc cannot be listed); `seconds` since the previous reading.
pub fn gpu_times(gpu: &mut LinuxGpu, seconds: Option<f64>) -> Option<GpuTimes> {
    let procs = fs::read_dir("/proc")
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter_map(|pid| Some((pid, process_gpu(pid)?)))
        .collect();
    Some(gpu.fold(procs, seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn nvidia_gpu_device_files() {
        for (path, want) in [
            ("/dev/nvidia0", true),
            ("/dev/nvidia12", true),
            ("/dev/kfd", false),
            ("/dev/nvidiactl", false),
            ("/dev/nvidia-uvm", false),
            ("/dev/nvidia-modeset", false),
            ("/dev/nvidia", false),
            ("/dev/null", false),
        ] {
            assert_eq!(nvidia_gpu(path), want, "{path}");
        }
    }

    /// The VMs and CI runners have no NVIDIA driver: NVML does not load, and nothing else changes.
    #[test]
    fn without_the_nvidia_driver_nvml_does_not_load() {
        if !Path::new("/proc/driver/nvidia").exists() {
            assert!(nvml().is_none());
        }
    }
}
