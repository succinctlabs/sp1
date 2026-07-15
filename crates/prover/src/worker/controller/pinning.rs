//! Optional CPU pinning for the controller.
//!
//! When `LEAVES_PIN_CORES=1` is set in the environment, the controller:
//!
//!   - sets `SP1_RUNNER_PIN_CORE=0` so the JIT child runner-binary pins
//!     itself to CPU 0 on startup (see `crates/core/runner-binary/src/main.rs`),
//!   - pins the controller's chunk-receive thread to CPU 1,
//!   - constructs a dedicated rayon pool whose worker threads each pin to a
//!     distinct physical CPU in `2..min(num_physical, num_logical)`, with the
//!     leaf-hashing rayon work then `.install`'d onto that pool.
//!
//! The mechanism is Linux-specific (`sched_setaffinity`). On other platforms
//! the pinning is a no-op — the env var is honored, but the syscall is
//! skipped behind `#[cfg(target_os = "linux")]`.

use std::sync::Arc;

/// Pin the calling thread to a single logical CPU.
///
/// No-op on non-Linux. Logs and continues on syscall failure (e.g. when
/// running under a restrictive cgroup that masks the CPU).
pub fn pin_current_thread_to_cpu(cpu: usize) {
    #[cfg(target_os = "linux")]
    {
        // Safety: writing to a stack-allocated cpu_set_t; the syscall's
        // contract requires the buffer to live for the duration of the call,
        // which it does (we don't return early).
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_ZERO(&mut set);
            libc::CPU_SET(cpu, &mut set);
            let rc = libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set);
            if rc != 0 {
                tracing::warn!(
                    cpu,
                    errno = ?std::io::Error::last_os_error(),
                    "sched_setaffinity failed (continuing unpinned)"
                );
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cpu;
    }
}

/// Build a rayon ThreadPool whose worker threads each pin to a fixed CPU.
///
/// Worker index `i` pins to `cpus[i]`. Pool size = `cpus.len()`. If `cpus`
/// is empty, falls back to the rayon global pool (returns `None`).
///
/// Returned via `Arc<rayon::ThreadPool>` so the hash worker thread can
/// `install` against it; rayon's `ThreadPool` is not `Clone`, so callers
/// share via the `Arc`.
pub fn build_pinned_rayon_pool(cpus: Vec<usize>) -> Option<Arc<rayon::ThreadPool>> {
    if cpus.is_empty() {
        return None;
    }
    let cpus_arc = Arc::new(cpus);
    let n = cpus_arc.len();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .start_handler({
            let cpus = cpus_arc.clone();
            move |idx| pin_current_thread_to_cpu(cpus[idx])
        })
        .build()
        .expect("build pinned rayon pool");
    Some(Arc::new(pool))
}

/// Returns `true` if `LEAVES_PIN_CORES` is set in the env.
pub fn pin_cores_enabled() -> bool {
    std::env::var_os("LEAVES_PIN_CORES").is_some_and(|s| !s.is_empty())
}

/// Returns the CPU set the pinned rayon pool should use, given the host's
/// physical and logical CPU counts. CPU 0 is for the JIT child, CPU 1 for
/// the parent recv thread. We restrict to one logical CPU per physical core
/// so rayon doesn't double up on SMT siblings of those two reserved cores.
pub fn pinned_pool_cpus(hw_physical: usize, hw_logical: usize) -> Vec<usize> {
    let upper = hw_physical.min(hw_logical);
    if upper <= 2 {
        return Vec::new();
    }
    (2..upper).collect()
}
