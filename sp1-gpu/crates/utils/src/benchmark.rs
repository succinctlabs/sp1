use std::time::Duration;

use slop_alloc::Buffer;
use sp1_gpu_cudart::{args, sys::algebra::bandwidth_test_kernel, DeviceBuffer, TaskScope};

/// Runs an ideal memory-bound baseline kernel.
///
/// Allocates device buffers and runs a simple kernel that reads `read_count` u32 elements and
/// writes `write_count` u32 elements. Each write-thread accumulates multiple input elements via
/// strided access, ensuring all reads happen and the compiler cannot elide any loads.
///
/// Returns the elapsed wall-clock time for just the kernel execution (excludes allocation).
///
/// This provides a bandwidth ceiling to compare against real kernels like the jagged sumcheck.
pub fn ideal_memory_bound_baseline(
    t: &TaskScope,
    read_count: usize,
    write_count: usize,
) -> Duration {
    assert!(read_count > 0, "read_count must be > 0");
    assert!(write_count > 0, "write_count must be > 0");

    // Allocate input buffer (read_count u32 elements).
    let host_input: Vec<u32> = (0..read_count as u32).collect();
    let input = DeviceBuffer::from_host_slice(&host_input, t).unwrap();

    // Allocate output buffer (write_count u32 elements).
    let mut output = Buffer::<u32, TaskScope>::with_capacity_in(write_count, t.clone());
    unsafe {
        output.assume_init();
    }

    // Synchronize before timing.
    t.synchronize_blocking().unwrap();

    let start = std::time::Instant::now();

    const BLOCK_SIZE: usize = 256;
    let grid_dim = write_count.div_ceil(BLOCK_SIZE);
    unsafe {
        let args = args!(
            input.as_ptr(),      // input
            output.as_mut_ptr(), // output
            read_count,          // read_count
            write_count          // write_count
        );
        t.launch_kernel(bandwidth_test_kernel(), grid_dim, BLOCK_SIZE, &args, 0)
            .unwrap();
    }

    // Synchronize after kernel.
    t.synchronize_blocking().unwrap();

    start.elapsed()
}
