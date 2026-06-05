//! Device-side bit-decomposition of column prefix sums.
//!
//! Replaces the host-side build of the K=64 two-stage bit MLE with a single
//! kernel launch: upload the `Vec<usize>` of column prefix sums as a small
//! `Buffer<u32, TaskScope>`, then expand into a `Mle<Felt, TaskScope>` in
//! `[K, two_c]` layout directly on device.

use slop_alloc::Buffer;
use slop_multilinear::Mle;
use slop_tensor::{Dimensions, Tensor};
use sp1_gpu_cudart::sys::jagged::bit_decompose_prefix_sums_kernel;
use sp1_gpu_cudart::{args, DeviceBuffer, TaskScope};
use sp1_gpu_utils::Felt;

/// `K = 64` matches `slop_jagged::jagged_assist::two_stage_jagged::K`.
pub const K: usize = 64;

/// Build the two-stage GKR bit MLE on device.
///
/// `prefix_sums` is the host `Vec<usize>` of column prefix sums (length
/// `num_real_pairs + 1`).  Returns an `Mle<Felt, TaskScope>` of shape
/// `[K=64, two_c]` where `two_c = 1 << log_num_cols`.  Columns at
/// indices `>= num_real_pairs` are zero-padded; bit rows above
/// `prefix_sum_length` are zero-padded by construction (the host prefix
/// sums fit in `u32`, so the top bits are all zero).
///
/// The output layout matches
/// `slop_jagged::build_merged_bit_mle_flat_gpu_layout` byte-for-byte.
pub fn build_bit_mle_on_device(
    prefix_sums: &[usize],
    log_num_cols: usize,
    backend: &TaskScope,
) -> Mle<Felt, TaskScope> {
    let two_c = 1usize << log_num_cols;
    let num_real_pairs = prefix_sums.len() - 1;
    assert!(num_real_pairs <= two_c, "num_real_pairs > 2^c");

    // Pack prefix sums as u32 (max value < 2^32 for SP1 shards).
    let packed_host: Vec<u32> = prefix_sums.iter().map(|&s| s as u32).collect();
    let packed_buf: Buffer<u32> = packed_host.into();
    let packed_device = DeviceBuffer::from_host(&packed_buf, backend).unwrap().into_inner();

    // Allocate the `[K, two_c]` output buffer (uninitialized — the kernel
    // writes every cell).
    let mut out: Buffer<Felt, TaskScope> = Buffer::with_capacity_in(K * two_c, backend.clone());
    unsafe { out.set_len(K * two_c) };

    // 2D grid: x over columns, y over bit rows.  Block 32x4 keeps occupancy
    // reasonable on Ada and writes contiguous 32-wide segments per warp.
    const BLOCK_X: usize = 32;
    const BLOCK_Y: usize = 4;
    let grid_x = two_c.div_ceil(BLOCK_X);
    let grid_y = K.div_ceil(BLOCK_Y);

    unsafe {
        let kernel = bit_decompose_prefix_sums_kernel();
        let kargs =
            args!(packed_device.as_ptr(), num_real_pairs as u32, two_c as u32, out.as_mut_ptr());
        backend
            .launch_kernel(kernel, (grid_x, grid_y, 1), (BLOCK_X, BLOCK_Y, 1), &kargs, 0)
            .unwrap();
    }

    let dims = Dimensions::try_from([K, two_c]).unwrap();
    Mle::new(Tensor { storage: out, dimensions: dims })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_gpu_cudart::{run_sync_in_place, DeviceTensor};

    /// GPU layout matches `build_merged_bit_mle_flat_gpu_layout` byte-for-byte.
    #[test]
    fn gpu_bit_mle_matches_cpu_build() {
        // Mix of prefix-sum sizes: some real cols, then padding.
        let prefix_sums: Vec<usize> = vec![0, 7, 7, 22, 22, 22, 100, 12345, 2_000_000_001];
        let num_real_pairs = prefix_sums.len() - 1;
        let log_num_cols =
            (num_real_pairs.next_power_of_two().max(1) as u32).trailing_zeros() as usize;
        let log_num_cols = log_num_cols.max(1);

        let host_ref =
            slop_jagged::build_merged_bit_mle_flat_gpu_layout::<Felt>(&prefix_sums, log_num_cols);

        let gpu_flat: Vec<Felt> = run_sync_in_place(|backend| {
            let mle = build_bit_mle_on_device(&prefix_sums, log_num_cols, &backend);
            DeviceTensor::from_raw(mle.into_guts()).to_host().unwrap().into_buffer().into_vec()
        })
        .unwrap();

        assert_eq!(host_ref.len(), gpu_flat.len(), "length mismatch");
        for (i, (h, g)) in host_ref.iter().zip(gpu_flat.iter()).enumerate() {
            assert_eq!(h, g, "mismatch at index {i}");
        }
    }
}
