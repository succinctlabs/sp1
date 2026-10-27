use std::iter::once;

use slop_alloc::{Backend, Buffer, CpuBackend, HasBackend};
use slop_tensor::{Dimensions, Tensor};
use sp1_gpu_cudart::{args, TaskScope};

#[derive(Clone, Debug)]
#[repr(C)]
pub struct JaggedMle<D: DenseData<A>, A: Backend> {
    /// col_index[i / 2] is the column that the i'th element of the dense data belongs to.
    pub col_index: Buffer<u32, A>,
    /// start_indices[i] is the half the dense index of the first element of the i'th column.
    pub start_indices: Buffer<u32, A>,
    /// column_heights[i] is half of the height of the i'th column. Device-
    /// resident — every fold runs on the GPU, and zerocheck consumes it
    /// directly on device to derive per-chip layouts without a host round-trip.
    pub column_heights: Buffer<u32, A>,
    pub dense_data: D,
}

pub struct VirtualTensor<T, B: Backend> {
    pub data: *const T,
    pub sizes: Dimensions,
    pub backend: B,
}

impl<T, B: Backend> VirtualTensor<T, B> {
    pub fn new(data: *const T, sizes: Dimensions, backend: B) -> Self {
        Self { data, sizes, backend }
    }

    pub fn sizes(&self) -> &[usize] {
        self.sizes.sizes()
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn as_ptr(&self) -> *const T {
        self.data
    }

    pub fn from_tensor(tensor: &Tensor<T, B>) -> Self {
        Self {
            data: tensor.as_ptr(),
            sizes: tensor.shape().clone(),
            backend: tensor.backend().clone(),
        }
    }
}

pub trait DenseData<A: Backend> {
    type DenseDataRaw;
    fn as_ptr(&self) -> Self::DenseDataRaw;
}

pub trait DenseDataMut<A: Backend>: DenseData<A> {
    type DenseDataMutRaw;
    fn as_mut_ptr(&mut self) -> Self::DenseDataMutRaw;
}

/// The raw pointer equivalent of [`JaggedMle`] for use in cuda kernels.
#[repr(C)]
pub struct JaggedMleRaw<D: DenseData<A>, A: Backend> {
    col_index: *const u32,
    start_indices: *const u32,
    dense_data: D::DenseDataRaw,
}

/// The mutable raw pointer equivalent of [`JaggedMle`] for use in cuda kernels.
#[repr(C)]
pub struct JaggedMleMutRaw<D: DenseDataMut<A>, A: Backend> {
    col_index: *mut u32,
    start_indices: *mut u32,
    dense_data: D::DenseDataMutRaw,
}

impl<D: DenseData<A>, A: Backend> JaggedMle<D, A> {
    pub fn as_raw(&self) -> JaggedMleRaw<D, A> {
        JaggedMleRaw {
            col_index: self.col_index.as_ptr(),
            start_indices: self.start_indices.as_ptr(),
            dense_data: self.dense_data.as_ptr(),
        }
    }

    pub fn as_mut_raw(&mut self) -> JaggedMleMutRaw<D, A>
    where
        D: DenseDataMut<A>,
    {
        JaggedMleMutRaw {
            col_index: self.col_index.as_mut_ptr(),
            start_indices: self.start_indices.as_mut_ptr(),
            dense_data: self.dense_data.as_mut_ptr(),
        }
    }

    pub fn new(
        dense_data: D,
        col_index: Buffer<u32, A>,
        start_indices: Buffer<u32, A>,
        column_heights: Buffer<u32, A>,
    ) -> Self {
        Self { dense_data, col_index, start_indices, column_heights }
    }

    pub fn column_heights(&self) -> &Buffer<u32, A> {
        &self.column_heights
    }

    pub fn dense(&self) -> &D {
        &self.dense_data
    }

    pub fn dense_mut(&mut self) -> &mut D {
        &mut self.dense_data
    }

    pub fn col_index(&self) -> &Buffer<u32, A> {
        &self.col_index
    }

    pub fn col_index_mut(&mut self) -> &mut Buffer<u32, A> {
        &mut self.col_index
    }

    pub fn start_indices(&self) -> &Buffer<u32, A> {
        &self.start_indices
    }

    pub fn start_indices_mut(&mut self) -> &mut Buffer<u32, A> {
        &mut self.start_indices
    }

    pub fn into_parts(self) -> (D, Buffer<u32, A>, Buffer<u32, A>) {
        (self.dense_data, self.col_index, self.start_indices)
    }
}

impl<D: DenseData<TaskScope>> JaggedMle<D, TaskScope> {
    /// Computes the next start indices, column heights and *input* total
    /// length for use in jagged fix last variable.
    ///
    /// Returns host buffers; the caller uploads device copies as needed. We
    /// download `column_heights` once and compute on host because the per-
    /// round fold's hot work happens on device — this metadata derivation is
    /// O(n_columns) and the round trip is cheap. The input length is returned
    /// alongside so callers don't re-download `column_heights` to sum it.
    ///
    /// TODO: ignore all of the padding stuff.
    pub fn next_start_indices_and_column_heights(
        &self,
    ) -> (Buffer<u32, CpuBackend>, Vec<u32>, u32) {
        // SAFETY: `column_heights` was populated via `extend_from_host_slice`
        // (or the equivalent during fold), so the device range is fully
        // initialised up to `len()`.
        let host_column_heights: Vec<u32> = unsafe { self.column_heights.copy_into_host_vec() };
        let input_length = host_column_heights.iter().sum::<u32>();
        let output_heights =
            host_column_heights.iter().map(|height| height.div_ceil(4) * 2).collect::<Vec<u32>>();

        let new_start_idx = once(0)
            .chain(output_heights.iter().scan(0u32, |acc, x| {
                *acc += x;
                Some(*acc)
            }))
            .collect::<Vec<_>>();
        let buffer_start_idx = Buffer::from(new_start_idx);
        (buffer_start_idx, output_heights, input_length)
    }

    /// Device-resident counterpart of [`Self::next_start_indices_and_column_heights`].
    ///
    /// Runs the `jagged_fold_metadata` kernel to compute the new `column_heights`
    /// and `start_indices` on device (no host download of the input
    /// `column_heights`, no host upload of the derived metadata). Reads back
    /// only the final `output_height` scalar (last element of new
    /// `start_indices`, ~4 bytes) since downstream callers need it to size
    /// host-allocated output tensors.
    ///
    /// Replaces the bulk `D2H column_heights + 2× H2D start_idx/heights`
    /// pattern with a single kernel launch + tiny D2H — on `v6/rsp` this
    /// drops ~50 k of `cudaMemcpyAsync` calls per prove across the 4
    /// logup_gkr callers (`execution::layer_transition`,
    /// `execution::first_layer_transition`, `sumcheck::fix_and_sum_first_layer`,
    /// `sumcheck::fix_and_sum_layer_transition`).
    ///
    /// Multi-block scans allocate small bookkeeping buffers (`block_counter`, `flags`,
    /// `scan_values`). Single-block scans need no bookkeeping allocations or initialization.
    ///
    /// Returns `(new_start_indices_dev, new_column_heights_dev, output_height)`.
    pub fn next_start_indices_and_column_heights_dev(
        &self,
    ) -> (Buffer<u32, TaskScope>, Buffer<u32, TaskScope>, u32) {
        fold_jagged_metadata_dev(&self.column_heights)
    }
}

/// Free-function core of [`JaggedMle::next_start_indices_and_column_heights_dev`]: runs the
/// fold-metadata kernel (`heights' = h.div_ceil(4) * 2` plus its prefix sum) on a device
/// `column_heights` buffer.
pub fn fold_jagged_metadata_dev(
    column_heights: &Buffer<u32, TaskScope>,
) -> (Buffer<u32, TaskScope>, Buffer<u32, TaskScope>, u32) {
    fold_jagged_metadata_n_dev(column_heights, 1, None)
}

/// Advance metadata by two folds in one launch: applying `2 * ceil(h / 4)` twice
/// equals `2 * ceil(h / 8)`. Avoids intermediate buffers and a host download.
pub fn fold_jagged_metadata_twice_dev(
    column_heights: &Buffer<u32, TaskScope>,
) -> (Buffer<u32, TaskScope>, Buffer<u32, TaskScope>, u32) {
    fold_jagged_metadata_n_dev(column_heights, 2, None)
}

/// Fold metadata on the GPU, reusing a previously measured output height when available.
/// The supplied height must come from the same column layout and number of folds.
pub fn fold_jagged_metadata_n_dev(
    column_heights: &Buffer<u32, TaskScope>,
    folds: u32,
    known_output_height: Option<u32>,
) -> (Buffer<u32, TaskScope>, Buffer<u32, TaskScope>, u32) {
    assert!(folds == 1 || folds == 2);
    let backend = column_heights.backend();
    let n_columns = column_heights.len();
    let section_size =
        unsafe { sp1_gpu_cudart::sys::kernels::jagged_fold_metadata_section_size() } as usize;
    let block_dim = unsafe { sp1_gpu_cudart::sys::kernels::jagged_fold_metadata_block_dim() };
    let n_blocks: usize = n_columns.div_ceil(section_size).max(1);

    let mut new_column_heights =
        Buffer::<u32, TaskScope>::with_capacity_in(n_columns, backend.clone());
    let mut new_start_indices =
        Buffer::<u32, TaskScope>::with_capacity_in(n_columns + 1, backend.clone());
    // SAFETY: the fold-metadata kernel writes all `n_columns` +
    // `n_columns + 1` slots before any downstream read.
    unsafe {
        new_column_heights.assume_init();
        new_start_indices.assume_init();
    }

    // Decoupled-lookback scan bookkeeping. Per the contract in
    // `fold_metadata.cuh`: `block_counter[0] = 0`, `flags[0] = 1` so
    // the first block doesn't wait, `flags[1..]` and `scan_values[..]`
    // start at zero.
    let single = n_blocks == 1;
    let mut scratch = if single {
        None
    } else {
        let bytes = std::mem::size_of::<u32>();
        let mut counter = Buffer::<u32, TaskScope>::with_capacity_in(1, backend.clone());
        let mut flags = Buffer::<u32, TaskScope>::with_capacity_in(n_blocks + 1, backend.clone());
        let mut values = Buffer::<u32, TaskScope>::with_capacity_in(n_blocks + 1, backend.clone());
        counter.write_bytes(0, bytes).unwrap();
        flags.write_bytes(1, bytes).unwrap();
        flags.write_bytes(0, n_blocks * bytes).unwrap();
        values.write_bytes(0, (n_blocks + 1) * bytes).unwrap();
        Some((counter, flags, values))
    };
    let (counter, flags, values) = scratch
        .as_mut()
        .map_or((std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()), |(c, f, v)| {
            (c.as_mut_ptr(), f.as_mut_ptr(), v.as_mut_ptr())
        });

    // SAFETY: `args!` tuple matches `jagged_fold_metadata`'s C signature
    // in `sys/include/jagged_assist/fold_metadata.cuh`; every pointer
    // borrows from a Buffer owned for the launch's lifetime, except null bookkeeping
    // pointers that the single-block specialization never dereferences.
    unsafe {
        let a = args!(
            column_heights.as_ptr(),
            n_columns as u32,
            new_column_heights.as_mut_ptr(),
            new_start_indices.as_mut_ptr(),
            counter,
            flags,
            values
        );
        backend
            .launch_kernel(
                sp1_gpu_cudart::sys::kernels::jagged_fold_metadata_specialized_kernel(
                    folds, single,
                ),
                (n_blocks as u32, 1u32, 1u32),
                (block_dim, 1u32, 1u32),
                &a,
                0,
            )
            .unwrap();
    }

    // The GKR circuit already records this height during generation. Reuse it
    // during proving to avoid a stream synchronization and download per fold.
    // Other callers discover the size by downloading the GPU-computed prefix sums.
    let output_height = known_output_height.unwrap_or_else(|| {
        let host_start_idx: Vec<u32> = unsafe { new_start_indices.copy_into_host_vec() };
        *host_start_idx.last().unwrap()
    });

    (new_start_indices, new_column_heights, output_height)
}

impl<D: DenseData<A>, A: Backend> HasBackend for JaggedMle<D, A> {
    type Backend = A;
    fn backend(&self) -> &A {
        self.col_index.backend()
    }
}
