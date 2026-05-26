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
    /// Allocates the scan bookkeeping (`block_counter`, `flags`,
    /// `scan_values`) inline. The bookkeeping is small (≤ `n_blocks + 1`
    /// `u32` each, where `n_blocks = ceil(n_columns / SECTION_SIZE)` —
    /// typically 1 for shards with a few hundred columns), so the extra
    /// allocs are cheap compared to the bulk transfers eliminated.
    ///
    /// Returns `(new_start_indices_dev, new_column_heights_dev, output_height)`.
    pub fn next_start_indices_and_column_heights_dev(
        &self,
    ) -> (Buffer<u32, TaskScope>, Buffer<u32, TaskScope>, u32) {
        let backend = self.column_heights.backend();
        let n_columns = self.column_heights.len();
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
        let u32_bytes = std::mem::size_of::<u32>();
        let mut block_counter = Buffer::<u32, TaskScope>::with_capacity_in(1, backend.clone());
        let mut flags = Buffer::<u32, TaskScope>::with_capacity_in(n_blocks + 1, backend.clone());
        let mut scan_values =
            Buffer::<u32, TaskScope>::with_capacity_in(n_blocks + 1, backend.clone());
        block_counter.write_bytes(0, u32_bytes).unwrap();
        flags.write_bytes(1, u32_bytes).unwrap();
        flags.write_bytes(0, n_blocks * u32_bytes).unwrap();
        scan_values.write_bytes(0, (n_blocks + 1) * u32_bytes).unwrap();

        // SAFETY: `args!` tuple matches `jagged_fold_metadata`'s C signature
        // in `sys/include/jagged_assist/fold_metadata.cuh`; every pointer
        // borrows from a Buffer owned for the launch's lifetime.
        unsafe {
            let a = args!(
                self.column_heights.as_ptr(),
                n_columns as u32,
                new_column_heights.as_mut_ptr(),
                new_start_indices.as_mut_ptr(),
                block_counter.as_mut_ptr(),
                flags.as_mut_ptr(),
                scan_values.as_mut_ptr()
            );
            backend
                .launch_kernel(
                    sp1_gpu_cudart::sys::kernels::jagged_fold_metadata_kernel(),
                    (n_blocks as u32, 1u32, 1u32),
                    (block_dim, 1u32, 1u32),
                    &a,
                    0,
                )
                .unwrap();
        }

        // Read back `output_height = new_start_indices[n_columns]`. The
        // downstream caller needs this scalar to size the next layer's
        // host-allocated output tensors. We download the whole
        // `new_start_indices` buffer (n_columns + 1 u32 ≈ a few KB,
        // *much* smaller than the bulk transfers this path replaces) and
        // grab the last element. A future optimization could maintain
        // `output_height` as a host-tracked scalar via the same
        // recurrence the kernel runs, eliminating this final D2H.
        // SAFETY: kernel above fully wrote `new_start_indices`; the
        // download synchronizes on `backend`'s stream.
        let host_start_idx: Vec<u32> = unsafe { new_start_indices.copy_into_host_vec() };
        let output_height = *host_start_idx.last().unwrap();

        (new_start_indices, new_column_heights, output_height)
    }
}

impl<D: DenseData<A>, A: Backend> HasBackend for JaggedMle<D, A> {
    type Backend = A;
    fn backend(&self) -> &A {
        self.col_index.backend()
    }
}
