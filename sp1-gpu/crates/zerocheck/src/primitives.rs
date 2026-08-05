use slop_algebra::{AbstractField, ExtensionField, Field};
use slop_alloc::{Backend, Buffer, CpuBackend, HasBackend, Slice};
use slop_commit::Rounds;

use slop_multilinear::{MleEval, Point};
use slop_tensor::{Tensor, TensorView};

use sp1_gpu_cudart::sys::kernels::{
    fix_last_two_variables_jagged_felt, fix_last_variable_jagged_ext, fix_last_variable_jagged_felt,
};
use sp1_gpu_cudart::sys::runtime::KernelPtr;
use sp1_gpu_cudart::{
    args, dot_along_dim_view, DeviceBuffer, DevicePoint, DeviceTensor, TaskScope,
};
use sp1_gpu_utils::{Ext, Felt, JaggedTraceMle, TraceDenseData, TraceOffset};
use std::collections::BTreeMap;

pub(crate) trait JaggedFixLastVariableKernel<K: Field> {
    fn jagged_fix_last_variable_kernel() -> KernelPtr;
}

impl JaggedFixLastVariableKernel<Felt> for TaskScope {
    fn jagged_fix_last_variable_kernel() -> KernelPtr {
        unsafe { fix_last_variable_jagged_felt() }
    }
}

impl JaggedFixLastVariableKernel<Ext> for TaskScope {
    fn jagged_fix_last_variable_kernel() -> KernelPtr {
        unsafe { fix_last_variable_jagged_ext() }
    }
}

/// Scratch buffers for the fold-metadata multi-block scan. Caller allocates
/// once (sized for the initial-round block count, which upper-bounds every
/// subsequent round) and resets in place — no per-fold allocation.
pub struct FoldMetadataScratch<'a> {
    pub block_counter: &'a mut Buffer<u32, TaskScope>,
    pub flags: &'a mut Buffer<u32, TaskScope>,
    pub scan_values: &'a mut Buffer<u32, TaskScope>,
}

/// Runs the fold-metadata kernel: reads `input_heights` (device pointer to
/// `n_columns` pair-unit heights), returns freshly allocated folded
/// `column_heights` and `start_indices` buffers.
///
/// Single launch — fully on device, no host round-trip. The kernel uses a
/// multi-block decoupled-lookback inclusive scan with the `h.div_ceil(4)*2`
/// transform fused into the load and the exclusive-prefix shift fused into
/// the store. The caller-owned scan scratch is reset in place per the
/// contract in `fold_metadata.cuh`; since `n_columns` is invariant across
/// folds, the same capacity suffices every round.
fn launch_fold_metadata(
    input_heights: *const u32,
    n_columns: usize,
    scratch: &mut FoldMetadataScratch<'_>,
    backend: &TaskScope,
) -> (Buffer<u32, TaskScope>, Buffer<u32, TaskScope>) {
    let section_size =
        unsafe { sp1_gpu_cudart::sys::kernels::jagged_fold_metadata_section_size() } as usize;
    let block_dim = unsafe { sp1_gpu_cudart::sys::kernels::jagged_fold_metadata_block_dim() };
    let n_blocks: usize = n_columns.div_ceil(section_size).max(1);

    let mut output_heights_dev =
        Buffer::<u32, TaskScope>::with_capacity_in(n_columns, backend.clone());
    let mut output_start_idx =
        Buffer::<u32, TaskScope>::with_capacity_in(n_columns + 1, backend.clone());
    // SAFETY: the fold-metadata kernel writes all `n_columns` + `n_columns+1`
    // slots before any downstream read.
    unsafe {
        output_heights_dev.assume_init();
        output_start_idx.assume_init();
    }

    // Reset the cached scan bookkeeping in place — no per-fold allocation.
    // `block_counter[0] = 0`, `flags[0]` set non-zero so the first block
    // doesn't wait, `flags[1..n_blocks+1] = 0` and `scan_values[0..n_blocks+1]
    // = 0` so the decoupled-lookback chain starts from a clean state.
    let u32_bytes = std::mem::size_of::<u32>();
    unsafe {
        scratch.block_counter.set_len(0);
        scratch.flags.set_len(0);
        scratch.scan_values.set_len(0);
    }
    scratch.block_counter.write_bytes(0, u32_bytes).unwrap();
    scratch.flags.write_bytes(1, u32_bytes).unwrap();
    scratch.flags.write_bytes(0, n_blocks * u32_bytes).unwrap();
    scratch.scan_values.write_bytes(0, (n_blocks + 1) * u32_bytes).unwrap();

    unsafe {
        let args = args!(
            input_heights,
            n_columns as u32,
            output_heights_dev.as_mut_ptr(),
            output_start_idx.as_mut_ptr(),
            scratch.block_counter.as_mut_ptr(),
            scratch.flags.as_mut_ptr(),
            scratch.scan_values.as_mut_ptr()
        );
        backend
            .launch_kernel(
                sp1_gpu_cudart::sys::kernels::jagged_fold_metadata_kernel(),
                (n_blocks as u32, 1u32, 1u32),
                (block_dim, 1u32, 1u32),
                &args,
                0,
            )
            .unwrap();
    }

    (output_heights_dev, output_start_idx)
}

/// Folds the trace MLE against `value`, returning the next-round MLE.
///
/// The caller passes `input_length` (sum of input column_heights in pair
/// units, used as the fold kernel's loop bound) and `new_total_length`
/// (sum of new column_heights * 2 = element count for the new dense
/// buffer). Both are deterministic functions of the existing column_heights
/// metadata; the zerocheck (and logup_gkr) callers maintain a per-chip
/// host-side tracker that produces them in O(n_chips) without any GPU sync.
///
/// The fold-metadata kernel (`jagged_fold_metadata`) computes the new
/// `column_heights` and `start_indices` on device — no host download of
/// column_heights, no host upload of derived metadata.
#[inline(always)]
pub(crate) fn evaluate_jagged_fix_last_variable<F: Field>(
    jagged_mle: &JaggedTraceMle<F, TaskScope>,
    value: Ext,
    input_length: u32,
    new_total_length: u32,
    scratch: FoldMetadataScratch<'_>,
) -> JaggedTraceMle<Ext, TaskScope>
where
    TaskScope: JaggedFixLastVariableKernel<F>,
    Ext: ExtensionField<F>,
{
    let backend = jagged_mle.dense().backend();

    // Adjusts offsets for each chip.
    fn update_offset(
        old_map: &BTreeMap<String, TraceOffset>,
        starting_offset: usize,
    ) -> (BTreeMap<String, TraceOffset>, usize) {
        let mut current_offset = starting_offset;
        let mut next_table_index = BTreeMap::new();
        for (chip, old_offset) in old_map.iter() {
            let next_poly_size = old_offset.poly_size.div_ceil(4) * 2;
            let upper = current_offset + next_poly_size * old_offset.num_polys;
            let next_offset = TraceOffset {
                dense_offset: current_offset..upper,
                poly_size: next_poly_size,
                num_polys: old_offset.num_polys,
            };
            next_table_index.insert(chip.clone(), next_offset.clone());
            current_offset = upper;
        }
        (next_table_index, current_offset)
    }
    let (next_preprocessed_table_index, next_preprocessed_offset) =
        update_offset(&jagged_mle.dense_data.preprocessed_table_index, 0);

    // For any round after the first, there's no padding.
    let (next_main_table_index, _next_main_offset) =
        update_offset(&jagged_mle.dense_data.main_table_index, next_preprocessed_offset);

    // ---- Device-side fold metadata ----
    let n_columns = jagged_mle.column_heights.len();
    let mut scratch = scratch;
    let (output_heights_dev, output_start_idx) =
        launch_fold_metadata(jagged_mle.column_heights.as_ptr(), n_columns, &mut scratch, backend);

    let new_data =
        Buffer::<Ext, TaskScope>::with_capacity_in(new_total_length as usize, backend.clone());
    let new_cols =
        Buffer::<u32, TaskScope>::with_capacity_in(new_total_length as usize / 2, backend.clone());

    // For the next trace data, we drop the element-unit padding (the
    // post-fold layout has no slack to track), but the *column* structure
    // is preserved — the fold-metadata kernel transforms every column's
    // height in place, so the padding-column count carries over unchanged.
    let next_trace_data = TraceDenseData {
        dense: new_data,
        preprocessed_offset: next_preprocessed_offset,
        preprocessed_cols: jagged_mle.dense_data.preprocessed_cols,
        preprocessed_table_index: next_preprocessed_table_index,
        main_table_index: next_main_table_index,
        main_padding: 0,
        preprocessed_padding: 0,
        prep_padding_col_count: jagged_mle.dense_data.prep_padding_col_count,
        main_padding_col_count: jagged_mle.dense_data.main_padding_col_count,
    };

    let mut next_jagged_mle =
        JaggedTraceMle::new(next_trace_data, new_cols, output_start_idx, output_heights_dev);

    const BLOCK_SIZE: usize = 256;
    const CHUNK_SIZE: usize = 1 << 16;
    let grid_size_x = (input_length as usize).div_ceil(CHUNK_SIZE).max(256);
    let grid_size = (grid_size_x, 1, 1);
    let block_dim_fold = BLOCK_SIZE;

    // SAFETY: `next_jagged_mle` is freshly allocated with capacity sized to
    // `total_length`; the kernel below writes every element before any later
    // reader (no host read until the next round consumes it). The `args!`
    // tuple matches `fix_last_variable_jagged_<felt|ext>`'s C signature in
    // `sys/include/zerocheck/jagged_mle.cuh`. Both jagged-MLE raw views borrow
    // from buffers held for the launch's lifetime by the enclosing scope.
    unsafe {
        next_jagged_mle.dense_data.dense.assume_init();
        next_jagged_mle.col_index.assume_init();
        let args = args!(jagged_mle.as_raw(), next_jagged_mle.as_mut_raw(), input_length, value);
        backend
            .launch_kernel(
                <TaskScope as JaggedFixLastVariableKernel<F>>::jagged_fix_last_variable_kernel(),
                grid_size,
                block_dim_fold,
                &args,
                0,
            )
            .unwrap();
    }

    next_jagged_mle
}

/// Folds the trace MLE against two challenges in a single pass over the
/// input, returning the twice-folded MLE — byte-identical to two chained
/// [`evaluate_jagged_fix_last_variable`] calls, but the intermediate
/// (half-size, extension-field) trace is never written or re-read.
///
/// `alpha_1` folds the last variable, `alpha_2` the second-to-last.
/// `input_length` is the input pair count; `new_total_length` the
/// twice-folded element count. Base-field input only: the caller is the
/// zerocheck fused first-two-rounds, whose two challenges are both known
/// before any fold happens.
#[inline(always)]
pub(crate) fn evaluate_jagged_fix_last_two_variables(
    jagged_mle: &JaggedTraceMle<Felt, TaskScope>,
    alpha_1: Ext,
    alpha_2: Ext,
    input_length: u32,
    new_total_length: u32,
    scratch: FoldMetadataScratch<'_>,
) -> JaggedTraceMle<Ext, TaskScope> {
    let backend = jagged_mle.dense().backend();

    // Adjusts offsets for each chip — the single-fold recurrence applied
    // twice.
    fn update_offset_twice(
        old_map: &BTreeMap<String, TraceOffset>,
        starting_offset: usize,
    ) -> (BTreeMap<String, TraceOffset>, usize) {
        let mut current_offset = starting_offset;
        let mut next_table_index = BTreeMap::new();
        for (chip, old_offset) in old_map.iter() {
            let once_poly_size = old_offset.poly_size.div_ceil(4) * 2;
            let next_poly_size = once_poly_size.div_ceil(4) * 2;
            let upper = current_offset + next_poly_size * old_offset.num_polys;
            let next_offset = TraceOffset {
                dense_offset: current_offset..upper,
                poly_size: next_poly_size,
                num_polys: old_offset.num_polys,
            };
            next_table_index.insert(chip.clone(), next_offset.clone());
            current_offset = upper;
        }
        (next_table_index, current_offset)
    }
    let (next_preprocessed_table_index, next_preprocessed_offset) =
        update_offset_twice(&jagged_mle.dense_data.preprocessed_table_index, 0);
    let (next_main_table_index, _next_main_offset) =
        update_offset_twice(&jagged_mle.dense_data.main_table_index, next_preprocessed_offset);

    // ---- Device-side fold metadata, applied twice ----
    //
    // The intermediate metadata is only an input to the second launch; its
    // start indices are never consumed.
    let n_columns = jagged_mle.column_heights.len();
    let mut scratch = scratch;
    let (mid_heights, _mid_starts) =
        launch_fold_metadata(jagged_mle.column_heights.as_ptr(), n_columns, &mut scratch, backend);
    let (output_heights_dev, output_start_idx) =
        launch_fold_metadata(mid_heights.as_ptr(), n_columns, &mut scratch, backend);

    let new_data =
        Buffer::<Ext, TaskScope>::with_capacity_in(new_total_length as usize, backend.clone());
    let new_cols =
        Buffer::<u32, TaskScope>::with_capacity_in(new_total_length as usize / 2, backend.clone());

    let next_trace_data = TraceDenseData {
        dense: new_data,
        preprocessed_offset: next_preprocessed_offset,
        preprocessed_cols: jagged_mle.dense_data.preprocessed_cols,
        preprocessed_table_index: next_preprocessed_table_index,
        main_table_index: next_main_table_index,
        main_padding: 0,
        preprocessed_padding: 0,
        prep_padding_col_count: jagged_mle.dense_data.prep_padding_col_count,
        main_padding_col_count: jagged_mle.dense_data.main_padding_col_count,
    };

    let mut next_jagged_mle =
        JaggedTraceMle::new(next_trace_data, new_cols, output_start_idx, output_heights_dev);

    const BLOCK_SIZE: usize = 256;
    const CHUNK_SIZE: usize = 1 << 16;
    let n_quads = input_length / 2;
    let grid_size_x = (n_quads as usize).div_ceil(CHUNK_SIZE).max(256);
    let grid_size = (grid_size_x, 1, 1);
    let block_dim_fold = BLOCK_SIZE;

    // SAFETY: `next_jagged_mle` is freshly allocated with capacity sized to
    // `new_total_length`; the kernel below writes every element (real
    // outputs plus the per-column zero tails) before any later reader. The
    // `args!` tuple matches `fix_last_two_variables_jagged_felt`'s C
    // signature in `sys/include/zerocheck/jagged_mle.cuh`.
    unsafe {
        next_jagged_mle.dense_data.dense.assume_init();
        next_jagged_mle.col_index.assume_init();
        let args =
            args!(jagged_mle.as_raw(), next_jagged_mle.as_mut_raw(), n_quads, alpha_1, alpha_2);
        backend
            .launch_kernel(
                fix_last_two_variables_jagged_felt(),
                grid_size,
                block_dim_fold,
                &args,
                0,
            )
            .unwrap();
    }

    next_jagged_mle
}

/// Evaluate every column of `traces` (preprocessed + main, in that order) at
/// `point` and return the per-column evaluations as host-side
/// [`Ext`] values.
///
/// Per chip: compute the row partial-Lagrange table for `point`, slice the
/// chip's flat region out of the trace's dense backing buffer via a
/// `TensorView`, and dot-product each column with the partial Lagrange along
/// the row dimension. The aggregated result is one [`Ext`] per (chip,
/// column), concatenated in the order
/// `preprocessed_table_index ∪ main_table_index`.
///
/// Chips whose dense region is empty are skipped (no contribution).
#[inline(always)]
pub fn evaluate_traces(traces: &JaggedTraceMle<Felt, TaskScope>, point: &Point<Ext>) -> Vec<Ext> {
    let trace_data = traces.dense();
    let backend = traces.backend();
    let device_point = DevicePoint::from_host(point, backend).unwrap();
    let partial_lagrange = device_point.partial_lagrange();
    let total_cols = trace_data
        .preprocessed_table_index
        .values()
        .chain(trace_data.main_table_index.values())
        .map(|index| index.num_polys)
        .sum::<usize>();
    let mut result_buffer =
        DeviceBuffer::with_capacity_in(total_cols, backend.clone()).into_inner();

    let trace_ptr = trace_data.dense.as_ptr();
    let chip_indices =
        trace_data.preprocessed_table_index.values().chain(trace_data.main_table_index.values());
    for index in chip_indices {
        if index.dense_offset.start == index.dense_offset.end {
            continue;
        }
        // SAFETY: `dense_offset.start` is a valid in-bounds offset into the
        // contiguous `trace_data.dense` buffer by construction (the offsets
        // describe disjoint regions inside the same buffer); `num_polys *
        // poly_size` equals the region's length, so the resulting
        // `TensorView` aliases exactly that chip's slice. The view borrows
        // through `chip_ptr`, which outlives this loop iteration.
        let chip_ptr = unsafe { trace_ptr.add(index.dense_offset.start) };
        let chip_view = unsafe {
            TensorView::from_raw_parts(
                chip_ptr,
                [index.num_polys, index.poly_size].try_into().unwrap(),
                backend.clone(),
            )
        };
        let result = dot_along_dim_view(chip_view, partial_lagrange.guts().as_view(), 1);
        result_buffer.extend_from_device_slice(result.as_buffer()).unwrap();
    }

    DeviceBuffer::from_raw(result_buffer).to_host().unwrap()
}

/// Evaluate every column of `jagged_mle` at `point` by iteratively folding
/// the trailing variable on device, returning one [`Ext`] per column.
///
/// Equivalent in result to running `MleEval::eval_at_point` per column on the
/// host, but folds the whole jagged trace in place via repeated
/// `fix_last_variable_jagged_felt`/`_ext` kernel launches — one per variable
/// in `point`, walking from the last variable down to the first. After the
/// chain the dense data holds, for each non-empty column, the four
/// (a, b, c, d) coefficients of the residual extension element packed
/// contiguously, from which the column's evaluation is read directly.
///
/// Used by the test/bench paths that need a host-visible "expected" set of
/// column evaluations to compare against the prover's opening transcript.
pub fn evaluate_jagged_columns(
    jagged_mle: &JaggedTraceMle<Felt, TaskScope>,
    point: Point<Ext>,
) -> Vec<Ext> {
    // Not a hot path (one call at the END of zerocheck). Download
    // `column_heights` once and walk the recurrence on host to compute the
    // per-round lengths needed by `evaluate_jagged_fix_last_variable`.
    let mut heights: Vec<u32> = unsafe { jagged_mle.column_heights.copy_into_host_vec() };
    let input_heights = heights.clone();
    let row_variable = point.dimension();
    let backend = jagged_mle.dense().backend();

    // Local scratch — one allocation, reused across the per-round folds
    // inside this function via `set_len(0) + write_bytes`. `n_columns` is
    // invariant across folds, so this single capacity sizes the scan
    // bookkeeping for every round.
    let section_size =
        unsafe { sp1_gpu_cudart::sys::kernels::jagged_fold_metadata_section_size() } as usize;
    let initial_n_blocks = heights.len().div_ceil(section_size).max(1);
    let mut block_counter = Buffer::<u32, _>::with_capacity_in(1, backend.clone());
    let mut flags = Buffer::<u32, _>::with_capacity_in(initial_n_blocks + 1, backend.clone());
    let mut scan_values = Buffer::<u32, _>::with_capacity_in(initial_n_blocks + 1, backend.clone());

    let mut input_length: u32 = heights.iter().sum();
    let mut next_heights: Vec<u32> = heights.iter().map(|h| h.div_ceil(4) * 2).collect();
    let mut new_total_length: u32 = next_heights.iter().sum::<u32>() * 2;
    let mut jagged_mle = evaluate_jagged_fix_last_variable(
        jagged_mle,
        *point[row_variable - 1],
        input_length,
        new_total_length,
        FoldMetadataScratch {
            block_counter: &mut block_counter,
            flags: &mut flags,
            scan_values: &mut scan_values,
        },
    );
    heights = next_heights;

    for i in (0..row_variable - 1).rev() {
        input_length = heights.iter().sum();
        next_heights = heights.iter().map(|h| h.div_ceil(4) * 2).collect();
        new_total_length = next_heights.iter().sum::<u32>() * 2;
        jagged_mle = evaluate_jagged_fix_last_variable(
            &jagged_mle,
            *point[i],
            input_length,
            new_total_length,
            FoldMetadataScratch {
                block_counter: &mut block_counter,
                flags: &mut flags,
                scan_values: &mut scan_values,
            },
        );
        heights = next_heights;
    }
    let result = unsafe { jagged_mle.dense_data.dense.copy_into_host_vec() };

    let mut idx = 0;
    let mut evals = vec![Ext::zero(); input_heights.len()];
    for i in 0..input_heights.len() {
        if input_heights[i] != 0 {
            evals[i] = result[idx];
            idx += 4;
        }
    }

    evals
}

/// Evaluate a jagged MLE at `(z_row, z_col)` using a chunked GPU kernel,
/// returning the device-side per-column accumulator tensor.
///
/// The work is partitioned into `CHUNK_SIZE`-row blocks fed through `kernel`
/// (the field-specialised `jagged_eval_kernel_chunked_<felt|ext>`); each
/// block writes its partial into a (block, column) tensor that the caller
/// is expected to reduce along the block dimension. `total_length` is the
/// sum of all column heights and selects the kernel grid; `num_cols` sizes
/// the column dimension of the output.
pub fn evaluate_jagged_mle_chunked<F: Field>(
    jagged_mle: JaggedTraceMle<F, TaskScope>,
    z_row: Point<Ext, TaskScope>,
    z_col: Point<Ext, TaskScope>,
    num_cols: usize,
    total_length: usize,
    kernel: unsafe extern "C" fn() -> KernelPtr,
) -> Tensor<Ext, TaskScope> {
    let backend = z_row.backend();

    const BLOCK_SIZE: usize = 256;
    const CHUNK_ELEMS: usize = 1 << 15;
    const MAX_COLS_SH: usize = 16;

    let n_chunks = total_length.div_ceil(CHUNK_ELEMS);

    let grid_size_x = n_chunks;
    let grid_size = (grid_size_x, 1, 1);

    // Dynamic shared memory:
    let nwarps = BLOCK_SIZE.div_ceil(32);
    let shared_reduce = nwarps * std::mem::size_of::<Ext>();
    let shared_starts = (MAX_COLS_SH + 1) * std::mem::size_of::<u32>();
    let shared_zcol = MAX_COLS_SH * std::mem::size_of::<Ext>();
    let shared_mem = shared_reduce + shared_starts + shared_zcol;

    // Output one partial per block.
    let mut output_evals =
        Tensor::<Ext, TaskScope>::with_sizes_in([1, grid_size.0], backend.clone());

    let z_row_lagrange = DevicePoint::new(z_row.clone()).partial_lagrange();
    let z_col_lagrange = DevicePoint::new(z_col.clone()).partial_lagrange();

    let args = args!(
        jagged_mle.as_raw(),
        z_row_lagrange.as_ptr(),
        z_col_lagrange.as_ptr(),
        (total_length as u32),
        (num_cols as u32),
        output_evals.as_mut_ptr()
    );

    unsafe {
        output_evals.assume_init();
        backend.launch_kernel(kernel(), grid_size, (BLOCK_SIZE, 1, 1), &args, shared_mem).unwrap();
    }

    let output_eval = DeviceTensor::from_raw(output_evals).sum_dim(1);
    output_eval.into_inner()
}

/// Evaluates each chip at `stacked_point` and returns the evaluations as `Rounds<Vec<MleEval>>`.
/// Inserts padding for chips included in the smallest cluster, but not the actual trace.
pub fn round_batch_evaluations(
    stacked_point: &Point<Ext>,
    jagged_trace_mle: &JaggedTraceMle<Felt, TaskScope>,
) -> Rounds<Vec<MleEval<Ext>>> {
    let evaluations = evaluate_traces(jagged_trace_mle, stacked_point);

    fn mle_eval_from_slice<A: Backend>(slice: &Slice<Ext, A>, backend: &A) -> MleEval<Ext, A> {
        let len = slice.len();
        let mut buf = Buffer::with_capacity_in(len, backend.clone());
        unsafe {
            buf.set_len(len);
            buf.copy_from_slice(slice, backend).unwrap()
        };
        let tensor = Tensor::from(buf);
        MleEval::new(tensor)
    }

    let mut evals_so_far = 0;
    let mut preprocessed_host_evaluations = Vec::new();

    for offset in jagged_trace_mle.dense().preprocessed_table_index.values() {
        if offset.poly_size == 0 {
            let mut zeros = Buffer::with_capacity_in(offset.num_polys, CpuBackend);

            zeros.write_bytes(0, offset.num_polys * size_of::<Ext>()).unwrap();

            let mle_eval = mle_eval_from_slice(&zeros, &CpuBackend);
            preprocessed_host_evaluations.push(mle_eval);
        } else {
            let slice =
                Buffer::from(evaluations[evals_so_far..evals_so_far + offset.num_polys].to_vec());

            let mle_eval = mle_eval_from_slice(&slice[..], &CpuBackend);
            preprocessed_host_evaluations.push(mle_eval);
            evals_so_far += offset.num_polys;
        }
    }

    let preprocessed_host_evaluations =
        preprocessed_host_evaluations.into_iter().collect::<Vec<_>>();

    let mut main_host_evaluations = Vec::new();
    for offset in jagged_trace_mle.dense().main_table_index.values() {
        if offset.poly_size == 0 {
            let mut zeros = Buffer::with_capacity_in(offset.num_polys, CpuBackend);

            zeros.write_bytes(0, offset.num_polys * size_of::<Ext>()).unwrap();

            let mle_eval = mle_eval_from_slice(&zeros, &CpuBackend);
            main_host_evaluations.push(mle_eval);
        } else {
            let slice =
                Buffer::from(evaluations[evals_so_far..evals_so_far + offset.num_polys].to_vec());

            let mle_eval = mle_eval_from_slice(&slice[..], &CpuBackend);
            main_host_evaluations.push(mle_eval);
            evals_so_far += offset.num_polys;
        }
    }
    let main_host_evaluations = main_host_evaluations.into_iter().collect::<Vec<_>>();

    Rounds::from_iter([preprocessed_host_evaluations, main_host_evaluations])
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use serial_test::serial;
    use slop_algebra::{extension::BinomialExtensionField, AbstractField};
    use slop_alloc::Buffer;
    use slop_multilinear::Mle;
    use slop_multilinear::Point;
    use sp1_gpu_cudart::run_sync_in_place;
    use sp1_gpu_cudart::sys::kernels::jagged_eval_kernel_chunked_felt;
    use sp1_gpu_cudart::{DeviceBuffer, DevicePoint};
    use sp1_hypercube::log2_ceil_usize;
    use sp1_primitives::SP1Field;

    use crate::primitives::{evaluate_jagged_columns, evaluate_jagged_mle_chunked};
    use sp1_gpu_utils::{Ext, Felt};
    use sp1_gpu_utils::{JaggedTraceMle, TraceDenseData, TraceOffset};

    fn get_keccak_size() -> Vec<(u32, u32)> {
        vec![
            (65536, 13),
            (252960, 282),
            (119040, 2640),
            (4960, 672),
            (124000, 20),
            (0, 10),
            (472032, 17),
            (131072, 3),
            (4960, 10),
        ]
    }

    fn get_secp256k1_double_size() -> Vec<(u32, u32)> {
        vec![
            (65536, 13),
            (1016736, 282),
            (478464, 20),
            (0, 10),
            (472032, 17),
            (131072, 3),
            (59808, 1610),
            (59808, 10),
        ]
    }

    fn get_core_size() -> Vec<(u32, u32)> {
        vec![
            (291872, 34),
            (1158208, 31),
            (15328, 37),
            (551776, 52),
            (1254144, 46),
            (65536, 13),
            (64, 247),
            (295232, 282),
            (0, 61),
            (0, 36),
            (25024, 32),
            (131936, 39),
            (974144, 49),
            (664544, 41),
            (320, 46),
            (1760, 46),
            (960, 50),
            (31648, 45),
            (128, 15),
            (144832, 20),
            (23392, 83),
            (16, 60),
            (0, 10),
            (472032, 17),
            (131072, 3),
            (387488, 66),
            (206720, 70),
            (32, 14),
            (316288, 52),
            (573792, 41),
            (736, 47),
            (2592, 46),
            (49440, 34),
            (1216, 33),
            (5600, 10),
            (5664, 68),
            (61408, 32),
        ]
    }

    // Given a vector of (row_count, col_count) as input, returns
    // 1. Mle's for every table.
    // 2. Randomly generated dense data corresponding to the Mle's.
    // 3. Col Index corresponding to the dense data, for use in a JaggedMle.
    // 4. Start indices for every column, for use in a JaggedMle.
    fn get_input(sizes: &[(u32, u32)]) -> (Vec<Mle<SP1Field>>, Vec<SP1Field>, Vec<u32>, Vec<u32>) {
        let mut rng = StdRng::seed_from_u64(8);
        let sum_length = sizes.iter().map(|(a, b)| a * b).sum::<u32>();
        let mut cols = vec![0; (sum_length / 2) as usize];
        let num_cols = sizes.iter().map(|(_, b)| b).sum::<u32>();
        let mut start_idx = vec![0u32; (num_cols + 1) as usize];
        let mut col_idx: u32 = 0;
        let mut cnt: usize = 0;
        let data =
            (0..sum_length).map(|_| Felt::from_wrapped_u32(rng.next_u32())).collect::<Vec<_>>();
        let mut mles = vec![];
        for (row, col) in sizes {
            assert_eq!(*row % 4, 0);
            for _ in 0..*col {
                mles.push(Mle::from_buffer(Buffer::from(
                    data[2 * cnt..2 * cnt + *row as usize].to_vec(),
                )));
                for _ in 0..row / 2 {
                    cols[cnt] = col_idx;
                    cnt += 1;
                }
                start_idx[(col_idx + 1) as usize] = start_idx[col_idx as usize] + row / 2;
                col_idx += 1;
            }
        }
        (mles, data, cols, start_idx)
    }

    fn mle_evaluation_test(table_sizes: Vec<(u32, u32)>) {
        let (mles, data, cols, start_idx) = get_input(&table_sizes);

        let mut input_heights = vec![];
        for i in 1..start_idx.len() {
            input_heights.push(start_idx[i] - start_idx[i - 1]);
        }

        let mut rng = StdRng::seed_from_u64(4);

        let row_variable: usize = 22;
        let col_variable = log2_ceil_usize(mles.len());
        let z_row = Point::<Ext>::rand(&mut rng, row_variable as u32);
        let z_col = Point::<Ext>::rand(&mut rng, col_variable as u32);

        // Compute expected value using async host-side evaluation
        let z_row_lagrange = Mle::partial_lagrange(&z_row);
        let z_col_lagrange = Mle::partial_lagrange(&z_col);

        let mut eval = BinomialExtensionField::<Felt, 4>::zero();
        for (i, mle) in mles.iter().enumerate() {
            eval +=
                mle.eval_at_eq(&z_row_lagrange).to_vec()[0] * z_col_lagrange.guts().as_slice()[i];
        }

        let data = Buffer::from(data);
        let cols = Buffer::from(cols);
        let start_idx = Buffer::from(start_idx);
        run_sync_in_place(move |t| {
            // Warmup iteration.
            let z_row_device = DevicePoint::from_host(&z_row, &t).unwrap().into_inner();
            let z_col_device = DevicePoint::from_host(&z_col, &t).unwrap().into_inner();
            let jagged_mle = JaggedTraceMle::new(
                TraceDenseData {
                    dense: DeviceBuffer::from_host(&data, &t).unwrap().into_inner(),
                    preprocessed_offset: 0,
                    preprocessed_cols: 0,
                    preprocessed_table_index: BTreeMap::new(),
                    main_table_index: BTreeMap::new(),
                    main_padding: 0,
                    preprocessed_padding: 0,
                    prep_padding_col_count: 0,
                    main_padding_col_count: 0,
                },
                DeviceBuffer::from_host(&cols, &t).unwrap().into_inner(),
                DeviceBuffer::from_host(&start_idx, &t).unwrap().into_inner(),
                DeviceBuffer::from_host_slice(&input_heights, &t).unwrap().into_inner(),
            );

            t.synchronize_blocking().unwrap();
            let evaluation = evaluate_jagged_mle_chunked(
                jagged_mle,
                z_row_device,
                z_col_device,
                mles.len(),
                data.len() / 2,
                jagged_eval_kernel_chunked_felt,
            );
            t.synchronize_blocking().unwrap();

            let host_evals = unsafe { evaluation.into_buffer().copy_into_host_vec() };
            let evaluation = host_evals[0];
            assert_eq!(evaluation, eval);

            // Real iteration for benchmarking.
            let z_row_device = DevicePoint::from_host(&z_row, &t).unwrap().into_inner();
            let z_col_device = DevicePoint::from_host(&z_col, &t).unwrap().into_inner();
            let jagged_mle = JaggedTraceMle::new(
                TraceDenseData {
                    dense: DeviceBuffer::from_host(&data, &t).unwrap().into_inner(),
                    preprocessed_offset: 0,
                    preprocessed_cols: 0,
                    preprocessed_table_index: BTreeMap::new(),
                    main_table_index: BTreeMap::new(),
                    main_padding: 0,
                    preprocessed_padding: 0,
                    prep_padding_col_count: 0,
                    main_padding_col_count: 0,
                },
                DeviceBuffer::from_host(&cols, &t).unwrap().into_inner(),
                DeviceBuffer::from_host(&start_idx, &t).unwrap().into_inner(),
                DeviceBuffer::from_host_slice(&input_heights, &t).unwrap().into_inner(),
            );

            t.synchronize_blocking().unwrap();
            let now = std::time::Instant::now();
            let evaluation = evaluate_jagged_mle_chunked(
                jagged_mle,
                z_row_device,
                z_col_device,
                mles.len(),
                data.len() / 2,
                jagged_eval_kernel_chunked_felt,
            );

            t.synchronize_blocking().unwrap();
            let elapsed = now.elapsed();

            let host_evals = unsafe { evaluation.into_buffer().copy_into_host_vec() };
            let evaluation = host_evals[0];
            assert_eq!(evaluation, eval);

            tracing::info!("elapsed jagged chunked {elapsed:?}");
        })
        .unwrap();
    }

    // Instead of encoding all of the column evaluations as an MLE, this test directly
    // compares all column evaluations to the expected value from host.
    fn mle_individual_evaluation_test(table_sizes: Vec<(u32, u32)>) {
        let mut rng = StdRng::seed_from_u64(6);
        // Make (# of tables) chip names.
        let chip_names =
            (0..table_sizes.len()).map(|i| format!("chip_{i}")).collect::<BTreeSet<_>>();

        // Arbitrarily choose the first 1/4 of the tables to be preprocessed.
        let preprocessed_boundary = table_sizes.len() / 4;

        let mut current_offset = 0;
        let mut preprocessed_cols = 0;
        let mut preprocessed_offset = 0;
        let mut preprocessed_table_index = BTreeMap::new();
        let mut main_table_index = BTreeMap::new();
        for (i, (chip, table_size)) in chip_names.iter().zip(table_sizes.iter()).enumerate() {
            let upper = current_offset + (table_size.0 * table_size.1) as usize;
            let trace_offset = TraceOffset {
                dense_offset: current_offset..upper,
                poly_size: table_size.0 as usize,
                num_polys: table_size.1 as usize,
            };
            if i < preprocessed_boundary {
                preprocessed_table_index.insert(chip.clone(), trace_offset);
                preprocessed_cols += table_size.1;
                preprocessed_offset += table_size.0 * table_size.1;
            } else {
                main_table_index.insert(chip.clone(), trace_offset);
            }
            current_offset = upper;
        }

        let (mles, data, cols, start_idx) = get_input(&table_sizes);

        let mut input_heights = vec![];
        for i in 1..start_idx.len() {
            input_heights.push(start_idx[i] - start_idx[i - 1]);
        }

        let row_variable: usize = 22;
        let z_row = Point::<Ext>::rand(&mut rng, row_variable as u32);

        // Compute expected values using async host-side evaluation
        let z_row_lagrange = Mle::partial_lagrange(&z_row);

        let mut eval = vec![];
        for mle in mles.iter() {
            eval.push(mle.eval_at_eq(&z_row_lagrange).to_vec()[0]);
        }

        let data = Buffer::from(data);
        let cols = Buffer::from(cols);
        let start_idx = Buffer::from(start_idx);
        run_sync_in_place(move |t| {
            let jagged_mle = JaggedTraceMle::new(
                TraceDenseData {
                    dense: DeviceBuffer::from_host(&data, &t).unwrap().into_inner(),
                    preprocessed_offset: preprocessed_offset as usize,
                    preprocessed_cols: preprocessed_cols as usize,
                    preprocessed_table_index,
                    main_table_index,
                    main_padding: 0,
                    preprocessed_padding: 0,
                    prep_padding_col_count: 0,
                    main_padding_col_count: 0,
                },
                DeviceBuffer::from_host(&cols, &t).unwrap().into_inner(),
                DeviceBuffer::from_host(&start_idx, &t).unwrap().into_inner(),
                DeviceBuffer::from_host_slice(&input_heights, &t).unwrap().into_inner(),
            );

            t.synchronize_blocking().unwrap();
            let now = std::time::Instant::now();

            let result = evaluate_jagged_columns(&jagged_mle, z_row.clone());
            assert_eq!(eval, result);
            t.synchronize_blocking().unwrap();

            let elapsed = now.elapsed();
            tracing::info!("time: {elapsed:?}");
        })
        .unwrap();
    }

    #[serial]
    #[test]
    fn test_jagged_mle_eval_keccak() {
        let table_sizes = get_keccak_size();
        mle_evaluation_test(table_sizes);
    }

    #[serial]
    #[test]
    fn test_jagged_mle_eval_secp() {
        let table_sizes = get_secp256k1_double_size();
        mle_evaluation_test(table_sizes);
    }

    #[serial]
    #[test]
    fn test_jagged_mle_eval_core() {
        let table_sizes = get_core_size();
        mle_evaluation_test(table_sizes);
    }

    #[serial]
    #[test]
    fn test_jagged_mle_eval_individual_keccak() {
        let table_sizes = get_keccak_size();
        mle_individual_evaluation_test(table_sizes);
    }

    #[serial]
    #[test]
    fn test_jagged_mle_eval_individual_secp() {
        let table_sizes = get_secp256k1_double_size();
        mle_individual_evaluation_test(table_sizes);
    }

    #[serial]
    #[test]
    fn test_jagged_mle_eval_individual_core() {
        let table_sizes = get_core_size();
        mle_individual_evaluation_test(table_sizes);
    }
}
