use crate::data::{InfoBuffer, JaggedDenseInfo};
use slop_algebra::{AbstractField, ExtensionField, Field};
use slop_alloc::{Backend, Buffer, CpuBackend, HasBackend, Slice};
use slop_commit::Rounds;
use slop_multilinear::{Evaluations, MleEval, Point};
use slop_tensor::Tensor;
use sp1_gpu_cudart::sys::runtime::KernelPtr;
use sp1_gpu_cudart::sys::v2_kernels::{
    fix_last_variable_jagged_ext, fix_last_variable_jagged_felt, fix_last_variable_jagged_info,
    initialize_jagged_info,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DevicePoint, DeviceTensor, TaskScope};
use sp1_gpu_utils::{Ext, Felt, JaggedMle, JaggedTraceMle, TraceDenseData, TraceOffset};
use std::collections::BTreeMap;
use std::iter::once;

pub trait JaggedFixLastVariableKernel<K: Field> {
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

#[inline(always)]
pub fn evaluate_jagged_fix_last_variable<F: Field>(
    jagged_mle: &JaggedTraceMle<F, TaskScope>,
    value: Ext,
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

    let length = jagged_mle.column_heights.iter().sum::<u32>();

    // Adjusts offsets for each column, without tracking chip information.
    let (buffer_start_idx, output_heights) = jagged_mle.next_start_indices_and_column_heights();

    let new_total_length = buffer_start_idx.last().unwrap() * 2;

    let output_start_idx =
        DeviceBuffer::from_host(&buffer_start_idx, backend).unwrap().into_inner();

    let new_data =
        Buffer::<Ext, TaskScope>::with_capacity_in(new_total_length as usize, backend.clone());
    let new_cols =
        Buffer::<u32, TaskScope>::with_capacity_in(new_total_length as usize / 2, backend.clone());

    // For the next trace data, we remove all of the padding.
    let next_trace_data = TraceDenseData {
        dense: new_data,
        preprocessed_offset: next_preprocessed_offset,
        preprocessed_cols: jagged_mle.dense_data.preprocessed_cols,
        preprocessed_table_index: next_preprocessed_table_index,
        main_table_index: next_main_table_index,
        main_padding: 0,
        preprocessed_padding: 0,
    };

    let mut next_jagged_mle =
        JaggedTraceMle::new(next_trace_data, new_cols, output_start_idx, output_heights);

    const BLOCK_SIZE: usize = 256;
    const CHUNK_SIZE: usize = 1 << 16;
    let grid_size_x = (length as usize).div_ceil(CHUNK_SIZE).max(256);
    let grid_size = (grid_size_x, 1, 1);
    let block_dim = BLOCK_SIZE;

    unsafe {
        next_jagged_mle.dense_data.dense.assume_init();
        next_jagged_mle.col_index.assume_init();
        let args = args!(jagged_mle.as_raw(), next_jagged_mle.as_mut_raw(), length, value);
        backend
            .launch_kernel(
                <TaskScope as JaggedFixLastVariableKernel<F>>::jagged_fix_last_variable_kernel(),
                grid_size,
                block_dim,
                &args,
                0,
            )
            .unwrap();
    }

    next_jagged_mle
}

#[inline(always)]
pub fn evaluate_traces(traces: &JaggedTraceMle<Felt, TaskScope>, point: &Point<Ext>) -> Vec<Ext> {
    let mut next_input_jagged_trace_mle =
        evaluate_jagged_fix_last_variable(traces, *point.last().unwrap());
    for alpha in point.iter().rev().skip(1) {
        next_input_jagged_trace_mle =
            evaluate_jagged_fix_last_variable(&next_input_jagged_trace_mle, *alpha);
    }

    let host_dense = DeviceBuffer::from_raw(next_input_jagged_trace_mle.dense_data.dense.clone())
        .to_host()
        .unwrap()
        .to_vec();

    // Only every four elements is not padding.
    host_dense.into_iter().step_by(4).collect::<Vec<_>>()
}

pub fn evaluate_jagged_columns(
    jagged_mle: &JaggedTraceMle<Felt, TaskScope>,
    point: Point<Ext>,
) -> Vec<Ext> {
    let input_heights = &jagged_mle.column_heights;
    let row_variable = point.dimension();
    let mut jagged_mle = evaluate_jagged_fix_last_variable(jagged_mle, *point[row_variable - 1]);

    for i in (0..row_variable - 1).rev() {
        jagged_mle = evaluate_jagged_fix_last_variable(&jagged_mle, *point[i]);
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

pub fn initialize_jagged_dense_info(
    heights: Vec<u32>,
    values: Vec<u32>,
    backend: &TaskScope,
) -> JaggedDenseInfo<TaskScope> {
    let buffer_start_idx = once(0)
        .chain(heights.iter().scan(0u32, |acc, x| {
            *acc += x;
            Some(*acc)
        }))
        .collect::<Buffer<_>>();
    let start_idx_device =
        DeviceBuffer::from_host(&buffer_start_idx, backend).unwrap().into_inner();
    let values = DeviceBuffer::from_host(&Buffer::from(values), backend).unwrap().into_inner();

    let num_blocks = heights.len();
    assert_eq!(heights.len(), values.len());

    let total_len = buffer_start_idx.last().unwrap() * 2;
    let info_buffer =
        Buffer::<u32, TaskScope>::with_capacity_in(total_len as usize, backend.clone());
    let info_cols_buffer =
        Buffer::<u32, TaskScope>::with_capacity_in(total_len as usize / 2, backend.clone());

    let mut jagged_info =
        JaggedMle::new(InfoBuffer::new(info_buffer), info_cols_buffer, start_idx_device, heights);

    const BLOCK_SIZE: usize = 256;
    const CHUNK_SIZE: usize = 1 << 16;
    let grid_size_x = (total_len as usize / 2).div_ceil(CHUNK_SIZE);
    let grid_size = (grid_size_x, 1, 1);
    let block_dim = BLOCK_SIZE;

    unsafe {
        jagged_info.dense_data.assume_init();
        jagged_info.col_index.assume_init();
        let args =
            args!(jagged_info.as_mut_raw(), values.as_ptr(), total_len / 2, num_blocks as u32);
        backend.launch_kernel(initialize_jagged_info(), grid_size, block_dim, &args, 0).unwrap();
    }

    JaggedDenseInfo(jagged_info)
}

pub fn evaluate_jagged_info_fix_last_variable(
    jagged_info: JaggedDenseInfo<TaskScope>,
) -> JaggedDenseInfo<TaskScope> {
    let backend = jagged_info.dense_data.backend();
    let input_heights = &jagged_info.column_heights;

    let length = input_heights.iter().sum::<u32>();
    let output_heights =
        input_heights.iter().map(|height| height.div_ceil(4) * 2).collect::<Vec<u32>>();
    let new_start_idx = once(0)
        .chain(output_heights.iter().scan(0u32, |acc, x| {
            *acc += x;
            Some(*acc)
        }))
        .collect::<Vec<_>>();
    let new_total_length = *new_start_idx.last().unwrap() * 2;
    let buffer_start_idx = Buffer::from(new_start_idx);
    let output_start_idx =
        DeviceBuffer::from_host(&buffer_start_idx, backend).unwrap().into_inner();
    let new_data =
        Buffer::<u32, TaskScope>::with_capacity_in(new_total_length as usize, backend.clone());
    let new_cols = Buffer::<u32, TaskScope>::with_capacity_in(
        (new_total_length / 2) as usize,
        backend.clone(),
    );

    let mut next_jagged_info = JaggedDenseInfo::new(
        InfoBuffer { data: new_data },
        new_cols,
        output_start_idx,
        output_heights,
    );

    const BLOCK_SIZE: usize = 256;
    const CHUNK_SIZE: usize = 1 << 16;
    let grid_size_x = (length as usize).div_ceil(CHUNK_SIZE).max(256);
    let grid_size = (grid_size_x, 1, 1);
    let block_dim = BLOCK_SIZE;

    unsafe {
        next_jagged_info.dense_data.assume_init();
        next_jagged_info.col_index.assume_init();
        let args = args!(jagged_info.as_raw(), next_jagged_info.as_mut_raw(), length);
        backend
            .launch_kernel(fix_last_variable_jagged_info(), grid_size, block_dim, &args, 0)
            .unwrap();
    }

    next_jagged_info
}

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

/// Evaluates each chip at `stacked_point` and returns the evaluations in a `Rounds<Evaluations>` form.
/// Inserts padding for chips included in the smallest cluster, but not the actual trace.
pub fn round_batch_evaluations(
    stacked_point: &Point<Ext>,
    jagged_trace_mle: &JaggedTraceMle<Felt, TaskScope>,
) -> Rounds<Evaluations<Ext>> {
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
        preprocessed_host_evaluations.into_iter().collect::<Evaluations<_, _>>();

    // Skip the padding column, if it exists.
    evals_so_far = jagged_trace_mle.dense().preprocessed_cols;
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
    let main_host_evaluations = main_host_evaluations.into_iter().collect::<Evaluations<_, _>>();

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
    use slop_koala_bear::KoalaBear;
    use slop_multilinear::Mle;
    use slop_multilinear::Point;
    use sp1_gpu_cudart::run_sync_in_place;
    use sp1_gpu_cudart::sys::v2_kernels::jagged_eval_kernel_chunked_felt;
    use sp1_gpu_cudart::{DeviceBuffer, DevicePoint};
    use sp1_hypercube::log2_ceil_usize;

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
    fn get_input(
        sizes: &[(u32, u32)],
    ) -> (Vec<Mle<KoalaBear>>, Vec<KoalaBear>, Vec<u32>, Vec<u32>) {
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
                },
                DeviceBuffer::from_host(&cols, &t).unwrap().into_inner(),
                DeviceBuffer::from_host(&start_idx, &t).unwrap().into_inner(),
                input_heights.clone(),
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
                },
                DeviceBuffer::from_host(&cols, &t).unwrap().into_inner(),
                DeviceBuffer::from_host(&start_idx, &t).unwrap().into_inner(),
                input_heights.clone(),
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

            println!("elapsed jagged chunked {elapsed:?}");
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
                },
                DeviceBuffer::from_host(&cols, &t).unwrap().into_inner(),
                DeviceBuffer::from_host(&start_idx, &t).unwrap().into_inner(),
                input_heights.clone(),
            );

            t.synchronize_blocking().unwrap();
            let now = std::time::Instant::now();

            let result = evaluate_jagged_columns(&jagged_mle, z_row.clone());
            assert_eq!(eval, result);
            t.synchronize_blocking().unwrap();

            let elapsed = now.elapsed();
            println!("time: {elapsed:?}");
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
