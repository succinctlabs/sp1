use data::JaggedDenseInfo;
use itertools::Itertools;
use primitives::{
    evaluate_jagged_fix_last_variable, evaluate_jagged_info_fix_last_variable,
    initialize_jagged_dense_info, JaggedFixLastVariableKernel,
};
use slop_air::BaseAir;
use slop_algebra::{
    interpolate_univariate_polynomial, AbstractExtensionField, AbstractField, ExtensionField,
    Field, UnivariatePolynomial,
};
use slop_alloc::{Backend, Buffer, CpuBackend, HasBackend};
use slop_challenger::{FieldChallenger, VariableLengthChallenger};
use slop_matrix::dense::RowMajorMatrixView;
use slop_multilinear::{Point, VirtualGeq};
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::Tensor;
use sp1_gpu_air::instruction::Instruction16;
use sp1_gpu_air::{air_block::BlockAir, SymbolicProverFolder};
use sp1_gpu_cudart::sys::runtime::KernelPtr;
use sp1_gpu_cudart::sys::v2_kernels::{
    jagged_constraint_poly_eval_1024_koala_bear_extension_kernel,
    jagged_constraint_poly_eval_1024_koala_bear_kernel,
    jagged_constraint_poly_eval_128_koala_bear_extension_kernel,
    jagged_constraint_poly_eval_128_koala_bear_kernel,
    jagged_constraint_poly_eval_256_koala_bear_extension_kernel,
    jagged_constraint_poly_eval_256_koala_bear_kernel,
    jagged_constraint_poly_eval_32_koala_bear_extension_kernel,
    jagged_constraint_poly_eval_32_koala_bear_kernel,
    jagged_constraint_poly_eval_512_koala_bear_extension_kernel,
    jagged_constraint_poly_eval_512_koala_bear_kernel,
    jagged_constraint_poly_eval_64_koala_bear_extension_kernel,
    jagged_constraint_poly_eval_64_koala_bear_kernel,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DevicePoint, DeviceTensor, TaskScope};
use sp1_gpu_utils::{Ext, Felt, JaggedTraceMle};
use sp1_hypercube::air::MachineAir;
use sp1_hypercube::prover::ZerocheckAir;
use sp1_hypercube::{
    AirOpenedValues, Chip, ChipEvaluation, ChipOpenedValues, ConstraintSumcheckFolder,
    LogUpEvaluations, ShardOpenedValues,
};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

pub mod data;
pub mod primitives;

pub struct EvalProgramInfo<B: Backend = CpuBackend> {
    pub constraint_indices: Buffer<u32, B>,
    pub operations: Buffer<Instruction16, B>,
    pub operations_indices: Buffer<u32, B>,
    pub f_ctr: u32,
    pub f_constants: Buffer<Felt, B>,
    pub f_constants_indices: Buffer<u32, B>,
    pub ef_constants: Buffer<Ext, B>,
    pub ef_constants_indices: Buffer<u32, B>,
}

pub type CudaEvalResult =
    (Vec<u32>, Vec<Instruction16>, Vec<u32>, Vec<Felt>, Vec<u32>, Vec<Ext>, Vec<u32>, u32, u32);

pub struct ZeroCheckJaggedPoly<'a, K: Field> {
    /// The program for **all chips**.
    pub program: EvalProgramInfo<TaskScope>,
    /// The data in a `JaggedTraceMle` form.
    pub data: Cow<'a, JaggedTraceMle<K, TaskScope>>,
    /// The information in a `JaggedDenseInfo` form.
    pub info: JaggedDenseInfo<TaskScope>,
    /// The `VirtualGeq` for each table.
    pub virtual_geq: Vec<VirtualGeq<Ext>>,
    /// The `eq_adjustment`, identical to the `ZeroCheckPoly`.
    pub eq_adjustment: Ext,
    /// The `padded_row_adjustment` for each table.
    pub padded_row_adjustment: Buffer<Ext, TaskScope>,
    /// The random evaluation point, from the GKR.
    pub zeta: Point<Ext>,
    /// The claimed evaluation.
    pub claim: Ext,
    /// The number of preprocessed columns.
    pub total_num_preprocessed_column: u32,
    /// The public values.
    pub public_values: Buffer<Felt, TaskScope>,
    /// The powers of alpha.
    pub powers_of_alpha: Buffer<Ext, TaskScope>,
    /// The gkr powers.
    pub gkr_powers: Buffer<Ext, TaskScope>,
    /// The powers of lambda.
    pub powers_of_lambda: Buffer<Ext, TaskScope>,
    /// The number of preprocessed column per chip.
    pub preprocessed_column: Buffer<u32, TaskScope>,
    /// The number of main column per chips.
    pub main_column: Buffer<u32, TaskScope>,
    /// The chips.
    pub chips_info: Vec<(u32, u32, u32)>,
    /// The total length of the info data.
    pub total_len: usize,
}

pub fn initialize_program_cpu<A>(
    chips: &BTreeSet<Chip<Felt, A>>,
    zerocheck_programs: &BTreeMap<String, CudaEvalResult>,
) -> EvalProgramInfo
where
    A: for<'a> BlockAir<SymbolicProverFolder<'a>>,
{
    let mut constraint_indices: Vec<u32> = vec![];
    let mut operations: Vec<Instruction16> = vec![];
    let mut operations_indices: Vec<u32> = vec![];
    let mut f_ctr: u32 = 0;
    let mut ef_ctr: u32 = 0;
    let mut f_constants: Vec<Felt> = vec![];
    let mut f_constants_indices: Vec<u32> = vec![];
    let mut ef_constants: Vec<Ext> = vec![];
    let mut ef_constants_indices: Vec<u32> = vec![];

    let max_num_constraints =
        itertools::max(chips.iter().map(|chip| chip.num_constraints)).unwrap();

    for chip in chips {
        let (
            chip_constraint_indices,
            chip_operations,
            chip_operations_indices,
            chip_f_constants,
            chip_f_constants_indices,
            chip_ef_constants,
            chip_ef_constants_indices,
            chip_f_ctr,
            chip_ef_ctr,
        ) = zerocheck_programs.get(chip.air.name()).unwrap_or_else(|| {
            panic!("Chip name {} not found in CUDA eval cache", chip.air.name());
        });

        for constraint_index in chip_constraint_indices {
            constraint_indices
                .push((max_num_constraints - chip.num_constraints) as u32 + constraint_index);
        }

        let current_instruction_len = operations.len() as u32;
        operations.extend(chip_operations);
        for idx in chip_operations_indices.iter() {
            operations_indices.push(current_instruction_len + idx);
        }

        let current_f_constants_len = f_constants.len() as u32;
        f_constants.extend(chip_f_constants);
        for idx in chip_f_constants_indices.iter() {
            f_constants_indices.push(current_f_constants_len + idx);
        }

        let current_ef_constants_len = ef_constants.len() as u32;
        ef_constants.extend(chip_ef_constants);
        for idx in chip_ef_constants_indices.iter() {
            ef_constants_indices.push(current_ef_constants_len + idx);
        }

        f_ctr = f_ctr.max(*chip_f_ctr);
        ef_ctr = ef_ctr.max(*chip_ef_ctr);
    }
    operations_indices.push(operations.len() as u32);

    EvalProgramInfo {
        constraint_indices: Buffer::from(constraint_indices),
        operations: Buffer::from(operations),
        operations_indices: Buffer::from(operations_indices),
        f_ctr,
        f_constants: Buffer::from(f_constants),
        f_constants_indices: Buffer::from(f_constants_indices),
        ef_constants: Buffer::from(ef_constants),
        ef_constants_indices: Buffer::from(ef_constants_indices),
    }
}

pub fn initialize_program<A>(
    chips: &BTreeSet<Chip<Felt, A>>,
    zerocheck_programs: &BTreeMap<String, CudaEvalResult>,
    scope: &TaskScope,
) -> EvalProgramInfo<TaskScope>
where
    A: for<'a> BlockAir<SymbolicProverFolder<'a>>,
{
    let cpu_info = initialize_program_cpu(chips, zerocheck_programs);

    let constraint_indices_device =
        DeviceBuffer::from_host(&cpu_info.constraint_indices, scope).unwrap().into_inner();
    let operations_device =
        DeviceBuffer::from_host(&cpu_info.operations, scope).unwrap().into_inner();
    let operations_indices_device =
        DeviceBuffer::from_host(&cpu_info.operations_indices, scope).unwrap().into_inner();
    let f_constants_device =
        DeviceBuffer::from_host(&cpu_info.f_constants, scope).unwrap().into_inner();
    let f_constants_indices_device =
        DeviceBuffer::from_host(&cpu_info.f_constants_indices, scope).unwrap().into_inner();
    let ef_constants_device =
        DeviceBuffer::from_host(&cpu_info.ef_constants, scope).unwrap().into_inner();
    let ef_constants_indices_device =
        DeviceBuffer::from_host(&cpu_info.ef_constants_indices, scope).unwrap().into_inner();

    EvalProgramInfo {
        constraint_indices: constraint_indices_device,
        operations: operations_device,
        operations_indices: operations_indices_device,
        f_constants: f_constants_device,
        f_constants_indices: f_constants_indices_device,
        f_ctr: cpu_info.f_ctr,
        ef_constants: ef_constants_device,
        ef_constants_indices: ef_constants_indices_device,
    }
}

/// The format is `is_first || chip_idx || prep_start || main_start` in little endian.
/// `is_first` is a bit, `chip_idx` is 7 bits, `prep_start` is 10 bits, and `main_start` is 14 bits.
pub fn pack_info(is_first: bool, chip_idx: u32, prep_start: u32, main_start: u32) -> u32 {
    (is_first as u32) + (chip_idx << 1) + (prep_start << 8) + (main_start << 18)
}

/// The `packed_info` is `is_first || chip_idx || prep_start || main_start` in little endian.
/// `is_first` is a bit, `chip_idx` is 7 bits, `prep_start` is 10 bits, and `main_start` is 14 bits.
pub fn unpack_info(packed_info: u32) -> (u32, u32, u32, u32) {
    (
        (packed_info & 1),
        ((packed_info >> 1) & 0x7F),
        (packed_info >> 8) & 0x3FF,
        (packed_info >> 18) & 0x3FFF,
    )
}

#[allow(clippy::type_complexity)]
pub fn initialize_dense_info<A>(
    chips: &BTreeSet<Chip<Felt, A>>,
    initial_heights: &[u32],
    backend: &TaskScope,
) -> (JaggedDenseInfo<TaskScope>, u32, usize, Vec<(u32, u32, u32)>)
where
    A: for<'a> BlockAir<SymbolicProverFolder<'a>>,
{
    let mut tot_len: usize = 0;
    let mut total_num_block: usize = 0;
    let mut chips_info = vec![];
    for (chip, height) in chips.iter().zip_eq(initial_heights.iter()) {
        let num_air_blocks = chip.air.clone().num_blocks();
        assert_eq!(height % 4, 0, "invariant height % 4 == 0 invalidated");
        tot_len += (*height as usize) * num_air_blocks;
        total_num_block += num_air_blocks;
        chips_info.push((
            num_air_blocks as u32,
            chip.preprocessed_width() as u32,
            chip.width() as u32,
        ));
    }

    let mut info_data = vec![0; total_num_block];
    let mut info_heights = vec![0; total_num_block];
    let mut air_block_idx: usize = 0;
    let mut total_preprocessed: u32 = 0;
    let mut total_main: u32 = 0;
    for (chip_idx, (chip, height)) in chips.iter().zip_eq(initial_heights.iter()).enumerate() {
        let num_air_blocks = chip.air.clone().num_blocks();
        for air_block in 0..num_air_blocks {
            let data = pack_info(air_block == 0, chip_idx as u32, total_preprocessed, total_main);
            info_data[air_block_idx] = data;
            info_heights[air_block_idx] = height / 2;
            air_block_idx += 1;
        }
        total_preprocessed += chip.air.clone().preprocessed_width() as u32;
        total_main += chip.air.clone().width() as u32;
    }

    let info = initialize_jagged_dense_info(info_heights, info_data, backend);
    (info, total_preprocessed, tot_len, chips_info)
}

#[allow(clippy::too_many_arguments)]
pub fn initialize_zerocheck_poly<'b, A>(
    data: &'b JaggedTraceMle<Felt, TaskScope>,
    chips: &BTreeSet<Chip<Felt, A>>,
    zerocheck_programs: &BTreeMap<String, CudaEvalResult>,
    initial_heights: Vec<u32>,
    public_values: Vec<Felt>,
    powers_of_alpha: Vec<Ext>,
    gkr_powers: Vec<Ext>,
    powers_of_lambda: Vec<Ext>,
    padded_row_adjustment: Vec<Ext>,
    zeta: Point<Ext>,
    claim: Ext,
) -> ZeroCheckJaggedPoly<'b, Felt>
where
    A: for<'a> BlockAir<SymbolicProverFolder<'a>>,
{
    let scope = data.dense().backend();
    let program = initialize_program(chips, zerocheck_programs, scope);
    let mut virtual_geq: Vec<VirtualGeq<Ext>> = vec![];
    let mut info_input_heights = vec![];

    for (chip, height) in chips.iter().zip_eq(initial_heights.iter()) {
        virtual_geq.push(VirtualGeq::new(
            *height,
            Ext::one(),
            Ext::zero(),
            zeta.dimension() as u32,
        ));
        let num_air_blocks = chip.air.clone().num_blocks();
        for _ in 0..num_air_blocks {
            info_input_heights.push(height / 2);
        }
    }

    let preprocessed_columns =
        chips.iter().map(|chip| chip.preprocessed_width() as u32).collect::<Buffer<u32>>();
    let main_columns = chips.iter().map(|chip| chip.width() as u32).collect::<Buffer<u32>>();

    let (info, total_preprocessed, tot_len, chips_info) =
        initialize_dense_info(chips, &initial_heights, scope);

    let padded_row_adjustment =
        DeviceBuffer::from_host(&Buffer::from(padded_row_adjustment), scope).unwrap().into_inner();
    let public_values_device =
        DeviceBuffer::from_host(&Buffer::from(public_values), scope).unwrap().into_inner();
    let powers_of_alpha_device =
        DeviceBuffer::from_host(&Buffer::from(powers_of_alpha), scope).unwrap().into_inner();
    let gkr_powers_device =
        DeviceBuffer::from_host(&Buffer::from(gkr_powers), scope).unwrap().into_inner();
    let powers_of_lambda_device =
        DeviceBuffer::from_host(&Buffer::from(powers_of_lambda), scope).unwrap().into_inner();
    let preprocessed_columns_device =
        DeviceBuffer::from_host(&preprocessed_columns, scope).unwrap().into_inner();
    let main_columns_device = DeviceBuffer::from_host(&main_columns, scope).unwrap().into_inner();

    ZeroCheckJaggedPoly {
        program,
        data: Cow::Borrowed(data),
        info,
        virtual_geq,
        eq_adjustment: Ext::one(),
        padded_row_adjustment,
        zeta,
        claim,
        total_num_preprocessed_column: total_preprocessed,
        public_values: public_values_device,
        powers_of_alpha: powers_of_alpha_device,
        gkr_powers: gkr_powers_device,
        powers_of_lambda: powers_of_lambda_device,
        preprocessed_column: preprocessed_columns_device,
        main_column: main_columns_device,
        chips_info,
        total_len: tot_len,
    }
}

pub trait JaggedConstraintPolyEvalKernel<K: Field> {
    fn jagged_constraint_poly_eval_kernel(memory_size: usize) -> KernelPtr;
}

impl JaggedConstraintPolyEvalKernel<Felt> for TaskScope {
    fn jagged_constraint_poly_eval_kernel(memory_size: usize) -> KernelPtr {
        match memory_size {
            0..=32 => unsafe { jagged_constraint_poly_eval_32_koala_bear_kernel() },
            33..=64 => unsafe { jagged_constraint_poly_eval_64_koala_bear_kernel() },
            65..=128 => unsafe { jagged_constraint_poly_eval_128_koala_bear_kernel() },
            129..=256 => unsafe { jagged_constraint_poly_eval_256_koala_bear_kernel() },
            257..=512 => unsafe { jagged_constraint_poly_eval_512_koala_bear_kernel() },
            513..=1024 => unsafe { jagged_constraint_poly_eval_1024_koala_bear_kernel() },
            _ => unreachable!(),
        }
    }
}

impl JaggedConstraintPolyEvalKernel<Ext> for TaskScope {
    fn jagged_constraint_poly_eval_kernel(memory_size: usize) -> KernelPtr {
        match memory_size {
            0..=32 => unsafe { jagged_constraint_poly_eval_32_koala_bear_extension_kernel() },
            33..=64 => unsafe { jagged_constraint_poly_eval_64_koala_bear_extension_kernel() },
            65..=128 => unsafe { jagged_constraint_poly_eval_128_koala_bear_extension_kernel() },
            129..=256 => unsafe { jagged_constraint_poly_eval_256_koala_bear_extension_kernel() },
            257..=512 => unsafe { jagged_constraint_poly_eval_512_koala_bear_extension_kernel() },
            513..=1024 => unsafe { jagged_constraint_poly_eval_1024_koala_bear_extension_kernel() },
            _ => unreachable!(),
        }
    }
}

pub fn evaluate_zerocheck<'b, K: Field>(
    input: &'b ZeroCheckJaggedPoly<'b, K>,
) -> UnivariatePolynomial<Ext>
where
    TaskScope: JaggedConstraintPolyEvalKernel<K>,
{
    let backend = input.data.backend();
    const BLOCK_SIZE: usize = 256;
    const NUM_EVAL_POINT: usize = 3;

    let n_chunks = input.total_len.div_ceil(1 << 12);
    let grid_size_x = n_chunks.max(256);
    let grid_size = (grid_size_x, 1, NUM_EVAL_POINT);

    let num_tiles = BLOCK_SIZE.div_ceil(32);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();

    let mut output: Tensor<Ext, TaskScope> =
        Tensor::with_sizes_in([NUM_EVAL_POINT, grid_size_x], backend.clone());

    let (rest, last) = input.zeta.split_at(input.zeta.dimension() - 1);
    let last = *last[0];
    let thresholds = input.virtual_geq.iter().map(|geq| geq.threshold).collect::<Buffer<_>>();
    let eq_coefficients =
        input.virtual_geq.iter().map(|geq| geq.eq_coefficient).collect::<Buffer<_>>();

    let rest_point = DevicePoint::from_host(&rest, backend).unwrap();
    let thresholds = DeviceBuffer::from_host(&thresholds, backend).unwrap().into_inner();
    let eq_coefficients = DeviceBuffer::from_host(&eq_coefficients, backend).unwrap().into_inner();

    let partial_lagrange = rest_point.partial_lagrange();
    let rest_point_dim = rest.dimension() as u32;

    unsafe {
        output.assume_init();
        let args = args!(
            input.program.constraint_indices.as_ptr(),
            input.program.operations,
            input.program.operations_indices.as_ptr(),
            input.program.f_constants.as_ptr(),
            input.program.f_constants_indices.as_ptr(),
            input.program.ef_constants.as_ptr(),
            input.program.ef_constants_indices.as_ptr(),
            input.data.as_raw(),
            input.info.as_raw(),
            partial_lagrange.as_ptr(),
            thresholds.as_ptr(),
            eq_coefficients.as_ptr(),
            (input.total_len / 2) as u32,
            input.padded_row_adjustment.as_ptr(),
            input.public_values.as_ptr(),
            input.powers_of_alpha.as_ptr(),
            input.gkr_powers.as_ptr(),
            input.powers_of_lambda.as_ptr(),
            input.preprocessed_column.as_ptr(),
            input.main_column.as_ptr(),
            input.total_num_preprocessed_column,
            output.as_mut_ptr(),
            rest_point_dim
        );
        backend
            .launch_kernel(
                <TaskScope as JaggedConstraintPolyEvalKernel<K>>::jagged_constraint_poly_eval_kernel(
                    input.program.f_ctr as usize,
                ),
                grid_size,
                (BLOCK_SIZE, 1, 1),
                &args,
                shared_mem,
            )
            .unwrap();
    }

    let output_eval = DeviceTensor::from_raw(output).sum_dim(1);
    let result = output_eval.to_host().unwrap().into_buffer().into_vec();

    let mut xs =
        vec![Ext::from_canonical_u32(0), Ext::from_canonical_u32(2), Ext::from_canonical_u32(4)];

    let mut ys = result
        .iter()
        .zip_eq(xs.iter())
        .map(|(&result, &x)| {
            let last_var_eq = (Ext::one() - x) * (Ext::one() - last) + x * last;
            result * last_var_eq * input.eq_adjustment
        })
        .collect::<Vec<_>>();

    xs.push(Ext::from_canonical_u32(1));
    ys.push(input.claim - ys[0]);

    xs.push((last - Ext::one()) / (last + last - Ext::one()));
    ys.push(Ext::zero());

    interpolate_univariate_polynomial(&xs, &ys)
}

pub fn zerocheck_fix_last_variable<'b, K: Field>(
    input: ZeroCheckJaggedPoly<'b, K>,
    point: Ext,
    claim: Ext,
) -> ZeroCheckJaggedPoly<'b, Ext>
where
    TaskScope: JaggedFixLastVariableKernel<K>,
    Ext: ExtensionField<K>,
{
    let (rest, last) = input.zeta.split_at(input.zeta.dimension() - 1);
    let last = *last[0];

    let new_data = evaluate_jagged_fix_last_variable(&input.data, point);
    let new_info = evaluate_jagged_info_fix_last_variable(input.info);

    let virtual_geq =
        input.virtual_geq.iter().map(|geq| geq.fix_last_variable(point)).collect::<Vec<_>>();
    let eq = (Ext::one() - last) * (Ext::one() - point) + last * point;
    let eq_adjustment = input.eq_adjustment * eq;
    let total_len = 2 * new_info.column_heights.iter().sum::<u32>() as usize;

    ZeroCheckJaggedPoly {
        program: input.program,
        data: Cow::Owned(new_data),
        info: new_info,
        virtual_geq,
        eq_adjustment,
        padded_row_adjustment: input.padded_row_adjustment,
        zeta: rest,
        claim,
        total_num_preprocessed_column: input.total_num_preprocessed_column,
        public_values: input.public_values,
        powers_of_alpha: input.powers_of_alpha,
        gkr_powers: input.gkr_powers,
        powers_of_lambda: input.powers_of_lambda,
        preprocessed_column: input.preprocessed_column,
        main_column: input.main_column,
        chips_info: input.chips_info,
        total_len,
    }
}

pub fn challenger_update<C>(
    input_poly: &UnivariatePolynomial<Ext>,
    challenger: &mut C,
) -> (Ext, Ext)
where
    C: FieldChallenger<Felt>,
{
    let coefficients =
        input_poly.coefficients.iter().flat_map(|x| x.as_base_slice()).copied().collect_vec();
    challenger.observe_slice(&coefficients);
    let point = challenger.sample_ext_element();
    let claim = input_poly.eval_at_point(point);
    (point, claim)
}

#[allow(clippy::too_many_arguments)]
pub fn zerocheck<A, C>(
    chips: &BTreeSet<Chip<Felt, A>>,
    zerocheck_programs: &BTreeMap<String, CudaEvalResult>,
    trace_mle: &JaggedTraceMle<Felt, TaskScope>,
    batching_challenge: Ext,
    gkr_opening_batch_randomness: Ext,
    logup_evaluations: &LogUpEvaluations<Ext>,
    public_values: Vec<Felt>,
    challenger: &mut C,
    max_log_row_count: u32,
) -> (ShardOpenedValues<Felt, Ext>, PartialSumcheckProof<Ext>)
where
    A: ZerocheckAir<Felt, Ext> + for<'a> BlockAir<SymbolicProverFolder<'a>>,
    C: FieldChallenger<Felt>,
{
    let data_input_heights = &trace_mle.column_heights;
    let initial_heights = trace_mle
        .dense_data
        .main_table_index
        .values()
        .map(|trace_offset| trace_offset.poly_size as u32)
        .collect::<Vec<u32>>();

    let max_num_constraints =
        itertools::max(chips.iter().map(|chip| chip.num_constraints)).unwrap();
    let max_columns =
        itertools::max(chips.iter().map(|chip| chip.preprocessed_width() + chip.width())).unwrap();
    let total_preprocessed_columns = trace_mle.dense().preprocessed_cols;
    let mut powers_of_challenge =
        batching_challenge.powers().take(max_num_constraints).collect::<Vec<_>>();
    powers_of_challenge.reverse();
    let num_chips = chips.len();

    let mut padded_row_adjustment = vec![Ext::zero(); num_chips];

    for (i, chip) in chips.iter().enumerate() {
        let prep_len = chip.preprocessed_width();
        let main_len = chip.width();
        let prep_zero = vec![Felt::zero(); prep_len];
        let main_zero = vec![Felt::zero(); main_len];
        let mut folder = ConstraintSumcheckFolder {
            preprocessed: RowMajorMatrixView::new_row(&prep_zero),
            main: RowMajorMatrixView::new_row(&main_zero),
            accumulator: Ext::zero(),
            public_values: &public_values,
            constraint_index: 0,
            powers_of_alpha: &powers_of_challenge
                [powers_of_challenge.len() - chip.num_constraints..],
        };
        chip.air.eval(&mut folder);
        padded_row_adjustment[i] = folder.accumulator;
    }

    let gkr_powers =
        gkr_opening_batch_randomness.powers().skip(1).take(max_columns).collect::<Vec<_>>();

    let lambda: Ext = challenger.sample_ext_element();
    let powers_of_lambda =
        lambda.powers().take(num_chips).collect_vec().into_iter().rev().collect();

    let mut claim = Ext::zero();

    let LogUpEvaluations { point: gkr_point, chip_openings } = logup_evaluations;

    for chip in chips.iter() {
        let ChipEvaluation {
            main_trace_evaluations: main_opening,
            preprocessed_trace_evaluations: prep_opening,
        } = chip_openings.get(chip.name()).unwrap();

        claim *= lambda;

        let addend = main_opening
            .evaluations()
            .as_slice()
            .iter()
            .chain(
                prep_opening
                    .as_ref()
                    .map_or_else(Vec::new, |mle| mle.evaluations().as_slice().to_vec())
                    .iter(),
            )
            .zip(gkr_powers.iter())
            .map(|(opening, power)| *opening * *power)
            .sum::<Ext>();

        claim += addend;
    }

    let main_poly = initialize_zerocheck_poly(
        trace_mle,
        chips,
        zerocheck_programs,
        initial_heights.clone(),
        public_values,
        powers_of_challenge,
        gkr_powers,
        powers_of_lambda,
        padded_row_adjustment,
        gkr_point.clone(),
        claim,
    );

    let mut univariate_polys = vec![];
    let mut jagged_point: Point<Ext> = Point::from(vec![]);
    let mut result = evaluate_zerocheck(&main_poly);
    let (mut point, mut next_claim) = challenger_update(&result, challenger);
    univariate_polys.push(result);
    jagged_point.add_dimension(point);
    let mut next_poly = zerocheck_fix_last_variable(main_poly, point, next_claim);
    for _ in 0..max_log_row_count - 1 {
        result = evaluate_zerocheck(&next_poly);
        (point, next_claim) = challenger_update(&result, challenger);
        univariate_polys.push(result);
        jagged_point.add_dimension(point);
        next_poly = zerocheck_fix_last_variable(next_poly, point, next_claim);
    }

    let final_jagged_data =
        unsafe { next_poly.data.as_ref().dense_data.dense.copy_into_host_vec() };

    let mut idx = 0;
    let mut individual_column_evals = vec![Ext::zero(); data_input_heights.len()];
    for i in 0..data_input_heights.len() {
        if data_input_heights[i] != 0 {
            individual_column_evals[i] = final_jagged_data[idx];
            idx += 4;
        }
    }

    let mut preprocessed_ptr = 0;
    let mut main_ptr = total_preprocessed_columns;
    let mut opened_values: BTreeMap<String, ChipOpenedValues<Felt, Ext>> = BTreeMap::new();
    challenger.observe(Felt::from_canonical_usize(chips.len()));
    for (i, chip) in chips.iter().enumerate() {
        let preprocessed_width = chip.preprocessed_width();
        let preprocessed = AirOpenedValues {
            local: individual_column_evals[preprocessed_ptr..preprocessed_ptr + preprocessed_width]
                .to_vec(),
        };
        challenger.observe_variable_length_extension_slice(&preprocessed.local);
        preprocessed_ptr += preprocessed_width;

        let width = chip.width();

        let main =
            AirOpenedValues { local: individual_column_evals[main_ptr..main_ptr + width].to_vec() };
        challenger.observe_variable_length_extension_slice(&main.local);
        main_ptr += width;

        opened_values.insert(
            chip.air.name().to_string(),
            ChipOpenedValues {
                preprocessed,
                main,
                degree: Point::from_usize(
                    initial_heights[i] as usize,
                    (max_log_row_count + 1) as usize,
                ),
            },
        );
    }

    let partial_sumcheck_proof = PartialSumcheckProof {
        univariate_polys,
        claimed_sum: claim,
        point_and_eval: (jagged_point, next_claim),
    };

    let shard_open_values = ShardOpenedValues { chips: opened_values };

    (shard_open_values, partial_sumcheck_proof)
}

#[cfg(test)]
pub mod tests {
    use itertools::Itertools;
    use rand::Rng;
    use serial_test::serial;
    use slop_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PairBuilder};
    use slop_algebra::{AbstractField, PrimeField32};
    use slop_alloc::{Buffer, CpuBackend};
    use slop_challenger::{
        CanObserve, CanSample, FieldChallenger, IopCtx, VariableLengthChallenger,
    };
    use slop_futures::queue::WorkerQueue;
    use slop_matrix::{dense::RowMajorMatrix, dense::RowMajorMatrixView, Matrix};
    use slop_multilinear::{full_geq, Mle, MleEval, Point};
    use slop_sumcheck::{partially_verify_sumcheck_proof, PartialSumcheckProof};
    use slop_tensor::Tensor;
    use sp1_gpu_cudart::{run_in_place, run_sync_in_place, PinnedBuffer};
    use sp1_hypercube::air::{MachineAir, SP1AirBuilder};
    use sp1_hypercube::prover::ZerocheckAir;
    use sp1_hypercube::{
        prover::ProverSemaphore, Chip, ChipEvaluation, ChipOpenedValues, ConstraintSumcheckFolder,
        LogUpEvaluations, ShardOpenedValues, VerifierConstraintFolder,
    };

    use sp1_gpu_air::codegen_cuda_eval;
    use sp1_primitives::SP1Field;
    use std::collections::{BTreeMap, BTreeSet};
    use std::marker::PhantomData;
    use std::ops::Deref;
    use std::sync::Arc;

    use sp1_core_machine::io::SP1Stdin;
    use sp1_gpu_jagged_tracegen::{
        full_tracegen,
        test_utils::tracegen_setup::{self, CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT},
        CORE_MAX_TRACE_SIZE,
    };
    use sp1_gpu_utils::{Ext, Felt, JaggedTraceMle, TestGC, TraceDenseData, TraceOffset};

    use super::primitives::evaluate_jagged_columns;
    use super::{
        challenger_update, evaluate_zerocheck, initialize_zerocheck_poly, zerocheck,
        zerocheck_fix_last_variable,
    };

    use core::{borrow::Borrow, mem::size_of};
    use sp1_core_executor::{ExecutionRecord, Program};
    use sp1_derive::AlignedBorrow;
    use sp1_gpu_air::{
        air_block::BlockAir, symbolic_expr_f::SymbolicExprF, symbolic_var_f::SymbolicVarF,
        SymbolicProverFolder,
    };

    #[derive(Debug)]
    pub enum ZerocheckTestChip {
        Chip1(ZerocheckTestChip1),
        Chip2(ZerocheckTestChip2),
        Chip3(ZerocheckTestChip3),
    }

    impl<AB: SP1AirBuilder + PairBuilder> Air<AB> for ZerocheckTestChip {
        fn eval(&self, builder: &mut AB) {
            match self {
                Self::Chip1(chip) => chip.eval(builder),
                Self::Chip2(chip) => chip.eval(builder),
                Self::Chip3(chip) => chip.eval(builder),
            }
        }
    }

    impl<F> BaseAir<F> for ZerocheckTestChip {
        fn width(&self) -> usize {
            match self {
                Self::Chip1(chip) => <ZerocheckTestChip1 as slop_air::BaseAir<F>>::width(chip),
                Self::Chip2(chip) => <ZerocheckTestChip2 as slop_air::BaseAir<F>>::width(chip),
                Self::Chip3(chip) => <ZerocheckTestChip3 as slop_air::BaseAir<F>>::width(chip),
            }
        }
    }

    impl<F: PrimeField32> MachineAir<F> for ZerocheckTestChip {
        type Record = ExecutionRecord;
        type Program = Program;

        fn name(&self) -> &'static str {
            match self {
                Self::Chip1(chip) => <ZerocheckTestChip1 as MachineAir<F>>::name(chip),
                Self::Chip2(chip) => <ZerocheckTestChip2 as MachineAir<F>>::name(chip),
                Self::Chip3(chip) => <ZerocheckTestChip3 as MachineAir<F>>::name(chip),
            }
        }

        fn num_rows(&self, _input: &Self::Record) -> Option<usize> {
            unimplemented!();
        }

        fn preprocessed_width(&self) -> usize {
            match self {
                Self::Chip1(chip) => {
                    <ZerocheckTestChip1 as MachineAir<F>>::preprocessed_width(chip)
                }
                Self::Chip2(chip) => {
                    <ZerocheckTestChip2 as MachineAir<F>>::preprocessed_width(chip)
                }
                Self::Chip3(chip) => {
                    <ZerocheckTestChip3 as MachineAir<F>>::preprocessed_width(chip)
                }
            }
        }

        fn generate_trace(&self, _: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
            unimplemented!();
        }

        fn generate_trace_into(
            &self,
            _: &Self::Record,
            _: &mut Self::Record,
            _: &mut [std::mem::MaybeUninit<F>],
        ) {
            unimplemented!();
        }

        fn included(&self, _: &Self::Record) -> bool {
            true
        }
    }

    impl<'a> BlockAir<SymbolicProverFolder<'a>> for ZerocheckTestChip {
        fn eval_block(&self, builder: &mut SymbolicProverFolder<'a>, index: usize) {
            match self {
                Self::Chip1(chip) => chip.eval_block(builder, index),
                Self::Chip2(chip) => chip.eval_block(builder, index),
                Self::Chip3(chip) => chip.eval_block(builder, index),
            }
        }

        fn num_blocks(&self) -> usize {
            match self {
                Self::Chip1(chip) => chip.num_blocks(),
                Self::Chip2(chip) => chip.num_blocks(),
                Self::Chip3(chip) => chip.num_blocks(),
            }
        }
    }

    #[derive(Default, Clone)]
    pub struct ZerocheckTestChip1;

    impl std::fmt::Debug for ZerocheckTestChip1 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ZerocheckTestChip1")
        }
    }

    /// The number of main trace columns for `ZerocheckTestChip1`.
    pub const NUM_ZEROCHECK_TEST1_COLS: usize = size_of::<ZerocheckTestCols1<u8>>();
    /// The column layout for the chip.
    #[derive(AlignedBorrow, Default, Clone, Copy)]
    #[repr(C)]
    pub struct ZerocheckTestCols1<T> {
        op_a: T,
        op_b: T,
        op_c: T,
        op_d: T,
    }

    impl<F> BaseAir<F> for ZerocheckTestChip1 {
        fn width(&self) -> usize {
            NUM_ZEROCHECK_TEST1_COLS
        }
    }

    impl<'a> BlockAir<SymbolicProverFolder<'a>> for ZerocheckTestChip1 {
        fn num_blocks(&self) -> usize {
            2
        }

        fn eval_block(&self, builder: &mut SymbolicProverFolder, index: usize) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &ZerocheckTestCols1<SymbolicVarF> = (*local).borrow();

            match index {
                0 => {
                    builder.assert_zero(
                        local.op_a + SymbolicExprF::from_canonical_u32(3) * local.op_b
                            - (local.op_b + local.op_c + SymbolicExprF::one())
                                * (local.op_b + local.op_c + SymbolicExprF::two())
                                * (local.op_b - local.op_c + SymbolicExprF::from_canonical_u32(8)),
                    );
                }
                1 => {
                    builder.assert_zero(
                        local.op_d
                            * (local.op_d - SymbolicExprF::one())
                            * (local.op_d - SymbolicExprF::two()),
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    impl<F: PrimeField32> MachineAir<F> for ZerocheckTestChip1 {
        type Record = ExecutionRecord;
        type Program = Program;

        fn name(&self) -> &'static str {
            "ZerocheckTest1"
        }

        fn num_rows(&self, _: &Self::Record) -> Option<usize> {
            unimplemented!();
        }

        fn generate_trace(
            &self,
            _: &ExecutionRecord,
            _: &mut ExecutionRecord,
        ) -> RowMajorMatrix<F> {
            unimplemented!();
        }

        fn generate_trace_into(
            &self,
            _: &Self::Record,
            _: &mut Self::Record,
            _: &mut [std::mem::MaybeUninit<F>],
        ) {
            unimplemented!();
        }

        fn included(&self, _: &Self::Record) -> bool {
            true
        }
    }

    impl<AB> Air<AB> for ZerocheckTestChip1
    where
        AB: SP1AirBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &ZerocheckTestCols1<AB::Var> = (*local).borrow();

            builder.assert_zero(
                local.op_a + AB::Expr::from_canonical_u32(3) * local.op_b
                    - (local.op_b + local.op_c + AB::Expr::one())
                        * (local.op_b + local.op_c + AB::Expr::two())
                        * (local.op_b - local.op_c + AB::Expr::from_canonical_u32(8)),
            );

            builder.assert_zero(
                local.op_d * (local.op_d - AB::Expr::one()) * (local.op_d - AB::Expr::two()),
            );
        }
    }

    #[derive(Default, Clone)]
    pub struct ZerocheckTestChip2;

    impl std::fmt::Debug for ZerocheckTestChip2 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ZerocheckTestChip2")
        }
    }

    /// The number of main trace columns for `ZerocheckTestChip2`.
    pub const NUM_ZEROCHECK_TEST2_COLS: usize = size_of::<ZerocheckTestCols2<u8>>();

    /// The column layout for the chip.
    #[derive(AlignedBorrow, Default, Clone, Copy)]
    #[repr(C)]
    pub struct ZerocheckTestCols2<T> {
        op_a: T,
        op_b: T,
        op_c: T,
        op_d: T,
    }

    impl<F> BaseAir<F> for ZerocheckTestChip2 {
        fn width(&self) -> usize {
            NUM_ZEROCHECK_TEST2_COLS
        }
    }

    impl<'a> BlockAir<SymbolicProverFolder<'a>> for ZerocheckTestChip2 {
        fn num_blocks(&self) -> usize {
            2
        }

        fn eval_block(&self, builder: &mut SymbolicProverFolder, index: usize) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &ZerocheckTestCols2<SymbolicVarF> = (*local).borrow();

            match index {
                0 => {
                    builder.assert_zero(
                        local.op_a + SymbolicExprF::from_canonical_u32(5) * local.op_b
                            - (local.op_b + local.op_c + SymbolicExprF::two())
                                * (local.op_b
                                    + SymbolicExprF::from_canonical_u32(3) * local.op_c
                                    + SymbolicExprF::one())
                                * (local.op_b - local.op_c + SymbolicExprF::from_canonical_u32(10)),
                    );
                }
                1 => {
                    builder.assert_zero(
                        (local.op_d + SymbolicExprF::one())
                            * (local.op_d - SymbolicExprF::one())
                            * (local.op_d - SymbolicExprF::two()),
                    );

                    builder.assert_zero(
                        local.op_b
                            - local.op_c * local.op_d * SymbolicExprF::from_canonical_u32(5)
                            - SymbolicExprF::from_canonical_u32(8)
                                * local.op_d
                                * local.op_d
                                * local.op_d
                            - SymbolicExprF::one(),
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    impl<F: PrimeField32> MachineAir<F> for ZerocheckTestChip2 {
        type Record = ExecutionRecord;
        type Program = Program;

        fn name(&self) -> &'static str {
            "ZerocheckTest2"
        }

        fn num_rows(&self, _: &Self::Record) -> Option<usize> {
            unimplemented!();
        }

        fn generate_trace(
            &self,
            _: &ExecutionRecord,
            _: &mut ExecutionRecord,
        ) -> RowMajorMatrix<F> {
            unimplemented!();
        }

        fn generate_trace_into(
            &self,
            _: &Self::Record,
            _: &mut Self::Record,
            _: &mut [std::mem::MaybeUninit<F>],
        ) {
            unimplemented!();
        }

        fn included(&self, _: &Self::Record) -> bool {
            true
        }
    }

    impl<AB> Air<AB> for ZerocheckTestChip2
    where
        AB: SP1AirBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &ZerocheckTestCols2<AB::Var> = (*local).borrow();

            builder.assert_zero(
                local.op_a + AB::Expr::from_canonical_u32(5) * local.op_b
                    - (local.op_b + local.op_c + AB::Expr::two())
                        * (local.op_b
                            + AB::Expr::from_canonical_u32(3) * local.op_c
                            + AB::Expr::one())
                        * (local.op_b - local.op_c + AB::Expr::from_canonical_u32(10)),
            );

            builder.assert_zero(
                (local.op_d + AB::Expr::one())
                    * (local.op_d - AB::Expr::one())
                    * (local.op_d - AB::Expr::two()),
            );

            builder.assert_zero(
                local.op_b
                    - local.op_c * local.op_d * AB::Expr::from_canonical_u32(5)
                    - AB::Expr::from_canonical_u32(8) * local.op_d * local.op_d * local.op_d
                    - AB::Expr::one(),
            );
        }
    }

    #[derive(Default, Clone)]
    pub struct ZerocheckTestChip3;

    impl std::fmt::Debug for ZerocheckTestChip3 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ZerocheckTestChip3")
        }
    }

    // The number of prep trace columns for `ZerocheckTestChip3`.
    pub const NUM_ZEROCHECK_TEST3_PREP_COLS: usize = size_of::<ZerocheckTestPrepCols3<u8>>();
    /// The number of main trace columns for `ZerocheckTestChip3`.
    pub const NUM_ZEROCHECK_TEST3_COLS: usize = size_of::<ZerocheckTestCols3<u8>>();

    /// The column layout for the chip.
    #[derive(AlignedBorrow, Default, Clone, Copy)]
    #[repr(C)]
    pub struct ZerocheckTestPrepCols3<T> {
        prep_a: T,
        prep_b: T,
    }

    /// The column layout for the chip.
    #[derive(AlignedBorrow, Default, Clone, Copy)]
    #[repr(C)]
    pub struct ZerocheckTestCols3<T> {
        op_a: T,
        op_b: T,
        op_c: T,
    }

    impl<F> BaseAir<F> for ZerocheckTestChip3 {
        fn width(&self) -> usize {
            NUM_ZEROCHECK_TEST3_COLS
        }
    }

    impl<'a> BlockAir<SymbolicProverFolder<'a>> for ZerocheckTestChip3 {
        fn num_blocks(&self) -> usize {
            3
        }

        fn eval_block(&self, builder: &mut SymbolicProverFolder, index: usize) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &ZerocheckTestCols3<SymbolicVarF> = (*local).borrow();

            let prep = builder.preprocessed();
            let prep = prep.row_slice(0);
            let prep: &ZerocheckTestPrepCols3<SymbolicVarF> = (*prep).borrow();

            let pv = builder.public_values();
            let pv_0 = pv[0];
            let pv_1 = pv[1];

            match index {
                0 => {
                    builder.assert_zero(
                        prep.prep_a
                            - (local.op_a * local.op_a * local.op_b
                                + SymbolicExprF::one()
                                + SymbolicExprF::from_canonical_u32(3) * pv_0 * local.op_c),
                    );
                }
                1 => {
                    builder.assert_zero(
                        prep.prep_b
                            - (SymbolicExprF::from_canonical_u32(8) * prep.prep_a * local.op_c
                                + pv_0 * local.op_a * local.op_b
                                + SymbolicExprF::from_canonical_u32(17)),
                    );
                }
                2 => {
                    builder.assert_zero(
                        local.op_a
                            - (local.op_b * local.op_c * SymbolicExprF::from_canonical_u32(8)
                                + local.op_b * local.op_b * local.op_b
                                + local.op_c * local.op_c * local.op_c
                                + SymbolicExprF::from_canonical_u32(178)
                                + pv_1),
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    impl<F: PrimeField32> MachineAir<F> for ZerocheckTestChip3 {
        type Record = ExecutionRecord;
        type Program = Program;

        fn name(&self) -> &'static str {
            "ZerocheckTest3"
        }

        fn preprocessed_width(&self) -> usize {
            NUM_ZEROCHECK_TEST3_PREP_COLS
        }

        fn num_rows(&self, _: &Self::Record) -> Option<usize> {
            unimplemented!();
        }

        fn generate_trace(
            &self,
            _: &ExecutionRecord,
            _: &mut ExecutionRecord,
        ) -> RowMajorMatrix<F> {
            unimplemented!();
        }

        fn generate_trace_into(
            &self,
            _: &Self::Record,
            _: &mut Self::Record,
            _: &mut [std::mem::MaybeUninit<F>],
        ) {
            unimplemented!();
        }

        fn included(&self, _: &Self::Record) -> bool {
            true
        }
    }

    impl<AB> Air<AB> for ZerocheckTestChip3
    where
        AB: SP1AirBuilder + PairBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &ZerocheckTestCols3<AB::Var> = (*local).borrow();

            let prep = builder.preprocessed();
            let prep = prep.row_slice(0);
            let prep: &ZerocheckTestPrepCols3<AB::Var> = (*prep).borrow();

            let pv = builder.public_values();
            let pv_0 = pv[0];
            let pv_1 = pv[1];

            builder.assert_zero(
                prep.prep_a
                    - (local.op_a * local.op_a * local.op_b
                        + AB::Expr::one()
                        + AB::Expr::from_canonical_u32(3) * pv_0.into() * local.op_c),
            );

            builder.assert_zero(
                prep.prep_b
                    - (AB::Expr::from_canonical_u32(8) * prep.prep_a * local.op_c
                        + pv_0.into() * local.op_a * local.op_b
                        + AB::Expr::from_canonical_u32(17)),
            );

            builder.assert_zero(
                local.op_a
                    - (local.op_b * local.op_c * AB::Expr::from_canonical_u32(8)
                        + local.op_b * local.op_b * local.op_b
                        + local.op_c * local.op_c * local.op_c
                        + AB::Expr::from_canonical_u32(178)
                        + pv_1.into()),
            )
        }
    }

    pub fn compute_padded_row_adjustment<A>(
        chip: &Chip<Felt, A>,
        alpha: Ext,
        public_values: &[Felt],
    ) -> Ext
    where
        A: MachineAir<Felt> + for<'a> Air<VerifierConstraintFolder<'a, Felt, Ext>>,
    {
        let dummy_preprocessed_trace = vec![Ext::zero(); chip.preprocessed_width()];
        let dummy_main_trace = vec![Ext::zero(); chip.width()];

        let mut folder = VerifierConstraintFolder::<Felt, Ext> {
            preprocessed: RowMajorMatrixView::new_row(&dummy_preprocessed_trace),
            main: RowMajorMatrixView::new_row(&dummy_main_trace),
            alpha,
            accumulator: Ext::zero(),
            public_values,
            _marker: PhantomData,
        };

        chip.eval(&mut folder);

        folder.accumulator
    }

    /// Evaluates the constraints for a chip and opening.
    pub fn eval_constraints<A>(
        chip: &Chip<Felt, A>,
        opening: &ChipOpenedValues<Felt, Ext>,
        alpha: Ext,
        public_values: &[Felt],
    ) -> Ext
    where
        A: MachineAir<Felt> + for<'a> Air<VerifierConstraintFolder<'a, Felt, Ext>>,
    {
        let mut folder = VerifierConstraintFolder::<Felt, Ext> {
            preprocessed: RowMajorMatrixView::new_row(&opening.preprocessed.local),
            main: RowMajorMatrixView::new_row(&opening.main.local),
            alpha,
            accumulator: Ext::zero(),
            public_values,
            _marker: PhantomData,
        };

        chip.eval(&mut folder);

        folder.accumulator
    }

    fn verify_opening_shape<A>(chip: &Chip<Felt, A>, opening: &ChipOpenedValues<Felt, Ext>)
    where
        A: MachineAir<Felt>,
    {
        // Verify that the preprocessed width matches the expected value for the chip.
        assert_eq!(
            opening.preprocessed.local.len(),
            chip.preprocessed_width(),
            "preprocessed width mismatch"
        );

        // Verify that the main width matches the expected value for the chip.
        assert_eq!(opening.main.local.len(), chip.width(), "main width mismatch");
    }

    pub fn verify_zerocheck<A, C>(
        shard_chips: &BTreeSet<Chip<Felt, A>>,
        opened_values: &ShardOpenedValues<Felt, Ext>,
        gkr_evaluations: &LogUpEvaluations<Ext>,
        zerocheck_proof: PartialSumcheckProof<Ext>,
        public_values: &[Felt],
        challenger: &mut C,
        max_log_row_count: usize,
    ) where
        A: MachineAir<Felt> + ZerocheckAir<Felt, Ext> + for<'a> BlockAir<SymbolicProverFolder<'a>>,
        C: FieldChallenger<Felt>,
    {
        // Get the random challenge to merge the constraints.
        let alpha = challenger.sample_ext_element::<Ext>();

        let gkr_batch_open_challenge = challenger.sample_ext_element::<Ext>();

        // Get the random lambda to RLC the zerocheck polynomials.
        let lambda = challenger.sample_ext_element::<Ext>();

        assert_eq!(gkr_evaluations.point.dimension(), max_log_row_count);
        assert_eq!(zerocheck_proof.point_and_eval.0.dimension(), max_log_row_count);

        // Get the value of eq(zeta, sumcheck's reduced point).
        let zerocheck_eq_val =
            Mle::full_lagrange_eval(&gkr_evaluations.point, &zerocheck_proof.point_and_eval.0);
        let zerocheck_eq_vals = vec![zerocheck_eq_val; shard_chips.len()];

        // To verify the constraints, we need to check that the RLC'ed reduced eval in the zerocheck
        // proof is correct.
        let mut rlc_eval = Ext::zero();
        for ((chip, (_, openings)), zerocheck_eq_val) in
            shard_chips.iter().zip_eq(opened_values.chips.iter()).zip_eq(zerocheck_eq_vals)
        {
            // Verify the shape of the opening arguments matches the expected values.
            verify_opening_shape(chip, openings);

            let mut point_extended = zerocheck_proof.point_and_eval.0.clone();
            point_extended.add_dimension(Ext::zero());
            for &x in openings.degree.iter() {
                assert_eq!(x * (x - Felt::one()), Felt::zero(), "degree not boolean point");
            }
            for &x in openings.degree.iter().skip(1) {
                assert_eq!(
                    x * *openings.degree.first().unwrap(),
                    Felt::zero(),
                    "degree > 2^max_log_row_count"
                );
            }

            let geq_val = full_geq(&openings.degree, &point_extended);

            let padded_row_adjustment = compute_padded_row_adjustment(chip, alpha, public_values);

            let constraint_eval = eval_constraints(chip, openings, alpha, public_values)
                - padded_row_adjustment * geq_val;

            let openings_batch = openings
                .main
                .local
                .iter()
                .chain(openings.preprocessed.local.iter())
                .copied()
                .zip(gkr_batch_open_challenge.powers().skip(1))
                .map(|(opening, power)| opening * power)
                .sum::<Ext>();

            // Horner's method.
            rlc_eval = rlc_eval * lambda + zerocheck_eq_val * (constraint_eval + openings_batch);
        }

        assert_eq!(
            zerocheck_proof.point_and_eval.1, rlc_eval,
            "expected final evaluation different"
        );

        let zerocheck_sum_modifications_from_gkr = gkr_evaluations
            .chip_openings
            .values()
            .map(|chip_evaluation| {
                chip_evaluation
                    .main_trace_evaluations
                    .deref()
                    .iter()
                    .copied()
                    .chain(
                        chip_evaluation
                            .preprocessed_trace_evaluations
                            .as_ref()
                            .iter()
                            .flat_map(|&evals| evals.deref().iter().copied()),
                    )
                    .zip(gkr_batch_open_challenge.powers().skip(1))
                    .map(|(opening, power)| opening * power)
                    .sum::<Ext>()
            })
            .collect::<Vec<_>>();

        let zerocheck_sum_modification = zerocheck_sum_modifications_from_gkr
            .iter()
            .fold(Ext::zero(), |acc, modification| lambda * acc + *modification);

        assert_eq!(
            zerocheck_proof.claimed_sum, zerocheck_sum_modification,
            "claimed sum different"
        );

        // Verify the zerocheck proof.
        partially_verify_sumcheck_proof(&zerocheck_proof, challenger, max_log_row_count, 4)
            .unwrap();

        // Observe the openings
        for (_, opening) in opened_values.chips.iter() {
            challenger.observe_variable_length_extension_slice(&opening.preprocessed.local);
            challenger.observe_variable_length_extension_slice(&opening.main.local);
        }
    }

    fn get_input_sizes() -> Vec<u32> {
        vec![1456088, 1665180, 1558084]
    }

    fn generate_random_row<R: Rng>(
        chip_idx: usize,
        rng: &mut R,
        public_values: &[Felt],
    ) -> (Vec<Felt>, Vec<Felt>) {
        match chip_idx {
            0 => {
                let b = random_felt(rng);
                let c = random_felt(rng);
                let a = (b + c + Felt::one())
                    * (b + c + Felt::two())
                    * (b - c + Felt::from_canonical_u32(8))
                    - b * Felt::from_canonical_u32(3);
                let d = Felt::from_canonical_u32(rng.next_u32() % 3);
                (vec![], vec![a, b, c, d])
            }
            1 => {
                let idx = rng.next_u32() % 3;
                let d = match idx {
                    0 => Felt::from_canonical_u32(SP1Field::ORDER_U32 - 1),
                    1 => Felt::from_canonical_u32(1),
                    2 => Felt::from_canonical_u32(2),
                    _ => panic!(),
                };
                let c = random_felt(rng);
                let b = c * d * Felt::from_canonical_u32(5)
                    + Felt::from_canonical_u32(8) * d * d * d
                    + Felt::one();

                let a = (b + c + Felt::two())
                    * (b + Felt::from_canonical_u32(3) * c + Felt::one())
                    * (b - c + Felt::from_canonical_u32(10))
                    - Felt::from_canonical_u32(5) * b;

                (vec![], vec![a, b, c, d])
            }
            2 => {
                let b = random_felt(rng);
                let c = random_felt(rng);
                let a = b * c * Felt::from_canonical_u32(8)
                    + b * b * b
                    + c * c * c
                    + Felt::from_canonical_u32(178)
                    + public_values[1];
                let prep_a = a * a * b
                    + Felt::from_canonical_u32(1)
                    + Felt::from_canonical_u32(3) * public_values[0] * c;
                let prep_b = Felt::from_canonical_u32(8) * prep_a * c
                    + public_values[0] * a * b
                    + Felt::from_canonical_u32(17);
                (vec![prep_a, prep_b], vec![a, b, c])
            }
            _ => unimplemented!(),
        }
    }

    fn random_felt<R: Rng>(rng: &mut R) -> Felt {
        Felt::from_wrapped_u32(rng.next_u32())
    }

    fn constraint_eval(
        chip_idx: usize,
        prep_row: Vec<Felt>,
        row: Vec<Felt>,
        public_values: Vec<Felt>,
    ) -> Vec<Felt> {
        match chip_idx {
            0 => {
                assert_eq!(prep_row.len(), 0);
                assert_eq!(row.len(), 4);
                let a = row[0];
                let b = row[1];
                let c = row[2];
                let d = row[3];
                let val1 = a + b * Felt::from_canonical_u32(3)
                    - (b + c + Felt::one())
                        * (b + c + Felt::two())
                        * (b - c + Felt::from_canonical_u32(8));
                let val2 = d * (d - Felt::one()) * (d - Felt::two());
                vec![val1, val2]
            }
            1 => {
                assert_eq!(prep_row.len(), 0);
                assert_eq!(row.len(), 4);
                let a = row[0];
                let b = row[1];
                let c = row[2];
                let d = row[3];
                let val1 = a + b * Felt::from_canonical_u32(5)
                    - (b + c + Felt::two())
                        * (b + Felt::from_canonical_u32(3) * c + Felt::one())
                        * (b - c + Felt::from_canonical_u32(10));
                let val2 = (d + Felt::one()) * (d - Felt::one()) * (d - Felt::two());
                let val3 = b
                    - c * d * Felt::from_canonical_u32(5)
                    - Felt::from_canonical_u32(8) * d * d * d
                    - Felt::one();
                vec![val1, val2, val3]
            }
            2 => {
                assert_eq!(prep_row.len(), 2);
                assert_eq!(row.len(), 3);
                let prep_a = prep_row[0];
                let prep_b = prep_row[1];
                let a = row[0];
                let b = row[1];
                let c = row[2];
                let val1 = prep_a
                    - (a * a * b
                        + Felt::one()
                        + Felt::from_canonical_u32(3) * public_values[0] * c);
                let val2 = prep_b
                    - (Felt::from_canonical_u32(8) * prep_a * c
                        + public_values[0] * a * b
                        + Felt::from_canonical_u32(17));
                let val3 = a
                    - (b * c * Felt::from_canonical_u32(8)
                        + b * b * b
                        + c * c * c
                        + Felt::from_canonical_u32(178)
                        + public_values[1]);
                vec![val1, val2, val3]
            }
            _ => unimplemented!(),
        }
    }

    fn get_input<A>(
        sizes: &[u32],
        chips_vec: &[Chip<Felt, A>],
        public_values: &[Felt],
    ) -> JaggedTraceMle<Felt, CpuBackend>
    where
        A: for<'a> BlockAir<SymbolicProverFolder<'a>>,
    {
        let mut rng = rand::thread_rng();
        let total_main =
            sizes.iter().enumerate().map(|(a, b)| b * (chips_vec[a].width() as u32)).sum::<u32>();
        let total_preprocessed = sizes
            .iter()
            .enumerate()
            .map(|(a, b)| b * (chips_vec[a].preprocessed_width() as u32))
            .sum::<u32>();

        let padded_preprocessed = total_preprocessed.next_multiple_of(1 << 21);
        let sum_length = padded_preprocessed + total_main;

        let mut preprocessed_table_index: BTreeMap<_, TraceOffset> = BTreeMap::new();
        let mut main_table_index: BTreeMap<_, TraceOffset> = BTreeMap::new();

        let mut data = vec![SP1Field::zero(); sum_length as usize];
        let mut preprocessed_ptr = 0;
        let mut main_ptr = padded_preprocessed;
        for (i, row) in sizes.iter().enumerate() {
            for j in 0..*row {
                let (prep_row, main_row) = generate_random_row(i, &mut rng, public_values);
                for k in 0..prep_row.len() {
                    data[(preprocessed_ptr + j + row * k as u32) as usize] = prep_row[k];
                }
                for k in 0..main_row.len() {
                    data[(main_ptr + j + row * k as u32) as usize] = main_row[k];
                }
            }
            preprocessed_table_index.insert(
                chips_vec[i].air.name().to_string(),
                TraceOffset {
                    dense_offset: preprocessed_ptr as usize
                        ..(preprocessed_ptr + row * chips_vec[i].preprocessed_width() as u32)
                            as usize,
                    poly_size: *row as usize,
                    num_polys: chips_vec[i].preprocessed_width(),
                },
            );
            preprocessed_ptr += row * chips_vec[i].preprocessed_width() as u32;
            main_table_index.insert(
                chips_vec[i].air.name().to_string(),
                TraceOffset {
                    dense_offset: main_ptr as usize
                        ..(main_ptr + row * chips_vec[i].width() as u32) as usize,
                    poly_size: *row as usize,
                    num_polys: chips_vec[i].width(),
                },
            );
            main_ptr += row * chips_vec[i].width() as u32;
        }
        assert_eq!(preprocessed_ptr, total_preprocessed);
        assert_eq!(main_ptr, sum_length);

        let mut cols = vec![0; (sum_length / 2) as usize];
        let num_cols = chips_vec
            .iter()
            .map(|chip| (chip.preprocessed_width() + chip.width()) as u32)
            .sum::<u32>()
            + 1;
        let mut start_idx = vec![0u32; (num_cols + 1) as usize];
        let mut col_idx: u32 = 0;
        let mut cnt: usize = 0;
        let mut heights: Vec<u32> = Vec::new();
        for (i, chip) in chips_vec.iter().enumerate() {
            let row = sizes[i];
            let col = chip.preprocessed_width() as u32;
            assert_eq!(row % 4, 0);
            for _ in 0..col {
                cols[cnt..cnt + (row as usize / 2)].fill(col_idx);
                cnt += row as usize / 2;
                start_idx[(col_idx + 1) as usize] = start_idx[col_idx as usize] + row / 2;
                col_idx += 1;
                heights.push(row / 2);
            }
        }
        cols[cnt..(padded_preprocessed / 2) as usize].fill(col_idx);
        start_idx[(col_idx + 1) as usize] = padded_preprocessed / 2;
        col_idx += 1;
        heights.push(padded_preprocessed / 2 - cnt as u32);
        cnt = (padded_preprocessed / 2) as usize;
        let total_preprocessed_cols = col_idx;

        for (i, chip) in chips_vec.iter().enumerate() {
            let row = sizes[i];
            let col = chip.width() as u32;
            assert_eq!(row % 4, 0);
            for _ in 0..col {
                cols[cnt..cnt + (row as usize / 2)].fill(col_idx);
                cnt += row as usize / 2;
                start_idx[(col_idx + 1) as usize] = start_idx[col_idx as usize] + row / 2;
                col_idx += 1;
                heights.push(row / 2);
            }
        }
        assert_eq!(col_idx, num_cols);

        // Main padding and preprocessed padding are only needed in commit. Set them to zero for this unit test.
        JaggedTraceMle::new(
            TraceDenseData {
                dense: Buffer::from(data),
                preprocessed_offset: padded_preprocessed as usize,
                preprocessed_cols: total_preprocessed_cols as usize,
                preprocessed_table_index,
                main_table_index,
                main_padding: 0,
                preprocessed_padding: 0,
            },
            Buffer::from(cols),
            Buffer::from(start_idx),
            heights,
        )
    }

    #[test]
    fn test_row_constraint() {
        const NUM_CHIPS: usize = 3;
        let mut rng = rand::thread_rng();
        for i in 0..NUM_CHIPS {
            for _ in 0..(1 << 16) {
                let public_values = vec![random_felt(&mut rng), random_felt(&mut rng)];
                let (prep_row, main_row) = generate_random_row(i, &mut rng, &public_values);
                let result = constraint_eval(i, prep_row, main_row, public_values);
                for v in result {
                    assert_eq!(v, Felt::zero());
                }
            }
        }
    }

    #[test]
    #[serial]
    fn test_zerocheck() {
        let mut chips: BTreeSet<Chip<Felt, _>> = BTreeSet::new();
        chips.insert(Chip::new(ZerocheckTestChip::Chip1(ZerocheckTestChip1)));
        chips.insert(Chip::new(ZerocheckTestChip::Chip2(ZerocheckTestChip2)));
        chips.insert(Chip::new(ZerocheckTestChip::Chip3(ZerocheckTestChip3)));

        let mut cache = BTreeMap::new();
        for chip in chips.iter() {
            let result = codegen_cuda_eval(chip.air.as_ref());
            cache.insert(chip.name().to_string(), result);
        }

        let chips_vec = chips.iter().cloned().collect::<Vec<_>>();
        let num_chips = chips_vec.len();
        let row_variables = 22;
        run_sync_in_place(move |t| {
            let input_size = get_input_sizes();
            let mut rng = rand::thread_rng();
            let public_values = vec![random_felt(&mut rng), random_felt(&mut rng)];

            let trace_mle = get_input(&input_size, &chips_vec, &public_values);
            let trace_mle = Arc::new(trace_mle.into_device(&t));
            let initial_heights = input_size.clone();

            let mut challenger = TestGC::default_challenger();
            let _lambda: Ext = challenger.sample();

            let alpha = challenger.sample();
            let beta = challenger.sample();
            let lambda: Ext = challenger.sample();

            let max_num_constraints =
                itertools::max(chips.iter().map(|chip| chip.num_constraints)).unwrap();
            let mut powers_of_alpha = vec![Ext::one(); max_num_constraints];
            for i in 1..max_num_constraints {
                powers_of_alpha[i] = powers_of_alpha[i - 1] * alpha;
            }
            powers_of_alpha.reverse();

            let mut gkr_powers = vec![Ext::zero(); 1024];
            gkr_powers[0] = beta;
            for i in 1..1024 {
                gkr_powers[i] = gkr_powers[i - 1] * beta;
            }

            let mut powers_of_lambda = vec![Ext::one(); num_chips];
            for i in 1..num_chips {
                powers_of_lambda[i] = powers_of_lambda[i - 1] * lambda;
            }
            powers_of_lambda.reverse();

            let mut padded_row_adjustment = vec![Ext::zero(); num_chips];

            for i in 0..num_chips {
                let prep_len = chips_vec[i].preprocessed_width();
                let main_len = chips_vec[i].width();
                let prep_zero = vec![Felt::zero(); prep_len];
                let main_zero = vec![Felt::zero(); main_len];
                let mut folder = ConstraintSumcheckFolder {
                    preprocessed: RowMajorMatrixView::new_row(&prep_zero),
                    main: RowMajorMatrixView::new_row(&main_zero),
                    accumulator: Ext::zero(),
                    public_values: &public_values,
                    constraint_index: 0,
                    powers_of_alpha: &powers_of_alpha
                        [powers_of_alpha.len() - chips_vec[i].num_constraints..],
                };
                chips_vec[i].air.eval(&mut folder);
                padded_row_adjustment[i] = folder.accumulator;
            }

            let zeta = Point::<Ext>::rand(&mut rng, row_variables);
            let individual_column_evals = evaluate_jagged_columns(&trace_mle, zeta.clone());
            let mut claim = Ext::zero();
            let mut preprocessed_ptr: usize = 0;
            let mut main_ptr = chips_vec.iter().map(|x| x.preprocessed_width()).sum::<usize>() + 1;

            for chip in chips_vec.iter() {
                let preprocessed_width = chip.preprocessed_width();
                let main_width = chip.width();
                claim *= lambda;
                for idx in 0..preprocessed_width {
                    claim += gkr_powers[main_width + idx]
                        * individual_column_evals[preprocessed_ptr + idx];
                }
                for idx in 0..main_width {
                    claim += gkr_powers[idx] * individual_column_evals[main_ptr + idx];
                }
                preprocessed_ptr += preprocessed_width;
                main_ptr += main_width;
            }

            let main_poly = initialize_zerocheck_poly(
                trace_mle.as_ref(),
                &chips,
                &cache,
                initial_heights.clone(),
                public_values.clone(),
                powers_of_alpha.clone(),
                gkr_powers.clone(),
                powers_of_lambda.clone(),
                padded_row_adjustment.clone(),
                zeta.clone(),
                claim,
            );

            let mut jagged_point = vec![];
            let mut result = evaluate_zerocheck(&main_poly);
            let (mut point, mut claim) = challenger_update(&result, &mut challenger);
            jagged_point.insert(0, point);
            let mut next_poly = zerocheck_fix_last_variable(main_poly, point, claim);
            for _ in 0..21 {
                result = evaluate_zerocheck(&next_poly);
                (point, claim) = challenger_update(&result, &mut challenger);
                jagged_point.insert(0, point);
                next_poly = zerocheck_fix_last_variable(next_poly, point, claim);
            }
            let result = unsafe { next_poly.data.as_ref().dense_data.dense.copy_into_host_vec() };
            let mut idx = 0;
            let data_input_heights = &trace_mle.column_heights;
            let mut individual_column_evals = vec![Ext::zero(); data_input_heights.len()];
            for i in 0..data_input_heights.len() {
                if data_input_heights[i] != 0 {
                    individual_column_evals[i] = result[idx];
                    idx += 4;
                }
            }

            let mut jagged_point = Point::from(jagged_point);

            let mut expected_final_claim = Ext::zero();
            let mut preprocessed_ptr: usize = 0;
            let mut main_ptr = chips_vec.iter().map(|x| x.preprocessed_width()).sum::<usize>() + 1;

            let eq_mul = Mle::full_lagrange_eval(&zeta, &jagged_point);
            jagged_point.add_dimension(Ext::zero());

            for (i, chip) in chips_vec.iter().enumerate() {
                let preprocessed_width = chip.preprocessed_width();
                let main_width = chip.width();
                expected_final_claim *= lambda;
                for idx in 0..preprocessed_width {
                    expected_final_claim += gkr_powers[main_width + idx]
                        * individual_column_evals[preprocessed_ptr + idx];
                }
                for idx in 0..main_width {
                    expected_final_claim +=
                        gkr_powers[idx] * individual_column_evals[main_ptr + idx];
                }

                let mut folder = VerifierConstraintFolder::<Felt, Ext> {
                    preprocessed: RowMajorMatrixView::new_row(
                        &individual_column_evals
                            [preprocessed_ptr..preprocessed_ptr + preprocessed_width],
                    ),
                    main: RowMajorMatrixView::new_row(
                        &individual_column_evals[main_ptr..main_ptr + main_width],
                    ),
                    alpha,
                    accumulator: Ext::zero(),
                    public_values: &public_values,
                    _marker: PhantomData,
                };
                chip.air.eval(&mut folder);
                expected_final_claim += folder.accumulator;

                expected_final_claim -= padded_row_adjustment[i]
                    * full_geq(
                        &Point::<Felt>::from_usize(
                            initial_heights[i] as usize,
                            row_variables as usize + 1,
                        ),
                        &jagged_point,
                    );
                preprocessed_ptr += preprocessed_width;
                main_ptr += main_width;
            }

            expected_final_claim *= eq_mul;
            assert_eq!(claim, expected_final_claim);

            t.synchronize_blocking().unwrap();
        })
        .unwrap();
    }

    #[test]
    #[serial]
    fn test_zerocheck_function_verify() {
        let mut chips: BTreeSet<Chip<Felt, _>> = BTreeSet::new();
        chips.insert(Chip::new(ZerocheckTestChip::Chip1(ZerocheckTestChip1)));
        chips.insert(Chip::new(ZerocheckTestChip::Chip2(ZerocheckTestChip2)));
        chips.insert(Chip::new(ZerocheckTestChip::Chip3(ZerocheckTestChip3)));

        let mut cache = BTreeMap::new();
        for chip in chips.iter() {
            let result = codegen_cuda_eval(chip.air.as_ref());
            cache.insert(chip.name().to_string(), result);
        }
        let chips_vec = chips.iter().cloned().collect::<Vec<_>>();
        let row_variables = 22;
        run_sync_in_place(move |t| {
            let input_size = get_input_sizes();
            let mut rng = rand::thread_rng();
            let public_values = vec![random_felt(&mut rng), random_felt(&mut rng)];

            let trace_mle = get_input(&input_size, &chips_vec, &public_values);
            let trace_mle = Arc::new(trace_mle.into_device(&t));

            let mut challenger = TestGC::default_challenger();
            challenger.observe(Felt::from_canonical_u32(0x2013));
            challenger.observe(Felt::from_canonical_u32(0x2015));
            challenger.observe(Felt::from_canonical_u32(0x2016));
            challenger.observe(Felt::from_canonical_u32(0x2023));
            challenger.observe(Felt::from_canonical_u32(0x2024));

            let _lambda: Ext = challenger.sample();

            let mut challenger_prover = challenger.clone();
            let batching_challenge = challenger_prover.sample_ext_element();
            let gkr_opening_batch_randomness = challenger_prover.sample_ext_element();
            let max_log_row_count = row_variables as usize;

            let zeta = Point::<Ext>::rand(&mut rng, row_variables);
            let individual_column_evals = evaluate_jagged_columns(&trace_mle, zeta.clone());

            let mut preprocessed_ptr: usize = 0;
            let mut main_ptr = chips_vec.iter().map(|x| x.preprocessed_width()).sum::<usize>() + 1;

            let mut chip_openings: BTreeMap<String, ChipEvaluation<Ext>> = BTreeMap::new();
            for chip in chips_vec.iter() {
                let preprocessed_width = chip.preprocessed_width();
                let main_width = chip.width();

                let chip_eval = ChipEvaluation {
                    preprocessed_trace_evaluations: match preprocessed_width {
                        0 => None,
                        _ => Some(MleEval::new(Tensor::from(
                            individual_column_evals
                                [preprocessed_ptr..preprocessed_ptr + preprocessed_width]
                                .to_vec(),
                        ))),
                    },
                    main_trace_evaluations: MleEval::new(Tensor::from(
                        individual_column_evals[main_ptr..main_ptr + main_width].to_vec(),
                    )),
                };

                chip_openings.insert(
                    <ZerocheckTestChip as sp1_hypercube::air::MachineAir<SP1Field>>::name(
                        &chip.air,
                    )
                    .to_string(),
                    chip_eval,
                );
                preprocessed_ptr += preprocessed_width;
                main_ptr += main_width;
            }

            let logup_evaluations = LogUpEvaluations { point: zeta, chip_openings };

            let (opened_values, zerocheck_proof) = zerocheck(
                &chips,
                &cache,
                trace_mle.as_ref(),
                batching_challenge,
                gkr_opening_batch_randomness,
                &logup_evaluations,
                public_values.clone(),
                &mut challenger_prover,
                max_log_row_count as u32,
            );

            let mut challenger_verifier = challenger.clone();
            crate::tests::verify_zerocheck(
                &chips,
                &opened_values,
                &logup_evaluations,
                zerocheck_proof,
                &public_values,
                &mut challenger_verifier,
                max_log_row_count,
            );
        })
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_zerocheck_real_traces() {
        let (machine, record, program) =
            tracegen_setup::setup(&test_artifacts::FIBONACCI_ELF, SP1Stdin::new()).await;

        run_in_place(|t| async move {
            let mut rng = rand::thread_rng();

            let capacity = CORE_MAX_TRACE_SIZE as usize;
            let buffer = PinnedBuffer::<Felt>::with_capacity(capacity);
            let queue = Arc::new(WorkerQueue::new(vec![buffer]));
            let buffer = queue.pop().await.unwrap();

            let (public_values, trace_mle, chips, _permit) = full_tracegen(
                &machine,
                program.clone(),
                Arc::new(record),
                &buffer,
                CORE_MAX_TRACE_SIZE as usize,
                LOG_STACKING_HEIGHT,
                CORE_MAX_LOG_ROW_COUNT,
                &t,
                ProverSemaphore::new(1),
                true,
            )
            .await;
            let chips = machine.smallest_cluster(&chips).unwrap();
            let mut cache = BTreeMap::new();
            for chip in chips.iter() {
                let result = codegen_cuda_eval(chip.air.as_ref());
                cache.insert(chip.name().to_string(), result);
            }

            let trace_mle = Arc::new(trace_mle);

            let mut challenger = TestGC::default_challenger();
            challenger.observe(Felt::from_canonical_u32(0x2013));
            challenger.observe(Felt::from_canonical_u32(0x2015));
            challenger.observe(Felt::from_canonical_u32(0x2016));
            challenger.observe(Felt::from_canonical_u32(0x2023));
            challenger.observe(Felt::from_canonical_u32(0x2024));

            let _lambda: Ext = challenger.sample();

            let mut challenger_prover = challenger.clone();
            let batching_challenge = challenger_prover.sample_ext_element();
            let gkr_opening_batch_randomness = challenger_prover.sample_ext_element();
            let max_log_row_count = CORE_MAX_LOG_ROW_COUNT;

            let zeta = Point::<Ext>::rand(&mut rng, CORE_MAX_LOG_ROW_COUNT);
            let individual_column_evals = evaluate_jagged_columns(&trace_mle, zeta.clone());

            let mut preprocessed_ptr: usize = 0;
            let mut main_ptr = chips.iter().map(|x| x.preprocessed_width()).sum::<usize>() + 1;

            let mut chip_openings: BTreeMap<String, ChipEvaluation<Ext>> = BTreeMap::new();
            for chip in chips.iter() {
                let preprocessed_width = chip.preprocessed_width();
                let main_width = chip.width();

                let chip_eval = ChipEvaluation {
                    preprocessed_trace_evaluations: match preprocessed_width {
                        0 => None,
                        _ => Some(MleEval::new(Tensor::from(
                            individual_column_evals
                                [preprocessed_ptr..preprocessed_ptr + preprocessed_width]
                                .to_vec(),
                        ))),
                    },
                    main_trace_evaluations: MleEval::new(Tensor::from(
                        individual_column_evals[main_ptr..main_ptr + main_width].to_vec(),
                    )),
                };

                chip_openings.insert(chip.air.name().to_string(), chip_eval);
                preprocessed_ptr += preprocessed_width;
                main_ptr += main_width;
            }

            let logup_evaluations = LogUpEvaluations { point: zeta, chip_openings };

            let (opened_values, zerocheck_proof) = zerocheck(
                chips,
                &cache,
                trace_mle.as_ref(),
                batching_challenge,
                gkr_opening_batch_randomness,
                &logup_evaluations,
                public_values.clone(),
                &mut challenger_prover,
                max_log_row_count,
            );

            let mut challenger_verifier = challenger.clone();
            crate::tests::verify_zerocheck(
                chips,
                &opened_values,
                &logup_evaluations,
                zerocheck_proof,
                &public_values,
                &mut challenger_verifier,
                max_log_row_count as usize,
            );
        })
        .await;
    }
}
