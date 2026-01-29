use sp1_gpu_air::{air_block::BlockAir, codegen_cuda_eval, SymbolicProverFolder};
use slop_air::Air;
use slop_algebra::{
    extension::BinomialExtensionField, AbstractExtensionField, ExtensionField, Field,
};
use slop_alloc::{Buffer, IntoHost};
use slop_koala_bear::KoalaBear;
use slop_multilinear::{Mle, PaddedMle};
use slop_tensor::{ReduceSumBackend, Tensor};
use sp1_hypercube::{
    air::MachineAir,
    prover::{ZerocheckProverData, ZerocheckRoundProver},
    ConstraintSumcheckFolder,
};
use std::{
    collections::BTreeMap,
    marker::PhantomData,
    ops::{Add, Mul, Range, Sub},
    sync::Arc,
};

use crate::{EvalProgram, InterpolateRowKernel};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceTensor, TaskScope};

use super::ConstraintPolyEvalKernel;

const EVAL_BLOCK_SIZE: usize = 256;
const EVAL_STRIDE: usize = 1;
const MAX_EVAL_INTERPOLATED_ROWS: usize = 256 * EVAL_BLOCK_SIZE * EVAL_STRIDE;

pub struct ZerocheckEvalProgramProverData<F, EF, A> {
    pub eval_programs: BTreeMap<String, Arc<EvalProgram<F, EF>>>,
    pub allocator: TaskScope,
    _marker: PhantomData<A>,
}

impl<A> ZerocheckEvalProgramProverData<KoalaBear, BinomialExtensionField<KoalaBear, 4>, A>
where
    A: for<'a> BlockAir<SymbolicProverFolder<'a>>,
{
    pub fn new(airs: &[Arc<A>], allocator: TaskScope) -> Self {
        let mut eval_programs = BTreeMap::new();
        for air in airs.iter() {
            let (
                constraint_indices,
                operations,
                operations_indices,
                f_constants,
                f_constants_indices,
                ef_constants,
                ef_constants_indices,
                f_ctr,
                _,
            ) = codegen_cuda_eval(air.as_ref());
            let constraint_indices = Buffer::from(constraint_indices);
            let operations = Buffer::from(operations);
            let operations_indices = Buffer::from(operations_indices);
            let f_constants = Buffer::from(f_constants);
            let f_constants_indices = Buffer::from(f_constants_indices);
            let ef_constants = Buffer::from(ef_constants);
            let ef_constants_indices = Buffer::from(ef_constants_indices);
            let eval_program = Arc::new(EvalProgram {
                constraint_indices,
                operations,
                operations_indices,
                f_ctr,
                f_constants,
                f_constants_indices,
                ef_constants,
                ef_constants_indices,
            });
            eval_programs.insert(air.name().to_owned(), eval_program);
        }
        Self { eval_programs, allocator, _marker: PhantomData }
    }
}

impl<F, EF, A> ZerocheckProverData<F, EF, TaskScope> for ZerocheckEvalProgramProverData<F, EF, A>
where
    F: Field,
    EF: ExtensionField<F>,
    A: for<'b> Air<ConstraintSumcheckFolder<'b, F, F, EF>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, F, EF, EF>>
        + MachineAir<F>,
    TaskScope: InterpolateRowKernel<F>
        + InterpolateRowKernel<EF>
        + ConstraintPolyEvalKernel<F>
        + ConstraintPolyEvalKernel<EF>
        + ReduceSumBackend<EF>,
{
    type Air = A;
    type RoundProver = ZerocheckEvalProgramProver<F, EF, A>;

    fn round_prover(
        &self,
        air: Arc<A>,
        public_values: Arc<Vec<F>>,
        powers_of_alpha: Arc<Vec<EF>>,
        gkr_powers: Arc<Vec<EF>>,
    ) -> Self::RoundProver {
        let eval_program = self.eval_programs.get(air.name()).unwrap().clone();
        let public_values = Arc::new(Buffer::from(public_values.to_vec()));
        let powers_of_alpha = Arc::new(Buffer::from(powers_of_alpha.to_vec()));
        let gkr_powers = Arc::new(Buffer::from(gkr_powers.to_vec()));

        let eval_program_device = Arc::new(eval_program.to_device_sync(&self.allocator).unwrap());
        let public_values_device = Arc::new(DeviceBuffer::from_host(&public_values, &self.allocator).unwrap().into_inner());
        let powers_of_alpha_device = Arc::new(DeviceBuffer::from_host(&powers_of_alpha, &self.allocator).unwrap().into_inner());
        let gkr_powers_device = Arc::new(DeviceBuffer::from_host(&gkr_powers, &self.allocator).unwrap().into_inner());

        ZerocheckEvalProgramProver::new(
            eval_program_device,
            air,
            public_values,
            public_values_device,
            powers_of_alpha,
            powers_of_alpha_device,
            gkr_powers,
            gkr_powers_device,
        )
    }
}

/// A prover that uses the eval program to evaluate the constraint polynomial.
pub struct ZerocheckEvalProgramProver<F, EF, A> {
    eval_program: Arc<EvalProgram<F, EF, TaskScope>>,
    /// The public values.
    public_values: Arc<Buffer<F>>,
    /// The public values on the device.
    public_values_device: Arc<Buffer<F, TaskScope>>,
    /// The powers of alpha.
    powers_of_alpha: Arc<Buffer<EF>>,
    /// The powers of alpha on the device.
    powers_of_alpha_device: Arc<Buffer<EF, TaskScope>>,

    gkr_powers: Arc<Buffer<EF>>,
    gkr_powers_device: Arc<Buffer<EF, TaskScope>>,
    /// The AIR that contains the constraint polynomial.
    air: Arc<A>,
}

impl<F, EF: Clone, A> Clone for ZerocheckEvalProgramProver<F, EF, A> {
    fn clone(&self) -> Self {
        Self {
            eval_program: self.eval_program.clone(),
            public_values: self.public_values.clone(),
            public_values_device: self.public_values_device.clone(),
            powers_of_alpha: self.powers_of_alpha.clone(),
            powers_of_alpha_device: self.powers_of_alpha_device.clone(),
            air: self.air.clone(),
            gkr_powers: self.gkr_powers.clone(),
            gkr_powers_device: self.gkr_powers_device.clone(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
impl<F, EF, A> ZerocheckEvalProgramProver<F, EF, A> {
    pub fn new(
        eval_program: Arc<EvalProgram<F, EF, TaskScope>>,
        air: Arc<A>,
        public_values: Arc<Buffer<F>>,
        public_values_device: Arc<Buffer<F, TaskScope>>,
        powers_of_alpha: Arc<Buffer<EF>>,
        powers_of_alpha_device: Arc<Buffer<EF, TaskScope>>,
        gkr_powers: Arc<Buffer<EF>>,
        gkr_powers_device: Arc<Buffer<EF, TaskScope>>,
    ) -> Self {
        Self {
            eval_program,
            public_values,
            public_values_device,
            powers_of_alpha,
            powers_of_alpha_device,
            air,
            gkr_powers,
            gkr_powers_device,
        }
    }

    fn constraint_poly_eval<
        K: Field + From<F> + Add<F, Output = K> + Sub<F, Output = K> + Mul<F, Output = K>,
    >(
        &self,
        partial_lagrange: &Mle<EF, TaskScope>,
        interpolated_preprocessed_rows: &Option<Tensor<K, TaskScope>>,
        interpolated_main_rows: &Tensor<K, TaskScope>,
        offset: usize,
    ) -> Tensor<EF, TaskScope>
    where
        TaskScope: ConstraintPolyEvalKernel<K>,
        F: Field,
        EF: ExtensionField<F>,
    {
        let EvalProgram {
            constraint_indices,
            operations,
            operations_indices,
            f_ctr,
            f_constants,
            f_constants_indices,
            ef_constants,
            ef_constants_indices,
        } = self.eval_program.as_ref();

        let num_air_blocks = operations_indices.len();
        assert_eq!(num_air_blocks, f_constants_indices.len());
        assert_eq!(num_air_blocks, ef_constants_indices.len());
        let backend = interpolated_main_rows.backend();

        let operations_len = operations.len();
        let main_width = interpolated_main_rows.sizes()[1];
        let interpolated_main_rows_height = interpolated_main_rows.sizes()[2];

        let (grid_size_x, grid_size_y, block_size_x, block_size_y): (usize, usize, usize, usize) =
            if interpolated_main_rows_height > 256 {
                (
                    interpolated_main_rows_height.div_ceil(256),
                    num_air_blocks.div_ceil(2),
                    256,
                    num_air_blocks.min(2),
                )
            } else {
                let y = num_air_blocks
                    .next_power_of_two()
                    .min((256 / interpolated_main_rows_height).next_power_of_two());
                (
                    1,
                    num_air_blocks.div_ceil(y),
                    interpolated_main_rows_height.next_power_of_two(),
                    y,
                )
            };

        let grid_size = (grid_size_x, grid_size_y, 3);
        let num_tiles = (block_size_x * block_size_y).checked_div(1).unwrap_or(1);
        let shared_mem = num_tiles * std::mem::size_of::<EF>();

        let mut output: Tensor<EF, TaskScope> =
            Tensor::with_sizes_in([3, grid_size_x * grid_size_y], backend.clone());

        let (preprocessed_ptr, preprocessed_width) =
            if let Some(preprocessed_rows) = interpolated_preprocessed_rows {
                (preprocessed_rows.as_ptr(), preprocessed_rows.sizes()[1])
            } else {
                (std::ptr::null(), 0)
            };

        // Evalulate the constraint polynomial on the interpolated rows.
        unsafe {
            // Run the interpolate row kernel.
            let partial_lagrange_ptr = partial_lagrange.guts().as_ptr().add(offset);
            let args = args!(
                num_air_blocks,
                constraint_indices.as_ptr(),
                operations.as_ptr(),
                operations_indices.as_ptr(),
                operations_len,
                f_constants.as_ptr(),
                f_constants_indices.as_ptr(),
                ef_constants.as_ptr(),
                ef_constants_indices.as_ptr(),
                partial_lagrange_ptr,
                preprocessed_ptr,
                preprocessed_width,
                interpolated_main_rows.as_ptr(),
                main_width,
                interpolated_main_rows_height,
                self.powers_of_alpha_device.as_ptr(),
                self.public_values_device.as_ptr(),
                self.gkr_powers_device.as_ptr(),
                output.as_mut_ptr()
            );

            output.assume_init();
            backend
                .launch_kernel(
                    <TaskScope as ConstraintPolyEvalKernel<K>>::constraint_poly_eval_kernel(
                        *f_ctr as usize,
                    ),
                    grid_size,
                    (block_size_x, block_size_y, 1),
                    &args,
                    shared_mem,
                )
                .unwrap();
        }

        output
    }
}

impl<F, K, EF, A> ZerocheckRoundProver<F, K, EF, TaskScope> for ZerocheckEvalProgramProver<F, EF, A>
where
    F: Field,
    EF: ExtensionField<F> + From<K> + ExtensionField<F> + AbstractExtensionField<K>,
    K: Field + From<F> + Add<F, Output = K> + Sub<F, Output = K> + Mul<F, Output = K>,
    A: for<'b> Air<ConstraintSumcheckFolder<'b, F, K, EF>> + MachineAir<F>,
    TaskScope: InterpolateRowKernel<K> + ConstraintPolyEvalKernel<K> + ReduceSumBackend<EF>,
{
    type Air = A;

    #[inline]
    fn air(&self) -> &Self::Air {
        &self.air
    }

    #[inline]
    fn public_values(&self) -> &[F] {
        &self.public_values
    }

    #[inline]
    fn powers_of_alpha(&self) -> &[EF] {
        &self.powers_of_alpha
    }

    #[inline]
    fn gkr_powers(&self) -> &[EF] {
        &self.gkr_powers
    }

    fn sum_as_poly_in_last_variable<const IS_FIRST_ROUND: bool>(
        &self,
        partial_lagrange: Arc<Mle<EF, TaskScope>>,
        preprocessed_values: Option<PaddedMle<K, TaskScope>>,
        main_values: PaddedMle<K, TaskScope>,
    ) -> (EF, EF, EF) {
        let height = main_values.inner().as_ref().unwrap().num_non_zero_entries();
        let mut y_s = [EF::zero(); 3];
        let mut start = 0;
        while start < height {
            let end = (start + MAX_EVAL_INTERPOLATED_ROWS).min(height);

            let eval_start = start >> 1;
            let eval_end = end.div_ceil(2);

            let interpolated_main_rows = interpolate_rows(
                main_values.inner().as_ref().unwrap(),
                eval_start..eval_end,
                height.div_ceil(2),
            );
            let interpolated_preprocessed_rows = preprocessed_values.as_ref().map(|values| {
                interpolate_rows(
                    values.inner().as_ref().unwrap(),
                    eval_start..eval_end,
                    height.div_ceil(2),
                )
            });
            let output = self
                .constraint_poly_eval(
                    &partial_lagrange,
                    &interpolated_preprocessed_rows,
                    &interpolated_main_rows,
                    eval_start,
                );
            let y_s_device = DeviceTensor::from_raw(output).sum_dim(1);
            let y_s_host = DeviceTensor::from_raw(y_s_device).to_host().unwrap().into_buffer().into_vec();
            for (acc, val) in y_s.iter_mut().zip(y_s_host.iter()) {
                *acc += *val;
            }

            start = end;
        }
        (y_s[0], y_s[1], y_s[2])
    }
}

fn interpolate_rows<K: Field>(
    values: &Mle<K, TaskScope>,
    range: Range<usize>,
    global_height: usize,
) -> Tensor<K, TaskScope>
where
    TaskScope: InterpolateRowKernel<K>,
{
    let backend = values.backend();

    let height = values.num_non_zero_entries();
    let width = values.num_polynomials();
    let offset = range.start;
    let interpolated_rows_height = range.len();

    let mut interpolated_rows: Tensor<K, TaskScope> =
        Tensor::with_sizes_in([3, width, interpolated_rows_height], backend.clone());
    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 1;
    let grid_size_x = interpolated_rows_height.div_ceil(BLOCK_SIZE * STRIDE);
    let grid_size_y = width;
    let grid_size = (grid_size_x, grid_size_y, 1);

    let args = args!(
        values.guts().as_ptr(),
        interpolated_rows.as_mut_ptr(),
        height,
        width,
        interpolated_rows_height,
        offset,
        global_height
    );
    unsafe {
        interpolated_rows.assume_init();

        backend
            .launch_kernel(
                <TaskScope as InterpolateRowKernel<K>>::interpolate_row_kernel(),
                grid_size,
                (BLOCK_SIZE, 1, 1),
                &args,
                0,
            )
            .unwrap();
    }
    interpolated_rows
}

#[cfg(test)]
mod tests {
    use super::*;

    use sp1_gpu_cudart::DeviceMle;
    use slop_algebra::{extension::BinomialExtensionField, AbstractField};
    use slop_koala_bear::KoalaBear;
    use slop_matrix::dense::RowMajorMatrix;
    use slop_multilinear::Mle;
    use slop_tensor::Tensor;

    #[tokio::test]
    async fn test_interpolate_rows() {
        let mut rng = rand::thread_rng();

        type F = KoalaBear;
        type EF = BinomialExtensionField<F, 4>;

        let main_height = (1 << 7) - 1;
        let main_width = 3;

        let main_mle = Mle::<EF>::new(Tensor::rand(&mut rng, [main_height, main_width]));
        let main_guts = main_mle.guts().as_slice();

        let (expected_y_0s, (expected_y_2s, expected_y_4s)): (Vec<_>, (Vec<_>, Vec<_>)) = main_guts
            .chunks(2 * main_width)
            // .take(main_height.div_ceil(2) - 1)
            .skip(1)
            .flat_map(|chunk| {
                let (chunk_0, mut chunk_1) = chunk.split_at(main_width);
                let zero_chunk = vec![EF::zero(); main_width];
                if chunk_1.len() != main_width {
                    chunk_1 = zero_chunk.as_slice();
                }
                chunk_0
                    .iter()
                    .zip(chunk_1)
                    .map(move |(e_0, e_1)| {
                        (
                            *e_0,
                            (
                                EF::from_canonical_usize(2) * (*e_1 - *e_0) + *e_0,
                                EF::from_canonical_usize(4) * (*e_1 - *e_0) + *e_0,
                            ),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unzip();

        let expected_y_0s = RowMajorMatrix::new(expected_y_0s, main_width).transpose().values;
        let expected_y_2s = RowMajorMatrix::new(expected_y_2s, main_width).transpose().values;
        let expected_y_4s = RowMajorMatrix::new(expected_y_4s, main_width).transpose().values;

        let interpolated_rows_host = sp1_gpu_cudart::spawn(move |t| async move {
            let main_mle_device = DeviceMle::from_host(&main_mle, &t).into_inner();
            let interpolated_rows = interpolate_rows::<EF>(
                &main_mle_device,
                1..main_height.div_ceil(2),
                main_height.div_ceil(2),
            );
            let interpolated_rows_host = DeviceTensor::from_raw(interpolated_rows.storage).to_host().unwrap();
            Tensor::from(interpolated_rows_host).reshape([
                3,
                main_width,
                main_height.div_ceil(2) - 1,
            ])
        })
        .await
        .unwrap();

        let calculated_y_0s = interpolated_rows_host.get(0).unwrap().as_slice();
        let calculated_y_2s = interpolated_rows_host.get(1).unwrap().as_slice();
        let calculated_y_4s = interpolated_rows_host.get(2).unwrap().as_slice();

        for (i, (calculated_y_0, expected_y_0)) in
            calculated_y_0s.iter().zip(expected_y_0s.iter()).enumerate()
        {
            assert_eq!(*calculated_y_0, *expected_y_0, "Mismatch at index {i}");
        }
        for (i, (calculated_y_2, expected_y_2)) in
            calculated_y_2s.iter().zip(expected_y_2s.iter()).enumerate()
        {
            assert_eq!(*calculated_y_2, *expected_y_2, "Mismatch at index {i}");
        }
        for (i, (calculated_y_4, expected_y_4)) in
            calculated_y_4s.iter().zip(expected_y_4s.iter()).enumerate()
        {
            assert_eq!(*calculated_y_4, *expected_y_4, "Mismatch at index {i}");
        }
    }
}
