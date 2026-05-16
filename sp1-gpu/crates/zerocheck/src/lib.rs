use itertools::Itertools;
use slop_algebra::{AbstractExtensionField, UnivariatePolynomial};
use slop_challenger::FieldChallenger;
use sp1_gpu_utils::{Ext, Felt};

pub mod data;
pub mod primitives;
pub mod prover;

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

#[cfg(test)]
pub mod tests {
    #![allow(clippy::print_stdout)]
    use itertools::Itertools;
    use rand::Rng;
    use serial_test::serial;
    use slop_air::{Air, BaseAir, PairBuilder};
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
        prover::ProverSemaphore, Chip, ChipEvaluation, ChipOpenedValues, LogUpEvaluations,
        ShardOpenedValues, VerifierConstraintFolder,
    };

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
    use super::prover::{compile_chips, upload_compiled_bytecode, zerocheck, CompiledChip};
    use sp1_gpu_air::ir::ChunkBudget;

    use core::{borrow::Borrow, mem::size_of};
    use sp1_core_executor::{ExecutionRecord, Program};
    use sp1_derive::AlignedBorrow;

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
        A: MachineAir<Felt> + ZerocheckAir<Felt, Ext>,
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
        A: MachineAir<Felt>,
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

    /// Scaling sanity check for the future "machine with thousands of chips"
    /// goal: replicate the compiled test chips up to 5000 and confirm the
    /// once-per-machine flat upload (`upload_compiled_bytecode`) handles it.
    #[test]
    #[serial]
    fn test_machine_bytecode_scaling() {
        let mut chips: BTreeSet<Chip<Felt, _>> = BTreeSet::new();
        chips.insert(Chip::new(ZerocheckTestChip::Chip1(ZerocheckTestChip1)));
        chips.insert(Chip::new(ZerocheckTestChip::Chip2(ZerocheckTestChip2)));
        chips.insert(Chip::new(ZerocheckTestChip::Chip3(ZerocheckTestChip3)));
        let base = compile_chips(&chips, ChunkBudget::recommended());

        // Replicate the compiled chips to a machine-sized chip count, each
        // with a distinct name (the chunker output is identical — we only
        // exercise the flatten + upload path at scale).
        const TARGET: usize = 5000;
        let mut big: Vec<CompiledChip> = Vec::with_capacity(TARGET);
        for i in 0..TARGET {
            let mut c = base[i % base.len()].clone();
            c.chip_idx = i as u32;
            c.name = format!("{}_{}", c.name, i);
            big.push(c);
        }

        run_sync_in_place(move |t| {
            let start = std::time::Instant::now();
            let mb = upload_compiled_bytecode(big, &t);
            println!(
                "upload_compiled_bytecode: {} chips uploaded in {:?}",
                mb.chips.len(),
                start.elapsed(),
            );
            assert_eq!(mb.chips.len(), TARGET);
            assert_eq!(mb.chip_index.len(), TARGET);
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

        let chips_vec = chips.iter().cloned().collect::<Vec<_>>();
        let row_variables = 22;

        run_sync_in_place(move |t| {
            // Build machine bytecode as a strict SUPERSET of the shard: a
            // fake extra chip is prepended so the real chips sit at machine
            // indices 1,2,3 while the shard sees them at 0,1,2. Exercises
            // the machine-⊋-shard selection path that e2e proving hits.
            let mut machine_compiled = compile_chips(&chips, ChunkBudget::recommended());
            let mut fake = machine_compiled[0].clone();
            fake.name = "ZZZ_fake_extra_chip".to_string();
            let mut superset = vec![fake];
            superset.append(&mut machine_compiled);
            let machine_bytecode = Arc::new(upload_compiled_bytecode(superset, &t));
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
                &machine_bytecode,
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

    /// Zerocheck on real RISC-V traces. Builds the machine bytecode from the
    /// WHOLE machine (machine ⊋ shard cluster) — mirroring what the e2e
    /// prover does — proves the shard cluster against it, and verifies. Also
    /// proves against a 5000-chip padded machine to confirm per-shard work is
    /// pay-per-use (independent of machine size).
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
            let trace_mle = Arc::new(trace_mle);

            // Build two machine bytecodes from the whole machine: one sized
            // to the real chip set, and one padded to 5000 chips with
            // distinct-named clones (simulating an auto-generated many-chip
            // machine). The shard cluster is selected by name from each.
            let machine_chip_set: BTreeSet<_> = machine.chips().iter().cloned().collect();
            let base_compiled = compile_chips(&machine_chip_set, ChunkBudget::recommended());
            let real_n = base_compiled.len();
            let mut padded = base_compiled.clone();
            let mut k = 0;
            while padded.len() < 5000 {
                let mut c = padded[k % real_n].clone();
                c.name = format!("{}__pad{}", c.name, padded.len());
                padded.push(c);
                k += 1;
            }
            println!(
                "5000-chip pay-per-use test: cluster={} chips, machine sizes {} and {}",
                chips.len(),
                real_n,
                padded.len(),
            );

            // The verifier's chip openings, derived from the committed trace.
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

            let mut challenger = TestGC::default_challenger();
            challenger.observe(Felt::from_canonical_u32(0x2013));
            challenger.observe(Felt::from_canonical_u32(0x2015));
            challenger.observe(Felt::from_canonical_u32(0x2016));

            // Prove the shard cluster against a given machine bytecode and
            // verify; returns the wall time of the `zerocheck` call.
            let run = |machine_compiled: Vec<CompiledChip>| {
                let mb = Arc::new(upload_compiled_bytecode(machine_compiled, &t));
                let mut challenger_prover = challenger.clone();
                let batching_challenge = challenger_prover.sample_ext_element();
                let gkr_opening_batch_randomness = challenger_prover.sample_ext_element();

                let start = std::time::Instant::now();
                let (opened_values, zerocheck_proof) = zerocheck(
                    chips,
                    &mb,
                    trace_mle.as_ref(),
                    batching_challenge,
                    gkr_opening_batch_randomness,
                    &logup_evaluations,
                    public_values.clone(),
                    &mut challenger_prover,
                    CORE_MAX_LOG_ROW_COUNT,
                );
                let elapsed = start.elapsed();

                let mut challenger_verifier = challenger.clone();
                crate::tests::verify_zerocheck(
                    chips,
                    &opened_values,
                    &logup_evaluations,
                    zerocheck_proof,
                    &public_values,
                    &mut challenger_verifier,
                    CORE_MAX_LOG_ROW_COUNT as usize,
                );
                elapsed
            };

            let t_small = run(base_compiled);
            let t_5000 = run(padded);
            println!(
                "  zerocheck: {}-chip machine = {:?}, 5000-chip machine = {:?}",
                real_n, t_small, t_5000,
            );

            // Pay-per-use: the 5000-chip machine must not slow the per-shard
            // proof down meaningfully vs the small machine.
            let slower = t_5000.as_secs_f64() / t_small.as_secs_f64();
            assert!(
                slower < 1.5,
                "per-shard work scaled with machine size ({slower:.2}x) — not pay-per-use",
            );
        })
        .await;
    }
}
