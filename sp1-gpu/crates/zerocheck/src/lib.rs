use itertools::Itertools;
use slop_algebra::{AbstractExtensionField, UnivariatePolynomial};
use slop_challenger::FieldChallenger;
use sp1_gpu_utils::{Ext, Felt};

pub mod primitives;
pub mod prover;

pub(crate) fn challenger_update<C>(
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
        /// Targeted: ColumnTile lowering of a `SubF`-spined linear sum.
        /// One constraint, two columns, `3·x0 - 2·x1 = 0`. Exercises the
        /// `COEFF_NEGATE_BIT` path end-to-end.
        LinearSub(ZerocheckLinearSubChip),
        /// Targeted: `COEFF_KIND_PUBLIC` branch with negate. One constraint
        /// `pv[0]·x0 - pv[1]·x1 = 0`. The kernel loads each coefficient
        /// from the public-values buffer rather than the const pool, and
        /// the second term carries `COEFF_NEGATE_BIT`. A wrong sign or a
        /// wrong-buffer load shows up as a verification failure.
        PublicCoeff(ZerocheckPublicCoeffChip),
        /// Targeted: extreme-width chip. 4096 main columns, single
        /// trivial constraint `x[0] = 0`. Far exceeds
        /// `WIDE_GKR_THRESHOLD` (256), so the launcher routes its GKR
        /// opening through the warp-per-row `zerocheck_gkr_sweep` kernel
        /// with significant lane parallelism. Also pushes the JaggedMle
        /// PR's `jagged_fold_metadata` kernel into deep multi-block
        /// territory (4097-col `start_indices` / `column_heights`).
        ExtraWide(ZerocheckExtraWideChip),
        /// Targeted: high register pressure → `MAX_REGS=256` fused
        /// kernel template (dead in production until a chip like this
        /// exists). 200 constraints over 64 shared columns: each
        /// constraint is a degree-2 polynomial that's true when every
        /// column equals a fixed constant. All 200 roots are alive at
        /// the asserts pass, forcing `max_reg ≥ 200` and exercising the
        /// `BLOCK_SIZE_HIGH_REG` (= 64-thread) branch of
        /// `block_size_for`.
        HighMaxReg(ZerocheckHighMaxRegChip),
    }

    impl<AB: SP1AirBuilder + PairBuilder> Air<AB> for ZerocheckTestChip {
        fn eval(&self, builder: &mut AB) {
            match self {
                Self::Chip1(chip) => chip.eval(builder),
                Self::Chip2(chip) => chip.eval(builder),
                Self::Chip3(chip) => chip.eval(builder),
                Self::LinearSub(chip) => chip.eval(builder),
                Self::PublicCoeff(chip) => chip.eval(builder),
                Self::ExtraWide(chip) => chip.eval(builder),
                Self::HighMaxReg(chip) => chip.eval(builder),
            }
        }
    }

    impl<F> BaseAir<F> for ZerocheckTestChip {
        fn width(&self) -> usize {
            match self {
                Self::Chip1(chip) => <ZerocheckTestChip1 as slop_air::BaseAir<F>>::width(chip),
                Self::Chip2(chip) => <ZerocheckTestChip2 as slop_air::BaseAir<F>>::width(chip),
                Self::Chip3(chip) => <ZerocheckTestChip3 as slop_air::BaseAir<F>>::width(chip),
                Self::LinearSub(chip) => {
                    <ZerocheckLinearSubChip as slop_air::BaseAir<F>>::width(chip)
                }
                Self::PublicCoeff(chip) => {
                    <ZerocheckPublicCoeffChip as slop_air::BaseAir<F>>::width(chip)
                }
                Self::ExtraWide(chip) => {
                    <ZerocheckExtraWideChip as slop_air::BaseAir<F>>::width(chip)
                }
                Self::HighMaxReg(chip) => {
                    <ZerocheckHighMaxRegChip as slop_air::BaseAir<F>>::width(chip)
                }
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
                Self::LinearSub(chip) => <ZerocheckLinearSubChip as MachineAir<F>>::name(chip),
                Self::PublicCoeff(chip) => <ZerocheckPublicCoeffChip as MachineAir<F>>::name(chip),
                Self::ExtraWide(chip) => <ZerocheckExtraWideChip as MachineAir<F>>::name(chip),
                Self::HighMaxReg(chip) => <ZerocheckHighMaxRegChip as MachineAir<F>>::name(chip),
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
                Self::LinearSub(chip) => {
                    <ZerocheckLinearSubChip as MachineAir<F>>::preprocessed_width(chip)
                }
                Self::PublicCoeff(chip) => {
                    <ZerocheckPublicCoeffChip as MachineAir<F>>::preprocessed_width(chip)
                }
                Self::ExtraWide(chip) => {
                    <ZerocheckExtraWideChip as MachineAir<F>>::preprocessed_width(chip)
                }
                Self::HighMaxReg(chip) => {
                    <ZerocheckHighMaxRegChip as MachineAir<F>>::preprocessed_width(chip)
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

    // ---- LinearSubChip — targeted SubF-in-LinearWeightedSum coverage ----
    //
    // One asserted constraint, two main columns, no preprocessed columns:
    //
    //   3·x0 - 2·x1 == 0
    //
    // The constraint expression is `MulF(3, x0) - MulF(2, x1)` — a flat
    // `SubF` over two `coeff·leaf` products. `analyze_constraints` tags it
    // `LinearWeightedSum`; `compile_chips` routes it to ColumnTile, and
    // `flatten_linear` emits two terms with the second carrying
    // `COEFF_NEGATE_BIT`. A regression in the SubF sign-tracking would
    // produce `3·x0 + 2·x1` instead and fail verification on the trace
    // generated by `generate_random_row(LinearSub, …)` (which sets
    // `x0 = 2·r, x1 = 3·r` so the true polynomial is zero).
    //
    // Width-4 alignment (`row % 4 == 0`) is required by `get_input`'s
    // jagged-layout assumption; we pad with `_pad_0` / `_pad_1` so the
    // useful columns stay first.
    #[derive(Default, Clone)]
    pub struct ZerocheckLinearSubChip;

    impl std::fmt::Debug for ZerocheckLinearSubChip {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ZerocheckLinearSubChip")
        }
    }

    pub const NUM_ZEROCHECK_LINEAR_SUB_COLS: usize = size_of::<ZerocheckLinearSubCols<u8>>();

    #[derive(AlignedBorrow, Default, Clone, Copy)]
    #[repr(C)]
    pub struct ZerocheckLinearSubCols<T> {
        x0: T,
        x1: T,
    }

    impl<F> BaseAir<F> for ZerocheckLinearSubChip {
        fn width(&self) -> usize {
            NUM_ZEROCHECK_LINEAR_SUB_COLS
        }
    }

    impl<F: PrimeField32> MachineAir<F> for ZerocheckLinearSubChip {
        type Record = ExecutionRecord;
        type Program = Program;

        fn name(&self) -> &'static str {
            "ZerocheckLinearSub"
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
            _: &ExecutionRecord,
            _: &mut ExecutionRecord,
            _: &mut [std::mem::MaybeUninit<F>],
        ) {
            unimplemented!();
        }

        fn included(&self, _: &Self::Record) -> bool {
            true
        }
    }

    impl<AB> Air<AB> for ZerocheckLinearSubChip
    where
        AB: SP1AirBuilder + PairBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &ZerocheckLinearSubCols<AB::Var> = (*local).borrow();
            builder.assert_zero(
                AB::Expr::from_canonical_u32(3) * local.x0
                    - AB::Expr::from_canonical_u32(2) * local.x1,
            );
        }
    }

    // ---- PublicCoeffChip — `COEFF_KIND_PUBLIC` × `COEFF_NEGATE_BIT` ----
    //
    // Single constraint `pv[0] · x0 − pv[1] · x1 == 0`. Trace picks
    // `x0 = pv[1]·r, x1 = pv[0]·r` so each row satisfies it for any r.
    // Hits the kernel's `COEFF_KIND_PUBLIC` load path (publics[] indirection)
    // and the negate flag on the right operand of the SubF — distinct from
    // `LinearSubChip` which exercises the const-pool load path.
    #[derive(Default, Clone)]
    pub struct ZerocheckPublicCoeffChip;

    impl std::fmt::Debug for ZerocheckPublicCoeffChip {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ZerocheckPublicCoeffChip")
        }
    }

    pub const NUM_ZEROCHECK_PUBLIC_COEFF_COLS: usize = size_of::<ZerocheckPublicCoeffCols<u8>>();

    #[derive(AlignedBorrow, Default, Clone, Copy)]
    #[repr(C)]
    pub struct ZerocheckPublicCoeffCols<T> {
        x0: T,
        x1: T,
    }

    impl<F> BaseAir<F> for ZerocheckPublicCoeffChip {
        fn width(&self) -> usize {
            NUM_ZEROCHECK_PUBLIC_COEFF_COLS
        }
    }

    impl<F: PrimeField32> MachineAir<F> for ZerocheckPublicCoeffChip {
        type Record = ExecutionRecord;
        type Program = Program;
        fn name(&self) -> &'static str {
            "ZerocheckPublicCoeff"
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
            _: &ExecutionRecord,
            _: &mut ExecutionRecord,
            _: &mut [std::mem::MaybeUninit<F>],
        ) {
            unimplemented!();
        }
        fn included(&self, _: &Self::Record) -> bool {
            true
        }
    }

    impl<AB> Air<AB> for ZerocheckPublicCoeffChip
    where
        AB: SP1AirBuilder + PairBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &ZerocheckPublicCoeffCols<AB::Var> = (*local).borrow();
            let pvs = builder.public_values();
            let pv0: AB::Expr = pvs[0].into();
            let pv1: AB::Expr = pvs[1].into();
            builder.assert_zero(pv0 * local.x0 - pv1 * local.x1);
        }
    }

    // ---- ExtraWideChip — extreme width for `gkr_sweep` wide path ----
    //
    // 4096 main columns, single trivial constraint `x[0] = 0`. Dominates
    // every chip width currently in SP1; pushes the launcher's GKR
    // dispatch firmly into the `zerocheck_gkr_sweep` warp-per-row regime
    // and inflates the JaggedMle PR's `jagged_fold_metadata` n_columns
    // / n_blocks to ~8 blocks per round.
    pub const NUM_ZEROCHECK_EXTRA_WIDE_COLS: usize = 4096;

    #[derive(Default, Clone)]
    pub struct ZerocheckExtraWideChip;

    impl std::fmt::Debug for ZerocheckExtraWideChip {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ZerocheckExtraWideChip")
        }
    }

    impl<F> BaseAir<F> for ZerocheckExtraWideChip {
        fn width(&self) -> usize {
            NUM_ZEROCHECK_EXTRA_WIDE_COLS
        }
    }

    impl<F: PrimeField32> MachineAir<F> for ZerocheckExtraWideChip {
        type Record = ExecutionRecord;
        type Program = Program;
        fn name(&self) -> &'static str {
            "ZerocheckExtraWide"
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
            _: &ExecutionRecord,
            _: &mut ExecutionRecord,
            _: &mut [std::mem::MaybeUninit<F>],
        ) {
            unimplemented!();
        }
        fn included(&self, _: &Self::Record) -> bool {
            true
        }
    }

    impl<AB> Air<AB> for ZerocheckExtraWideChip
    where
        AB: SP1AirBuilder + PairBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            // `x[0] = 0` — minimal asserted constraint; the rest of the
            // 4096 columns participate via the GKR opening only, which is
            // exactly the dispatch we want to exercise.
            let main = builder.main();
            let local = main.row_slice(0);
            builder.assert_zero(local[0].into());
        }
    }

    // ---- HighMaxRegChip — high register pressure → MAX_REGS=256 tier ----
    //
    // `NUM_HMR_LEAVES = 64` columns (matches the chunker's recommended
    // `max_leafset`), `NUM_HMR_CONSTRAINTS = 200` constraints all sharing
    // the same 64 columns. Each constraint i is
    //   `(x[i % NUM] - c) · (x[(i+1) % NUM] - c) − (x[(i+2) % NUM] - c) · (x[(i+3) % NUM] - c) == 0`
    // — a degree-2 polynomial over 4 shared columns and a constant. The
    // shape is general (not LinearWeightedSum) so it lowers to
    // Sequential; all 200 roots stay alive at the asserts pass, forcing
    // `max_reg ≥ 200` and selecting the `MAX_REGS=256` fused-kernel
    // template, which the review flagged as unexercised today.
    //
    // Trace: every column holds the same constant `c` per row. Then each
    // `(x[k] - c) = 0`, every product is 0, every difference is 0, every
    // constraint holds — for any `c`.
    pub const NUM_HMR_LEAVES: usize = 64;
    pub const NUM_HMR_CONSTRAINTS: usize = 200;
    pub const HMR_CONSTANT: u32 = 12345;

    #[derive(Default, Clone)]
    pub struct ZerocheckHighMaxRegChip;

    impl std::fmt::Debug for ZerocheckHighMaxRegChip {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ZerocheckHighMaxRegChip")
        }
    }

    impl<F> BaseAir<F> for ZerocheckHighMaxRegChip {
        fn width(&self) -> usize {
            NUM_HMR_LEAVES
        }
    }

    impl<F: PrimeField32> MachineAir<F> for ZerocheckHighMaxRegChip {
        type Record = ExecutionRecord;
        type Program = Program;
        fn name(&self) -> &'static str {
            "ZerocheckHighMaxReg"
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
            _: &ExecutionRecord,
            _: &mut ExecutionRecord,
            _: &mut [std::mem::MaybeUninit<F>],
        ) {
            unimplemented!();
        }
        fn included(&self, _: &Self::Record) -> bool {
            true
        }
    }

    impl<AB> Air<AB> for ZerocheckHighMaxRegChip
    where
        AB: SP1AirBuilder + PairBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let c = AB::Expr::from_canonical_u32(HMR_CONSTANT);
            for i in 0..NUM_HMR_CONSTRAINTS {
                let a: AB::Expr = local[i % NUM_HMR_LEAVES].into();
                let b: AB::Expr = local[(i + 1) % NUM_HMR_LEAVES].into();
                let d: AB::Expr = local[(i + 2) % NUM_HMR_LEAVES].into();
                let e: AB::Expr = local[(i + 3) % NUM_HMR_LEAVES].into();
                let cc = c.clone();
                builder
                    .assert_zero((a - cc.clone()) * (b - cc.clone()) - (d - cc.clone()) * (e - cc));
            }
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

    /// Pick `chip`'s trace row that satisfies its asserted-zero constraints.
    /// Dispatches on the variant so adding a new test chip only needs a new
    /// arm here, not a chip-index renumbering at every call site.
    fn generate_random_row<R: Rng>(
        chip: &ZerocheckTestChip,
        rng: &mut R,
        public_values: &[Felt],
    ) -> (Vec<Felt>, Vec<Felt>) {
        match chip {
            ZerocheckTestChip::Chip1(_) => {
                let b = random_felt(rng);
                let c = random_felt(rng);
                let a = (b + c + Felt::one())
                    * (b + c + Felt::two())
                    * (b - c + Felt::from_canonical_u32(8))
                    - b * Felt::from_canonical_u32(3);
                let d = Felt::from_canonical_u32(rng.next_u32() % 3);
                (vec![], vec![a, b, c, d])
            }
            ZerocheckTestChip::Chip2(_) => {
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
            ZerocheckTestChip::Chip3(_) => {
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
            // `c0·x0 - c1·x1 = 0` — a pure LinearWeightedSum with SubF in
            // the spine. Picks `(x0, x1) = (2·r, 3·r)` so 3·x0 - 2·x1 = 0
            // for any r. Designed to exercise the ColumnTile lowering's
            // `COEFF_NEGATE_BIT` path; a regression in SubF sign tracking
            // would fail verification on this chip without needing a
            // RISC-V execution trace.
            ZerocheckTestChip::LinearSub(_) => {
                let r = random_felt(rng);
                let x0 = r + r; // 2·r
                let x1 = r + r + r; // 3·r
                (vec![], vec![x0, x1])
            }
            // `pv[0]·x0 - pv[1]·x1 = 0`. Picks `(x0, x1) = (pv[1]·r,
            // pv[0]·r)` so the constraint is `pv[0]·pv[1]·r -
            // pv[1]·pv[0]·r = 0` for any r. Caller must supply two
            // public values.
            ZerocheckTestChip::PublicCoeff(_) => {
                assert!(
                    public_values.len() >= 2,
                    "PublicCoeffChip needs ≥2 public values for its coefficients",
                );
                let r = random_felt(rng);
                let x0 = public_values[1] * r;
                let x1 = public_values[0] * r;
                (vec![], vec![x0, x1])
            }
            // `x[0] = 0`; the remaining 4095 columns can hold any value
            // (they participate only in the GKR opening, not in any
            // asserted constraint).
            ZerocheckTestChip::ExtraWide(_) => {
                let mut row = vec![Felt::zero(); NUM_ZEROCHECK_EXTRA_WIDE_COLS];
                row[0] = Felt::zero();
                for cell in row.iter_mut().skip(1) {
                    *cell = random_felt(rng);
                }
                (vec![], row)
            }
            // All columns hold the same `HMR_CONSTANT`; every
            // `(x[k] - HMR_CONSTANT)` factor is zero, so every product
            // and every difference of products in the chip's 200
            // constraints is zero.
            ZerocheckTestChip::HighMaxReg(_) => {
                let row = vec![Felt::from_canonical_u32(HMR_CONSTANT); NUM_HMR_LEAVES];
                (vec![], row)
            }
        }
    }

    fn random_felt<R: Rng>(rng: &mut R) -> Felt {
        Felt::from_wrapped_u32(rng.next_u32())
    }

    /// Sanity-evaluator for the generated rows: returns the value of each
    /// asserted-zero constraint expression on a given row. Used by
    /// `test_row_constraint` to confirm the row generators above produce
    /// traces that actually satisfy each chip's AIR. Dispatches on the
    /// variant so it stays in lockstep with the chip catalog.
    fn constraint_eval(
        chip: &ZerocheckTestChip,
        prep_row: Vec<Felt>,
        row: Vec<Felt>,
        public_values: Vec<Felt>,
    ) -> Vec<Felt> {
        match chip {
            ZerocheckTestChip::Chip1(_) => {
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
            ZerocheckTestChip::Chip2(_) => {
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
            ZerocheckTestChip::Chip3(_) => {
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
            ZerocheckTestChip::LinearSub(_) => {
                assert_eq!(prep_row.len(), 0);
                assert_eq!(row.len(), 2);
                let x0 = row[0];
                let x1 = row[1];
                // Mirrors the chip's `eval`: `3·x0 - 2·x1`.
                vec![x0 * Felt::from_canonical_u32(3) - x1 * Felt::from_canonical_u32(2)]
            }
            ZerocheckTestChip::PublicCoeff(_) => {
                assert_eq!(prep_row.len(), 0);
                assert_eq!(row.len(), 2);
                assert!(public_values.len() >= 2);
                vec![public_values[0] * row[0] - public_values[1] * row[1]]
            }
            ZerocheckTestChip::ExtraWide(_) => {
                assert_eq!(prep_row.len(), 0);
                assert_eq!(row.len(), NUM_ZEROCHECK_EXTRA_WIDE_COLS);
                // Only `x[0] = 0` is asserted; other columns are
                // unconstrained.
                vec![row[0]]
            }
            ZerocheckTestChip::HighMaxReg(_) => {
                assert_eq!(prep_row.len(), 0);
                assert_eq!(row.len(), NUM_HMR_LEAVES);
                let c = Felt::from_canonical_u32(HMR_CONSTANT);
                (0..NUM_HMR_CONSTRAINTS)
                    .map(|i| {
                        let a = row[i % NUM_HMR_LEAVES] - c;
                        let b = row[(i + 1) % NUM_HMR_LEAVES] - c;
                        let d = row[(i + 2) % NUM_HMR_LEAVES] - c;
                        let e = row[(i + 3) % NUM_HMR_LEAVES] - c;
                        a * b - d * e
                    })
                    .collect()
            }
        }
    }

    fn get_input(
        sizes: &[u32],
        chips_vec: &[Chip<Felt, ZerocheckTestChip>],
        public_values: &[Felt],
    ) -> JaggedTraceMle<Felt, CpuBackend> {
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
                let (prep_row, main_row) =
                    generate_random_row(&chips_vec[i].air, &mut rng, public_values);
                for k in 0..prep_row.len() {
                    data[(preprocessed_ptr + j + row * k as u32) as usize] = prep_row[k];
                }
                for k in 0..main_row.len() {
                    data[(main_ptr + j + row * k as u32) as usize] = main_row[k];
                }
            }
            preprocessed_table_index.insert(
                <ZerocheckTestChip as MachineAir<SP1Field>>::name(&chips_vec[i].air).to_string(),
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
                <ZerocheckTestChip as MachineAir<SP1Field>>::name(&chips_vec[i].air).to_string(),
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
                // The synthetic trace layout emits exactly one prep-padding
                // column (see the `heights.push(padded_preprocessed / 2 - cnt
                // as u32)` line above); no main-padding columns.
                prep_padding_col_count: 1,
                main_padding_col_count: 0,
            },
            Buffer::from(cols),
            Buffer::from(start_idx),
            Buffer::from(heights),
        )
    }

    /// All variants of `ZerocheckTestChip`. New test chips added to the
    /// enum should be appended here so `test_row_constraint` automatically
    /// exercises their row generator + constraint evaluator pair.
    fn all_test_chips() -> Vec<ZerocheckTestChip> {
        vec![
            ZerocheckTestChip::Chip1(ZerocheckTestChip1),
            ZerocheckTestChip::Chip2(ZerocheckTestChip2),
            ZerocheckTestChip::Chip3(ZerocheckTestChip3),
            ZerocheckTestChip::LinearSub(ZerocheckLinearSubChip),
            ZerocheckTestChip::PublicCoeff(ZerocheckPublicCoeffChip),
            ZerocheckTestChip::ExtraWide(ZerocheckExtraWideChip),
            ZerocheckTestChip::HighMaxReg(ZerocheckHighMaxRegChip),
        ]
    }

    #[test]
    fn test_row_constraint() {
        let mut rng = rand::thread_rng();
        for chip in all_test_chips() {
            for _ in 0..(1 << 16) {
                let public_values = vec![random_felt(&mut rng), random_felt(&mut rng)];
                let (prep_row, main_row) = generate_random_row(&chip, &mut rng, &public_values);
                let result = constraint_eval(&chip, prep_row, main_row, public_values);
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

    /// Common scaffolding for "build chip set → tracegen → zerocheck →
    /// verify_zerocheck" tests. Caller controls the chip set, the row
    /// sizes per chip, the public values, the machine bytecode (so each
    /// test can decide whether to exercise the machine-⊋-shard path),
    /// and the `max_log_row_count`. Panics if verification fails. Each
    /// new targeted-AIR-pattern test stacks on top of this — see
    /// `test_zerocheck_linear_sub` for the minimal example.
    fn run_zerocheck_and_verify(
        chips: &BTreeSet<Chip<Felt, ZerocheckTestChip>>,
        machine_compiled: Vec<CompiledChip>,
        sizes: &[u32],
        public_values: &[Felt],
        max_log_row_count: u32,
    ) {
        let chips_vec = chips.iter().cloned().collect::<Vec<_>>();
        let chips_cloned = chips.clone();
        let pv = public_values.to_vec();
        let sizes_owned = sizes.to_vec();
        run_sync_in_place(move |t| {
            let machine_bytecode = Arc::new(upload_compiled_bytecode(machine_compiled, &t));

            let trace_mle = get_input(&sizes_owned, &chips_vec, &pv);
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

            let mut rng = rand::thread_rng();
            let zeta = Point::<Ext>::rand(&mut rng, max_log_row_count);
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
                    <ZerocheckTestChip as MachineAir<SP1Field>>::name(&chip.air).to_string(),
                    chip_eval,
                );
                preprocessed_ptr += preprocessed_width;
                main_ptr += main_width;
            }

            let logup_evaluations = LogUpEvaluations { point: zeta, chip_openings };
            let (opened_values, zerocheck_proof) = zerocheck(
                &chips_cloned,
                &machine_bytecode,
                trace_mle.as_ref(),
                batching_challenge,
                gkr_opening_batch_randomness,
                &logup_evaluations,
                pv.clone(),
                &mut challenger_prover,
                max_log_row_count,
            );

            let mut challenger_verifier = challenger.clone();
            crate::tests::verify_zerocheck(
                &chips_cloned,
                &opened_values,
                &logup_evaluations,
                zerocheck_proof,
                &pv,
                &mut challenger_verifier,
                max_log_row_count as usize,
            );
        })
        .unwrap();
    }

    /// Targeted regression for the ColumnTile-`SubF` sign bug. Builds a
    /// single-chip cluster of `ZerocheckLinearSubChip` whose only
    /// constraint is `3·x0 - 2·x1 == 0`. The trace generator emits rows
    /// satisfying the constraint; if the prover's ColumnTile lowering
    /// drops the sign on the right operand of `SubF`, the prover's claim
    /// disagrees with what `VerifierConstraintFolder` evaluates and
    /// `verify_zerocheck` panics. ~1s test, no RISC-V execution
    /// required.
    #[test]
    #[serial]
    fn test_zerocheck_linear_sub() {
        let mut chips: BTreeSet<Chip<Felt, _>> = BTreeSet::new();
        chips.insert(Chip::new(ZerocheckTestChip::LinearSub(ZerocheckLinearSubChip)));
        let machine_compiled = compile_chips(&chips, ChunkBudget::recommended());
        // 2^20 rows — big enough to exercise multiple sumcheck rounds + the
        // per-round dispatch tables but still tiny relative to a real shard.
        run_zerocheck_and_verify(&chips, machine_compiled, &[1 << 20], &[], 20);
    }

    /// Targeted regression for the `COEFF_KIND_PUBLIC` × `COEFF_NEGATE_BIT`
    /// branch: drives a single-chip cluster of `PublicCoeffChip` whose only
    /// constraint loads both coefficients from the public-values buffer and
    /// negates one of them. A sign error in the `PUBLIC` arm of the
    /// ColumnTile kernel — or a `COEFF_KIND_PUBLIC` ↔ `COEFF_KIND_CONST`
    /// dispatch confusion — would fail verification here.
    #[test]
    #[serial]
    fn test_zerocheck_public_coeff() {
        let mut chips: BTreeSet<Chip<Felt, _>> = BTreeSet::new();
        chips.insert(Chip::new(ZerocheckTestChip::PublicCoeff(ZerocheckPublicCoeffChip)));
        let machine_compiled = compile_chips(&chips, ChunkBudget::recommended());
        // Public values must be non-zero so the trace-generator's
        // `(x0, x1) = (pv[1]·r, pv[0]·r)` actually varies row-to-row.
        let public_values = vec![Felt::from_canonical_u32(7), Felt::from_canonical_u32(13)];
        run_zerocheck_and_verify(&chips, machine_compiled, &[1 << 20], &public_values, 20);
    }

    /// Extreme-width coverage. 4096 main columns drive the launcher's
    /// `zerocheck_gkr_sweep` warp-per-row kernel at production-scale
    /// lane parallelism, and inflate the JaggedMle PR's
    /// `jagged_fold_metadata` into deep multi-block territory (~8
    /// blocks for the start_indices scan). Picks a small row count
    /// because the chip's total trace bytes scale as `width × rows`.
    #[test]
    #[serial]
    fn test_zerocheck_extra_wide() {
        let mut chips: BTreeSet<Chip<Felt, _>> = BTreeSet::new();
        chips.insert(Chip::new(ZerocheckTestChip::ExtraWide(ZerocheckExtraWideChip)));
        let machine_compiled = compile_chips(&chips, ChunkBudget::recommended());
        // 2^12 rows × 4096 cols × 4 bytes ≈ 64 MB main trace — large
        // enough to exercise the GKR sweep at scale, still well under
        // device-buffer pressure.
        run_zerocheck_and_verify(&chips, machine_compiled, &[1 << 12], &[], 12);
    }

    /// Pushes the fused-sequential kernel into the `MAX_REGS=256`
    /// template tier. The chip has 200 constraints over 64 shared
    /// columns; the chunker bundles them into one chunk; all 200 roots
    /// stay alive at the asserts pass, forcing `max_reg ≥ 200`. The
    /// pointer table in `fused_sequential_kernel_for` then selects the
    /// 256-register template (which `block_size_for` runs at the
    /// reduced-occupancy `BLOCK_SIZE_HIGH_REG = 64` thread block).
    /// Without this test, that template was never executed by any
    /// production chip — a compile-time mistake in its specialization
    /// would slip through.
    #[test]
    #[serial]
    fn test_zerocheck_high_max_reg() {
        let mut chips: BTreeSet<Chip<Felt, _>> = BTreeSet::new();
        chips.insert(Chip::new(ZerocheckTestChip::HighMaxReg(ZerocheckHighMaxRegChip)));
        let machine_compiled = compile_chips(&chips, ChunkBudget::recommended());
        // Modest row count: per-row work is heavy (200 constraints × 64
        // cols of degree-2 polynomial evaluation), so a million rows
        // would be unnecessarily slow.
        run_zerocheck_and_verify(&chips, machine_compiled, &[1 << 16], &[], 16);
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
