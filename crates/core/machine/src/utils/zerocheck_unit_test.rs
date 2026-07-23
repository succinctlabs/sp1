use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use slop_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use sp1_core_executor::Program;
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::{MachineAir, SP1AirBuilder};

use crate::utils::zeroed_f_vec;

/// The number of main trace columns for `AddiChip`.
pub const NUM_MINIMAL_ADD_COLS: usize = size_of::<MinimalAddCols<u8>>();

/// A chip that implements addition for the opcode ADDI.
#[derive(Default, Clone)]
pub struct MinimalAddChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct MinimalAddCols<T> {
    op_a: T,
    op_b: T,
    op_c: T,
}

impl<F> BaseAir<F> for MinimalAddChip {
    fn width(&self) -> usize {
        NUM_MINIMAL_ADD_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MinimalAddChip {
    type Record = Vec<(u32, u32, u32)>;

    type Program = Program;

    fn name(&self) -> &'static str {
        "MinimalAdd"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        Some(input.len().next_multiple_of(32))
    }

    fn generate_trace_into(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _buffer: &mut [std::mem::MaybeUninit<F>],
    ) {
        unimplemented!();
    }

    fn generate_trace(
        &self,
        input: &Vec<(u32, u32, u32)>,
        _: &mut Vec<(u32, u32, u32)>,
    ) -> RowMajorMatrix<F> {
        // Generate the rows for the trace.
        let chunk_size = std::cmp::max(input.len() / num_cpus::get(), 1);
        let mut values = zeroed_f_vec(input.len() * NUM_MINIMAL_ADD_COLS);

        values.chunks_mut(chunk_size * NUM_MINIMAL_ADD_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_MINIMAL_ADD_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut MinimalAddCols<F> = row.borrow_mut();

                    if idx < input.len() {
                        let event = input[idx];
                        cols.op_a = F::from_canonical_u32(event.0);
                        cols.op_b = F::from_canonical_u32(event.1);
                        cols.op_c = F::from_canonical_u32(event.2);
                    }
                });
            },
        );
        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MINIMAL_ADD_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.is_empty()
    }
}

impl<AB> Air<AB> for MinimalAddChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MinimalAddCols<AB::Var> = (*local).borrow();

        builder.assert_eq(local.op_a, local.op_b + local.op_c + AB::Expr::one());
    }
}

impl std::fmt::Debug for MinimalAddChip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MinimalAddChip")
    }
}

/// A minimal chip with a preprocessed column, used to exercise the zerocheck prover on chips
/// with preprocessed traces. The constraint `a^3 = p + 1` is cubic in the trace and does not
/// hold on zero-padded rows.
#[derive(Default, Clone)]
pub struct MinimalCubeChip;

impl<F> BaseAir<F> for MinimalCubeChip {
    fn width(&self) -> usize {
        1
    }
}

impl<F: PrimeField32> MachineAir<F> for MinimalCubeChip {
    type Record = Vec<(u32, u32, u32)>;

    type Program = Program;

    fn name(&self) -> &'static str {
        "MinimalCube"
    }

    fn preprocessed_width(&self) -> usize {
        1
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        Some(input.len())
    }

    fn generate_trace_into(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _buffer: &mut [std::mem::MaybeUninit<F>],
    ) {
        unimplemented!();
    }

    fn generate_trace(&self, _input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        unimplemented!();
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.is_empty()
    }
}

impl<AB> Air<AB> for MinimalCubeChip
where
    AB: SP1AirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let a = main.row_slice(0)[0];
        let preprocessed = builder.preprocessed();
        let p = preprocessed.row_slice(0)[0];

        builder.assert_eq(a * a * a, p.into() + AB::Expr::one());
    }
}

impl std::fmt::Debug for MinimalCubeChip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MinimalCubeChip")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use std::sync::Arc;

    use itertools::Itertools;
    use rand::Rng;
    use slop_air::Air;
    use slop_algebra::{extension::BinomialExtensionField, AbstractField};
    use slop_alloc::CpuBackend;
    use slop_challenger::IopCtx;
    use slop_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
    use slop_multilinear::{full_geq, Mle, MleEval, PaddedMle, Padding, Point, VirtualGeq};
    use slop_sumcheck::{partially_verify_sumcheck_proof, reduce_sumcheck_to_evaluation};
    use slop_uni_stark::get_symbolic_constraints;
    use sp1_hypercube::{
        air::MachineAir,
        debug_constraints,
        prover::{ZeroCheckPoly, ZerocheckCpuProverData},
        AirOpenedValues, Chip, ChipOpenedValues, ConstraintSumcheckFolder, InnerSC, ShardVerifier,
        PROOF_MAX_NUM_PVS,
    };
    use sp1_primitives::{SP1Field, SP1GlobalContext};

    use crate::utils::{setup_logger, MinimalAddChip, NUM_MINIMAL_ADD_COLS};

    use super::MinimalCubeChip;

    type F = sp1_primitives::SP1Field;
    type EF = BinomialExtensionField<F, 4>;

    /// Builds a zerocheck polynomial and its sumcheck claim for a `MinimalAddChip` trace with
    /// the given number of real rows, mirroring the setup done by the shard prover.
    fn make_minimal_add_zerocheck_poly(
        rng: &mut impl Rng,
        zeta: &Point<EF>,
        num_real_entries: usize,
        num_variables: u32,
    ) -> (ZeroCheckPoly<F, F, EF, MinimalAddChip>, EF) {
        let air = MinimalAddChip;

        let mut shard = Vec::new();
        for _ in 0..num_real_entries {
            let operand_1 = rng.gen_range(0..(u16::MAX as u32));
            let operand_2 = rng.gen_range(0..(u16::MAX as u32));
            let result = operand_1.wrapping_add(operand_2) + 1;
            shard.push((result, operand_1, operand_2));
        }

        let main_trace = if num_real_entries == 0 {
            PaddedMle::zeros(NUM_MINIMAL_ADD_COLS, num_variables)
        } else {
            let trace = MinimalAddChip::generate_trace(&air, &shard, &mut Vec::new());
            PaddedMle::new(
                Some(Arc::new(trace.into())),
                num_variables,
                Padding::Constant((F::zero(), NUM_MINIMAL_ADD_COLS, CpuBackend)),
            )
        };

        let alpha = rng.gen::<EF>();
        let gkr_power = rng.gen::<EF>();

        let num_constraints = get_symbolic_constraints::<F, _>(&air, 0, PROOF_MAX_NUM_PVS).len();
        let mut alpha_powers = alpha.powers().take(num_constraints).collect::<Vec<_>>();
        alpha_powers.reverse();
        let gkr_powers = gkr_power.powers().take(NUM_MINIMAL_ADD_COLS).collect::<Vec<_>>();

        let public_values = vec![F::zero(); PROOF_MAX_NUM_PVS];
        let dummy_main = vec![F::zero(); NUM_MINIMAL_ADD_COLS];
        let mut folder = ConstraintSumcheckFolder {
            preprocessed: RowMajorMatrixView::new_row(&[]),
            main: RowMajorMatrixView::new_row(&dummy_main),
            accumulator: EF::zero(),
            public_values: &public_values,
            constraint_index: 0,
            powers_of_alpha: &alpha_powers,
        };
        air.eval(&mut folder);
        let padded_row_adjustment = folder.accumulator;

        let gkr_openings: MleEval<EF> = main_trace.eval_at(zeta);
        let claim = gkr_openings
            .evaluations()
            .as_slice()
            .iter()
            .zip_eq(gkr_powers.iter())
            .map(|(opening, power)| *opening * *power)
            .sum::<EF>();

        let air_data = ZerocheckCpuProverData::round_prover(
            Arc::new(air),
            Arc::new(public_values),
            Arc::new(alpha_powers),
            Arc::new(gkr_powers),
        );

        let virtual_geq =
            VirtualGeq::new(num_real_entries as u32, F::one(), F::zero(), num_variables);
        let geq_value = if num_real_entries > 0 { EF::zero() } else { EF::one() };

        let poly = ZeroCheckPoly::new(
            air_data,
            zeta.clone(),
            None,
            main_trace,
            EF::one(),
            geq_value,
            padded_row_adjustment,
            virtual_geq,
        );
        (poly, claim)
    }

    /// Builds a zerocheck polynomial and its sumcheck claim for a `MinimalCubeChip` trace,
    /// which exercises the preprocessed trace handling of the zerocheck prover.
    fn make_minimal_cube_zerocheck_poly(
        rng: &mut impl Rng,
        zeta: &Point<EF>,
        num_real_entries: usize,
        num_variables: u32,
    ) -> (ZeroCheckPoly<F, F, EF, MinimalCubeChip>, EF) {
        let air = MinimalCubeChip;

        let mut main_values = Vec::with_capacity(num_real_entries);
        let mut preprocessed_values = Vec::with_capacity(num_real_entries);
        for _ in 0..num_real_entries {
            let a = rng.gen::<F>();
            main_values.push(a);
            preprocessed_values.push(a * a * a - F::one());
        }

        let (main_trace, preprocessed_trace) = if num_real_entries == 0 {
            (PaddedMle::zeros(1, num_variables), PaddedMle::zeros(1, num_variables))
        } else {
            let padding = || Padding::Constant((F::zero(), 1, CpuBackend));
            (
                PaddedMle::new(
                    Some(Arc::new(RowMajorMatrix::new(main_values, 1).into())),
                    num_variables,
                    padding(),
                ),
                PaddedMle::new(
                    Some(Arc::new(RowMajorMatrix::new(preprocessed_values, 1).into())),
                    num_variables,
                    padding(),
                ),
            )
        };

        let alpha = rng.gen::<EF>();
        let gkr_power = rng.gen::<EF>();

        let num_constraints = get_symbolic_constraints::<F, _>(&air, 1, PROOF_MAX_NUM_PVS).len();
        let mut alpha_powers = alpha.powers().take(num_constraints).collect::<Vec<_>>();
        alpha_powers.reverse();
        // One power for the main column, one for the preprocessed column.
        let gkr_powers = gkr_power.powers().take(2).collect::<Vec<_>>();

        let public_values = vec![F::zero(); PROOF_MAX_NUM_PVS];
        let dummy_row = vec![F::zero(); 1];
        let mut folder = ConstraintSumcheckFolder {
            preprocessed: RowMajorMatrixView::new_row(&dummy_row),
            main: RowMajorMatrixView::new_row(&dummy_row),
            accumulator: EF::zero(),
            public_values: &public_values,
            constraint_index: 0,
            powers_of_alpha: &alpha_powers,
        };
        air.eval(&mut folder);
        let padded_row_adjustment = folder.accumulator;

        // The openings are batched in the order main columns, then preprocessed columns.
        let main_openings: MleEval<EF> = main_trace.eval_at(zeta);
        let preprocessed_openings: MleEval<EF> = preprocessed_trace.eval_at(zeta);
        let claim = main_openings
            .evaluations()
            .as_slice()
            .iter()
            .chain(preprocessed_openings.evaluations().as_slice().iter())
            .zip_eq(gkr_powers.iter())
            .map(|(opening, power)| *opening * *power)
            .sum::<EF>();

        let air_data = ZerocheckCpuProverData::round_prover(
            Arc::new(air),
            Arc::new(public_values),
            Arc::new(alpha_powers),
            Arc::new(gkr_powers),
        );

        let virtual_geq =
            VirtualGeq::new(num_real_entries as u32, F::one(), F::zero(), num_variables);
        let geq_value = if num_real_entries > 0 { EF::zero() } else { EF::one() };

        let poly = ZeroCheckPoly::new(
            air_data,
            zeta.clone(),
            Some(preprocessed_trace),
            main_trace,
            EF::one(),
            geq_value,
            padded_row_adjustment,
            virtual_geq,
        );
        (poly, claim)
    }

    #[test]
    fn test_zerocheck() {
        setup_logger();
        let mut rng = rand::thread_rng();
        let air = MinimalAddChip::default();
        let num_real_entries = 65;
        let num_variables = 7;

        let mut shard = Vec::new();

        for _ in 0..num_real_entries {
            let operand_1 = rand::thread_rng().gen_range(0..(u16::MAX as u32));
            let operand_2 = rand::thread_rng().gen_range(0..(u16::MAX as u32));

            let result = operand_1.wrapping_add(operand_2) + 1;

            shard.push((result, operand_1, operand_2));
        }

        let virtually_padded_trace =
            MinimalAddChip::generate_trace(&MinimalAddChip, &shard, &mut Vec::new());

        assert!(<MinimalAddChip as MachineAir<F>>::preprocessed_width(&air) == 0);

        let alpha = rng.gen::<EF>();
        let gkr_power = rng.gen::<EF>();

        let num_constraints = get_symbolic_constraints::<F, _>(&air, 0, PROOF_MAX_NUM_PVS).len();

        let mut alpha_powers = alpha.powers().take(num_constraints).collect::<Vec<_>>();

        alpha_powers.reverse();

        let gkr_powers = gkr_power.powers().take(NUM_MINIMAL_ADD_COLS).collect::<Vec<_>>();

        let main_trace = PaddedMle::new(
            Some(Arc::new(virtually_padded_trace.clone().into())),
            num_variables,
            Padding::Constant((F::zero(), NUM_MINIMAL_ADD_COLS, CpuBackend)),
        );

        let virtual_geq =
            VirtualGeq::new(num_real_entries as u32, F::one(), F::zero(), num_variables);

        let air_data = ZerocheckCpuProverData::round_prover(
            Arc::new(air),
            Arc::new(vec![F::zero(); PROOF_MAX_NUM_PVS]),
            Arc::new(alpha_powers.clone()),
            Arc::new(gkr_powers.clone()),
        );

        let dummy_main = vec![F::zero(); NUM_MINIMAL_ADD_COLS];

        let mut folder = ConstraintSumcheckFolder {
            preprocessed: RowMajorMatrixView::new_row(&[]),
            main: RowMajorMatrixView::new_row(&dummy_main),
            accumulator: EF::zero(),
            public_values: &vec![F::zero(); PROOF_MAX_NUM_PVS],
            constraint_index: 0,
            powers_of_alpha: &alpha_powers,
        };

        let air = MinimalAddChip::default();

        air.eval(&mut folder);
        let padded_row_adjustment = folder.accumulator;

        let zeta = Point::rand(&mut rng, num_variables);

        let gkr_openings: MleEval<EF> = main_trace.eval_at(&zeta);

        let sumcheck_claim = gkr_openings
            .evaluations()
            .as_slice()
            .iter()
            .zip_eq(gkr_powers.iter())
            .map(|(a, b)| *a * *b)
            .sum::<EF>();

        let zerocheck_poly = ZeroCheckPoly::<F, F, EF, _>::new(
            air_data,
            zeta.clone(),
            None,
            main_trace.clone(),
            EF::one(),
            EF::zero(),
            padded_row_adjustment,
            virtual_geq,
        );

        let claims = vec![sumcheck_claim];
        let t = 1;
        let lambda = EF::zero();

        let mut challenger = SP1GlobalContext::default_challenger();

        let (proof, column_openings) =
            reduce_sumcheck_to_evaluation(vec![zerocheck_poly], &mut challenger, claims, t, lambda);

        let chip_eval_claim = proof.point_and_eval.1;
        let chip_eval_point = proof.point_and_eval.0.clone();

        let column_openings = &column_openings[0];

        assert_eq!(column_openings, &main_trace.eval_at(&chip_eval_point).to_vec());

        let opening = ChipOpenedValues::<F, EF> {
            preprocessed: AirOpenedValues { local: vec![] },
            main: AirOpenedValues { local: column_openings.clone() },
            degree: Point::from_usize(num_real_entries as usize, num_variables as usize + 1),
        };

        let openings_batch = column_openings
            .iter()
            .zip_eq(gkr_powers.iter())
            .map(|(opening, power)| *opening * *power)
            .sum::<EF>();

        let public_values = vec![F::zero(); PROOF_MAX_NUM_PVS];

        let zerocheck_eq_val = Mle::full_lagrange_eval(&zeta, &chip_eval_point);

        let mut challenger = SP1GlobalContext::default_challenger();

        let padded_row_adjustment =
            ShardVerifier::<SP1GlobalContext, InnerSC<_>>::compute_padded_row_adjustment(
                &Chip::new(MinimalAddChip::default()),
                alpha,
                &public_values,
            );

        let mut point_extended = chip_eval_point.clone();
        point_extended.add_dimension(EF::zero());

        let geq_val = full_geq(&opening.degree, &point_extended);

        let eval = ShardVerifier::<SP1GlobalContext, InnerSC<_>>::eval_constraints(
            &Chip::new(MinimalAddChip::default()),
            &opening,
            alpha,
            &public_values,
        );

        let constraint_eval = eval - padded_row_adjustment * geq_val;

        partially_verify_sumcheck_proof(&proof, &mut challenger, num_variables as usize, 4)
            .unwrap();
        assert_eq!(chip_eval_claim, zerocheck_eq_val * (constraint_eval + openings_batch));
    }

    /// Checks that the zerocheck prover with fused first two rounds produces exactly the same
    /// proof as the generic round-by-round sumcheck prover, and that the proof verifies.
    #[test]
    fn test_zerocheck_fused_first_two_rounds() {
        setup_logger();
        let mut rng = rand::thread_rng();

        // Chip heights covering all residues mod 4, full traces, single rows, fully padded
        // chips, and the minimum numbers of variables.
        let cases: Vec<(usize, Vec<usize>)> = vec![
            (7, vec![65]),
            (7, vec![128, 1, 67]),
            (7, vec![2, 66]),
            (7, vec![3, 0, 64]),
            (7, vec![4, 5]),
            (2, vec![1, 2, 3, 4]),
            (1, vec![1, 2]),
        ];

        for (num_variables, heights) in cases {
            let zeta = Point::<EF>::rand(&mut rng, num_variables as u32);
            let lambda = rng.gen::<EF>();
            // The lookahead depth of the fused prover; traces with a single variable only
            // support the plain first round.
            let lookahead = num_variables.min(2);

            let (add_polys, add_claims): (Vec<_>, Vec<_>) = heights
                .iter()
                .map(|&height| {
                    make_minimal_add_zerocheck_poly(&mut rng, &zeta, height, num_variables as u32)
                })
                .unzip();

            // A chip with a preprocessed trace always has a non-empty one in production, so only
            // non-zero heights are exercised for the cube chip.
            let (cube_polys, cube_claims): (Vec<_>, Vec<_>) = heights
                .iter()
                .filter(|&&height| height > 0)
                .map(|&height| {
                    make_minimal_cube_zerocheck_poly(&mut rng, &zeta, height, num_variables as u32)
                })
                .unzip();

            // Run the generic and the fused prover on identical inputs and transcripts.
            let mut challenger_generic = SP1GlobalContext::default_challenger();
            let (add_proof_generic, add_evals_generic) = reduce_sumcheck_to_evaluation(
                add_polys.clone(),
                &mut challenger_generic,
                add_claims.clone(),
                1,
                lambda,
            );

            let mut challenger_fused = SP1GlobalContext::default_challenger();
            let (add_proof_fused, add_evals_fused) = reduce_sumcheck_to_evaluation(
                add_polys,
                &mut challenger_fused,
                add_claims,
                lookahead,
                lambda,
            );

            assert_eq!(
                add_proof_generic.univariate_polys, add_proof_fused.univariate_polys,
                "add chip messages differ for {num_variables} variables, heights {heights:?}"
            );
            assert_eq!(add_proof_generic.claimed_sum, add_proof_fused.claimed_sum);
            assert_eq!(add_proof_generic.point_and_eval, add_proof_fused.point_and_eval);
            assert_eq!(add_evals_generic, add_evals_fused);

            let mut challenger_verify = SP1GlobalContext::default_challenger();
            partially_verify_sumcheck_proof(
                &add_proof_fused,
                &mut challenger_verify,
                num_variables,
                4,
            )
            .unwrap();

            let mut challenger_generic = SP1GlobalContext::default_challenger();
            let (cube_proof_generic, cube_evals_generic) = reduce_sumcheck_to_evaluation(
                cube_polys.clone(),
                &mut challenger_generic,
                cube_claims.clone(),
                1,
                lambda,
            );

            let mut challenger_fused = SP1GlobalContext::default_challenger();
            let (cube_proof_fused, cube_evals_fused) = reduce_sumcheck_to_evaluation(
                cube_polys,
                &mut challenger_fused,
                cube_claims,
                lookahead,
                lambda,
            );

            assert_eq!(
                cube_proof_generic.univariate_polys, cube_proof_fused.univariate_polys,
                "cube chip messages differ for {num_variables} variables, heights {heights:?}"
            );
            assert_eq!(cube_proof_generic.claimed_sum, cube_proof_fused.claimed_sum);
            assert_eq!(cube_proof_generic.point_and_eval, cube_proof_fused.point_and_eval);
            assert_eq!(cube_evals_generic, cube_evals_fused);

            let mut challenger_verify = SP1GlobalContext::default_challenger();
            partially_verify_sumcheck_proof(
                &cube_proof_fused,
                &mut challenger_verify,
                num_variables,
                4,
            )
            .unwrap();
        }
    }

    #[test]
    fn test_debug_constraints() {
        setup_logger();
        let num_real_entries = 65;

        let mut shard = Vec::new();

        for _ in 0..num_real_entries {
            let operand_1 = rand::thread_rng().gen_range(0..(u16::MAX as u32));
            let operand_2 = rand::thread_rng().gen_range(0..(u16::MAX as u32));

            let result = operand_1.wrapping_add(operand_2) + 1;

            shard.push((result, operand_1, operand_2));
        }

        let virtually_padded_trace: RowMajorMatrix<SP1Field> =
            MinimalAddChip::generate_trace(&MinimalAddChip, &shard, &mut Vec::new());

        let main_trace: Mle<SP1Field> = Mle::from(virtually_padded_trace);

        debug_constraints::<SP1GlobalContext, _>(
            &Chip::new(MinimalAddChip::default()),
            None,
            &main_trace,
            &[],
        );
    }

    #[test]
    fn test_debug_constraints_failing() {
        setup_logger();
        let num_real_entries = 65;

        let mut shard = Vec::new();

        for i in 0..num_real_entries {
            let operand_1 = rand::thread_rng().gen_range(0..(u16::MAX as u32));
            let operand_2 = rand::thread_rng().gen_range(0..(u16::MAX as u32));

            let mut result = operand_1.wrapping_add(operand_2) + 1;

            if i == 27 {
                result += 42;
            }

            shard.push((result, operand_1, operand_2));
        }

        let virtually_padded_trace: RowMajorMatrix<SP1Field> =
            MinimalAddChip::generate_trace(&MinimalAddChip, &shard, &mut Vec::new());

        let main_trace: Mle<SP1Field> = Mle::from(virtually_padded_trace);

        debug_constraints::<SP1GlobalContext, _>(
            &Chip::new(MinimalAddChip::default()),
            None,
            &main_trace,
            &[],
        );
    }
}
