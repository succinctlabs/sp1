use std::{iter::repeat_n, marker::PhantomData};

use itertools::{izip, Itertools};
use slop_algebra::AbstractField;
use slop_jagged::{
    BooleanityBatchedProof, IncBranchingProgram, JaggedLittlePolynomialVerifierParams,
    JaggedSumcheckEvalProof, LOG_NUM_BITS, NUM_BITS, PREFIX_SUM_BITS,
};
use slop_multilinear::{partial_lagrange_blocking, Mle, MleEval, Point};
use slop_sumcheck::PartialSumcheckProof;
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Ext, Felt, SymbolicExt, SymbolicFelt},
};

use crate::{
    basefold::{
        stacked::{RecursiveStackedPcsProof, RecursiveStackedPcsVerifier},
        RecursiveBasefoldProof, RecursiveBasefoldVerifier,
    },
    challenger::FieldChallengerVariable,
    sumcheck::{evaluate_mle_ext, verify_sumcheck},
    symbolic::IntoSymbolic,
    CircuitConfig, SP1FieldConfigVariable,
};

use super::jagged_eval::{
    JaggedEvalPoints, RecursiveJaggedEvalConfig, RecursiveJaggedEvalSumcheckConfig,
};

/// MSB-first bit-decomposition of an integer as a `Point<SymbolicExt>` (matches
/// `Point::from_usize`).
fn int_as_ext_point(value: usize, dim: usize) -> Point<SymbolicExt<SP1Field, SP1ExtensionField>> {
    (0..dim)
        .rev()
        .map(|b| {
            let bit = ((value >> b) & 1) as u32;
            SymbolicExt::<SP1Field, SP1ExtensionField>::from_canonical_u32(bit)
        })
        .collect()
}

/// In-circuit analogue of `slop_jagged::BooleanityBatched`.  Holds the two
/// integer-ish parameters (`num_real_cols` and the MSB-first bit-decomp of
/// `max_prefix_sum`); the `verify_in_circuit` method takes the per-protocol-run
/// values (proof, η, two-stage finals, α, ρ_bit) as arguments.
pub(crate) struct RecursiveBooleanityBatched<'a> {
    pub num_real_cols: usize,
    pub max_prefix_sum_bits: &'a Point<Felt<SP1Field>>,
}

impl<'a> RecursiveBooleanityBatched<'a> {
    pub(crate) fn new(
        num_real_cols: usize,
        max_prefix_sum_bits: &'a Point<Felt<SP1Field>>,
    ) -> Self {
        Self { num_real_cols, max_prefix_sum_bits }
    }
}

impl<'a> RecursiveBooleanityBatched<'a> {
    /// In-circuit analogue of `slop_jagged::BooleanityBatched::verify`.
    /// Returns `(combined_point, p_claim)` where `combined_point = z_new ⧺ ρ_bit`
    /// and `p_claim = Σ_b eq(ρ_bit, b) · p_b(z_new)`.
    pub(crate) fn verify_in_circuit<C: CircuitConfig, SC: SP1FieldConfigVariable<C>>(
        &self,
        builder: &mut Builder<C>,
        challenger: &mut SC::FriChallengerVariable,
        proof: &BooleanityBatchedProof<Ext<SP1Field, SP1ExtensionField>>,
        two_stage: &slop_jagged::TwoStageEqProductProof<Ext<SP1Field, SP1ExtensionField>>,
        alpha: SymbolicExt<SP1Field, SP1ExtensionField>,
        rho_bit: &Point<SymbolicExt<SP1Field, SP1ExtensionField>>,
    ) -> (Point<SymbolicExt<SP1Field, SP1ExtensionField>>, SymbolicExt<SP1Field, SP1ExtensionField>)
    {
        let RecursiveBooleanityBatched { num_real_cols, max_prefix_sum_bits } = *self;
        // η from the two-stage GKR's stage-2 sumcheck point, lifted to SymbolicExt.
        let z: Point<SymbolicExt<SP1Field, SP1ExtensionField>> =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(
                &two_stage.stage2.point_and_eval.0,
            );
        let z = &z;
        // Same split as the CPU `slop_jagged::split_two_stage_finals`.
        let v_curr: Vec<SymbolicExt<SP1Field, SP1ExtensionField>> = (0..NUM_BITS)
            .map(|b| two_stage.final_evals[2 * (PREFIX_SUM_BITS - 1 - b) + 1].into())
            .collect();
        let v_next: Vec<SymbolicExt<SP1Field, SP1ExtensionField>> = (0..NUM_BITS)
            .map(|b| two_stage.final_evals[2 * (PREFIX_SUM_BITS - 1 - b)].into())
            .collect();
        let v_next = v_next.as_slice();
        let v_curr = v_curr.as_slice();
        assert_eq!(proof.final_evals.len(), NUM_BITS);
        assert_eq!(v_next.len(), NUM_BITS);
        assert_eq!(v_curr.len(), NUM_BITS);
        assert_eq!(rho_bit.dimension(), LOG_NUM_BITS);
        assert!(num_real_cols >= 1);

        let c = z.dimension();
        let zero = SymbolicExt::<SP1Field, SP1ExtensionField>::zero();

        // eq_rho[b] = eq(ρ_bit, b) — partial_lagrange table over the 5-dim ρ_bit.
        let eq_rho_tensor = partial_lagrange_blocking(rho_bit);
        let eq_rho: &[SymbolicExt<SP1Field, SP1ExtensionField>] =
            eq_rho_tensor.as_buffer().as_slice();

        // eq_at_boundary = eq(z, num_real_cols - 1).
        let boundary_pt = int_as_ext_point(num_real_cols - 1, c);
        let eq_at_boundary = Mle::full_lagrange_eval(&boundary_pt, z);

        let alpha_sq = alpha * alpha;

        // λ[b] = bit b (LSB-indexed) of max_prefix_sum, lifted from the bit-Felts.
        // `max_prefix_sum_bits` is the MSB-first Point<Felt>; bit b lives at
        // index `prefix_sum_dim - 1 - b`.  Bits b >= prefix_sum_dim are zero.
        let prefix_sum_dim = max_prefix_sum_bits.dimension();
        assert!(prefix_sum_dim <= NUM_BITS);
        let lambda: Vec<SymbolicExt<SP1Field, SP1ExtensionField>> = (0..NUM_BITS)
            .map(|b| {
                if b < prefix_sum_dim {
                    let felt = *max_prefix_sum_bits[prefix_sum_dim - 1 - b];
                    SymbolicExt::<SP1Field, SP1ExtensionField>::Base(SymbolicFelt::from(felt))
                } else {
                    zero
                }
            })
            .collect();

        // Initial claim check.
        let expected_initial_claim: SymbolicExt<SP1Field, SP1ExtensionField> = (0..NUM_BITS)
            .map(|b| eq_rho[b] * (v_next[b] + alpha_sq * v_curr[b] - lambda[b] * eq_at_boundary))
            .fold(zero, |acc, term| acc + term);
        let claimed_sum_sym: SymbolicExt<SP1Field, SP1ExtensionField> =
            proof.partial_sumcheck_proof.claimed_sum.into();
        builder.assert_ext_eq(expected_initial_claim, claimed_sum_sym);

        // Verify the inner sumcheck (degree 3 over c variables).
        verify_sumcheck::<C, SC>(builder, challenger, &proof.partial_sumcheck_proof);

        // Final consistency check at z_new = proof.point_and_eval.0.
        let z_new_sym: Point<SymbolicExt<SP1Field, SP1ExtensionField>> =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(
                &proof.partial_sumcheck_proof.point_and_eval.0,
            );

        // inc_zn = IncBranchingProgram::new(c, num_real_cols).eval(z, z_new).
        let inc_bp = IncBranchingProgram::new(c, num_real_cols);
        let inc_zn = inc_bp.eval(z, &z_new_sym);

        // eq_zn = eq(z, z_new).
        let eq_zn = Mle::full_lagrange_eval(z, &z_new_sym);

        let final_evals_sym: Vec<SymbolicExt<SP1Field, SP1ExtensionField>> =
            proof.final_evals.iter().map(|x| (*x).into()).collect();

        let eq_times_evals =
            (0..NUM_BITS).map(|b| eq_rho[b] * final_evals_sym[b]).collect::<Vec<_>>();

        let sum_p: SymbolicExt<SP1Field, SP1ExtensionField> = eq_times_evals.iter().copied().sum();
        let sum_p_sq: SymbolicExt<SP1Field, SP1ExtensionField> =
            eq_times_evals.iter().zip(final_evals_sym.iter()).map(|(a, b)| *a * *b).sum();

        let aa_minus_a = alpha_sq - alpha;
        let expected_final = (inc_zn + aa_minus_a * eq_zn) * sum_p + alpha * eq_zn * sum_p_sq;
        let point_eval_sym: SymbolicExt<SP1Field, SP1ExtensionField> =
            proof.partial_sumcheck_proof.point_and_eval.1.into();
        builder.assert_ext_eq(expected_final, point_eval_sym);

        // combined_point = z_new ⧺ ρ_bit; p_claim = sum_p.
        let combined_point: Point<SymbolicExt<SP1Field, SP1ExtensionField>> =
            z_new_sym.iter().copied().chain(rho_bit.iter().copied()).collect::<Vec<_>>().into();
        (combined_point, sum_p)
    }
}

pub struct RecursivePcsImpl<C, SC, P> {
    _marker: PhantomData<(C, SC, P)>,
}

pub struct JaggedPcsProofVariable<Proof, Digest> {
    pub params: JaggedLittlePolynomialVerifierParams<Felt<SP1Field>>,
    pub sumcheck_proof: PartialSumcheckProof<Ext<SP1Field, SP1ExtensionField>>,
    pub jagged_eval_proof: JaggedSumcheckEvalProof<Ext<SP1Field, SP1ExtensionField>>,
    /// Booleanity-batched sumcheck — read so the witness shape matches the
    /// host proof, but not yet verified by the recursive verifier (the
    /// host-side verifier handles it; recursion will catch up in a follow-up).
    pub boolean_batched_proof:
        slop_jagged::BooleanityBatchedProof<Ext<SP1Field, SP1ExtensionField>>,
    pub pcs_proof: RecursiveStackedPcsProof<Proof, SP1Field, SP1ExtensionField>,
    pub column_counts: Vec<Vec<usize>>,
    pub row_counts: Vec<Vec<Felt<SP1Field>>>,
    pub original_commitments: Vec<Digest>,
    pub expected_eval: Ext<SP1Field, SP1ExtensionField>,
}

#[derive(Clone)]
pub struct RecursiveJaggedPcsVerifier<SC: SP1FieldConfigVariable<C>, C: CircuitConfig> {
    pub stacked_pcs_verifier: RecursiveStackedPcsVerifier<RecursiveBasefoldVerifier<C, SC>>,
    pub max_log_row_count: usize,
    pub jagged_evaluator: RecursiveJaggedEvalSumcheckConfig<SC>,
}

/// Per-round commitment data: the round digests + the cumulative column-count
/// offsets that say where each round's "artificial" padding column lives in
/// the flattened evaluation-claims vector.
pub struct RoundCommitments<'a, D> {
    pub commitments: &'a [D],
    pub insertion_points: &'a [usize],
}

impl<SC: SP1FieldConfigVariable<C>, C: CircuitConfig> RecursiveJaggedPcsVerifier<SC, C> {
    pub fn verify_trusted_evaluations(
        &self,
        builder: &mut Builder<C>,
        round_commits: RoundCommitments<'_, SC::DigestVariable>,
        point: Point<Ext<SP1Field, SP1ExtensionField>>,
        evaluation_claims: &[MleEval<Ext<SP1Field, SP1ExtensionField>>],
        proof: &JaggedPcsProofVariable<RecursiveBasefoldProof<C, SC>, SC::DigestVariable>,
        challenger: &mut SC::FriChallengerVariable,
    ) -> Vec<Felt<SP1Field>> {
        let RoundCommitments { commitments, insertion_points } = round_commits;
        let JaggedPcsProofVariable {
            pcs_proof,
            sumcheck_proof,
            jagged_eval_proof,
            params,
            column_counts,
            original_commitments,
            expected_eval,
            ..
        } = proof;
        let num_col_variables = (params.col_prefix_sums.len() - 1).next_power_of_two().ilog2();

        let z_col =
            (0..num_col_variables).map(|_| challenger.sample_ext(builder)).collect::<Point<_>>();

        let z_row = point;

        // Collect the claims for the different polynomials.
        let mut column_claims = evaluation_claims.iter().flatten().copied().collect::<Vec<_>>();

        let added_columns: Vec<usize> =
            column_counts.iter().map(|cc| cc[cc.len() - 2] + 1).collect();
        // For each commit, Rizz needed a commitment to a vector of length a multiple of
        // 1 << self.pcs.log_stacking_height, and this is achieved by adding a single column of
        // zeroes as the last matrix of the commitment. We insert these "artificial" zeroes
        // into the evaluation claims.
        let zero_ext: Ext<SP1Field, SP1ExtensionField> =
            builder.constant(SP1ExtensionField::zero());
        for (insertion_point, num_added_columns) in
            insertion_points.iter().rev().zip(added_columns.iter().rev())
        {
            for _ in 0..*num_added_columns {
                column_claims.insert(*insertion_point, zero_ext);
            }
        }

        for (round_column_counts, round_row_counts, modified_commitment, original_commitment) in izip!(
            column_counts.iter(),
            proof.row_counts.iter(),
            commitments.iter(),
            original_commitments.iter()
        ) {
            let mut felts_vec: Vec<Felt<_>> =
                vec![builder.eval(SP1Field::from_canonical_usize(round_column_counts.len()))];
            for &count in round_row_counts {
                felts_vec.push(builder.eval(count));
            }

            for &count in round_column_counts {
                felts_vec.push(builder.eval(SP1Field::from_canonical_usize(count)));
            }
            let hash = SC::hash(builder, &felts_vec);
            let expected_commitment = SC::compress(builder, [*original_commitment, hash]);

            SC::assert_digest_eq(builder, expected_commitment, *modified_commitment);
        }

        // Pad the column claims to the next power of two.
        column_claims.resize(column_claims.len().next_power_of_two(), zero_ext);

        let column_mle = Mle::from(column_claims);
        let sumcheck_claim: Ext<SP1Field, SP1ExtensionField> =
            evaluate_mle_ext(builder, column_mle, z_col.clone())[0];

        builder.assert_ext_eq(sumcheck_claim, sumcheck_proof.claimed_sum);

        builder.cycle_tracker_v2_enter("jagged - verify sumcheck");
        verify_sumcheck::<C, SC>(builder, challenger, sumcheck_proof);
        builder.cycle_tracker_v2_exit();

        builder.cycle_tracker_v2_enter("jagged - jagged-eval");
        let (jagged_eval, prefix_sum_felts) = self.jagged_evaluator.jagged_evaluation(
            builder,
            params,
            JaggedEvalPoints { z_row, z_col, z_trace: sumcheck_proof.point_and_eval.0.clone() },
            jagged_eval_proof,
            challenger,
        );
        builder.cycle_tracker_v2_exit();

        // Check the prefix_sum_felts against the row counts.
        let repeated_flattened_row_counts: Vec<Felt<SP1Field>> = proof
            .row_counts
            .iter()
            .flatten()
            .zip_eq(column_counts.iter().flatten())
            .flat_map(|(row, col)| repeat_n(*row, *col))
            .collect();

        let mut acc: Felt<_> = builder.constant(SP1Field::zero());

        for (row_count, expected) in
            repeated_flattened_row_counts.iter().zip_eq(prefix_sum_felts.iter())
        {
            builder.assert_felt_eq(acc, *expected);
            acc = builder.eval(acc + *row_count)
        }
        let mut final_area = SymbolicFelt::zero();
        let two: Felt<_> = builder.constant(SP1Field::two());
        for bit in proof.params.col_prefix_sums.iter().last().unwrap().iter() {
            final_area = *bit + two * final_area;
        }
        builder.assert_felt_eq(acc, final_area);

        // Compute the expected evaluation of the dense trace polynomial.
        builder.assert_ext_eq(jagged_eval * *expected_eval, sumcheck_proof.point_and_eval.1);

        // ----- Booleanity-batched sumcheck + inline aux MLE eval check. -----
        //
        // Mirrors CPU `slop_jagged::verifier::verify_trusted_evaluations`: the
        // CPU samples (α, ρ_bit), runs `verify_boolean_batched` to reduce the
        // 64 (curr+next) two-stage finals at η to a combined claim
        // `p_claim` at `(z_new, ρ_bit)` on the `[NUM_BITS, 2^c]` curr-bit
        // MLE, then verifies that `p_claim` matches the deterministic eval
        // of that MLE — computed from the *public* `usize_prefix_sums`
        // (already represented in `params.col_prefix_sums` as MSB-first
        // bit-Felts).  No second_stream_data is sent; the verifier
        // reconstructs the MLE inline.
        builder.cycle_tracker_v2_enter("jagged - booleanity-batched verify");
        let two_stage = &jagged_eval_proof.two_stage_proof;

        let alpha_bb: SymbolicExt<SP1Field, SP1ExtensionField> =
            challenger.sample_ext(builder).into();
        let rho_bit: Point<SymbolicExt<SP1Field, SP1ExtensionField>> =
            (0..LOG_NUM_BITS).map(|_| challenger.sample_ext(builder).into()).collect();

        let max_prefix_sum_bits = params.col_prefix_sums.iter().last().unwrap().clone();
        let num_real_cols = params.col_prefix_sums.len() - 1;
        let (combined_point, p_claim) =
            RecursiveBooleanityBatched::new(num_real_cols, &max_prefix_sum_bits)
                .verify_in_circuit::<C, SC>(
                    builder,
                    challenger,
                    &proof.boolean_batched_proof,
                    two_stage,
                    alpha_bb,
                    &rho_bit,
                );
        builder.cycle_tracker_v2_exit();

        // Inline aux MLE eval check.  The combined_point = z_new ⧺ ρ_bit.
        // The deterministic curr-bit MLE eval at (z_new, ρ_bit) is
        //   Σ_{col<num_real_cols} eq(z_new, col)
        //     · Σ_{b<NUM_BITS} eq(ρ_bit, b) · bit_b(usize_prefix_sums[col])
        // and `params.col_prefix_sums[col]` is the MSB-first bit-Felt
        // decomposition we use to read those bits in-circuit.
        builder.cycle_tracker_v2_enter("jagged - inline aux MLE eval check");
        let c = num_real_cols.next_power_of_two().ilog2() as usize;
        debug_assert_eq!(combined_point.dimension(), c + LOG_NUM_BITS);
        let z_new_sym: Point<SymbolicExt<SP1Field, SP1ExtensionField>> =
            combined_point.iter().take(c).copied().collect::<Vec<_>>().into();

        // eq_z_new[col] = eq(z_new, col) — partial Lagrange table.
        let eq_z_new_tensor = partial_lagrange_blocking(&z_new_sym);
        let mut eq_z_new_reduced = Vec::with_capacity(eq_z_new_tensor.total_len());
        for eq_elem in eq_z_new_tensor.as_buffer().as_slice() {
            let eq_elem: Ext<_, _> = builder.eval(*eq_elem);
            builder.reduce_e(eq_elem);
            eq_z_new_reduced.push(eq_elem);
        }

        // eq_rho[b] = eq(ρ_bit, b).
        let eq_rho_tensor = partial_lagrange_blocking(&rho_bit);
        let mut eq_rho_reduced = Vec::with_capacity(eq_rho_tensor.total_len());
        for eq_elem in eq_rho_tensor.as_buffer().as_slice() {
            let eq_elem: Ext<_, _> = builder.eval(*eq_elem);
            builder.reduce_e(eq_elem);
            eq_rho_reduced.push(eq_elem);
        }

        let zero = SymbolicExt::<SP1Field, SP1ExtensionField>::zero();
        let mut expected_p_claim = zero;
        for (col, ps_bits) in params.col_prefix_sums.iter().enumerate().take(num_real_cols) {
            let prefix_sum_dim = ps_bits.dimension();
            let mut bit_contribution = zero;
            for b in 0..NUM_BITS {
                if b < prefix_sum_dim {
                    let bit_felt = *ps_bits[prefix_sum_dim - 1 - b];
                    bit_contribution += eq_rho_reduced[b] * SymbolicFelt::from(bit_felt);
                }
            }
            expected_p_claim += eq_z_new_reduced[col] * bit_contribution;
        }
        builder.assert_ext_eq(expected_p_claim, p_claim);
        builder.cycle_tracker_v2_exit();

        // Verify the evaluation proof.
        let evaluation_point = sumcheck_proof.point_and_eval.0.clone();
        self.stacked_pcs_verifier.verify_untrusted_evaluation(
            builder,
            original_commitments,
            &evaluation_point,
            pcs_proof,
            SymbolicExt::from(*expected_eval),
            challenger,
        );
        prefix_sum_felts
    }
}

pub struct RecursiveMachineJaggedPcsVerifier<'a, SC: SP1FieldConfigVariable<C>, C: CircuitConfig> {
    pub jagged_pcs_verifier: &'a RecursiveJaggedPcsVerifier<SC, C>,
    pub column_counts_by_round: Vec<Vec<usize>>,
}

impl<'a, SC: SP1FieldConfigVariable<C>, C: CircuitConfig>
    RecursiveMachineJaggedPcsVerifier<'a, SC, C>
{
    pub fn new(
        jagged_pcs_verifier: &'a RecursiveJaggedPcsVerifier<SC, C>,
        column_counts_by_round: Vec<Vec<usize>>,
    ) -> Self {
        Self { jagged_pcs_verifier, column_counts_by_round }
    }

    pub fn verify_trusted_evaluations(
        &self,
        builder: &mut Builder<C>,
        commitments: &[SC::DigestVariable],
        point: Point<Ext<SP1Field, SP1ExtensionField>>,
        evaluation_claims: &[MleEval<Ext<SP1Field, SP1ExtensionField>>],
        proof: &JaggedPcsProofVariable<RecursiveBasefoldProof<C, SC>, SC::DigestVariable>,
        challenger: &mut SC::FriChallengerVariable,
    ) -> Vec<Felt<SP1Field>> {
        let insertion_points = self
            .column_counts_by_round
            .iter()
            .scan(0, |state, y| {
                *state += y.iter().sum::<usize>();
                Some(*state)
            })
            .collect::<Vec<_>>();

        self.jagged_pcs_verifier.verify_trusted_evaluations(
            builder,
            RoundCommitments { commitments, insertion_points: &insertion_points },
            point,
            evaluation_claims,
            proof,
            challenger,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{marker::PhantomData, sync::Arc};

    use rand::{thread_rng, Rng};
    use slop_algebra::AbstractField;
    use slop_basefold::{BasefoldVerifier, FriConfig};
    use slop_challenger::{CanObserve, IopCtx};
    use slop_commit::Rounds;
    use slop_jagged::{JaggedPcsProof, JaggedPcsVerifier, JaggedProver};
    use slop_multilinear::{Evaluations, Mle, MleEval, PaddedMle, Point};
    use sp1_core_machine::utils::setup_logger;
    use sp1_hypercube::{inner_perm, prover::SP1InnerPcsProver, SP1InnerPcs, SP1PcsProof};
    use sp1_primitives::{SP1DiffusionMatrix, SP1ExtensionField, SP1Field, SP1GlobalContext};
    use sp1_recursion_compiler::circuit::{AsmBuilder, AsmCompiler, AsmConfig, CircuitV2Builder};
    use sp1_recursion_executor::Executor;

    use crate::{
        basefold::{
            stacked::RecursiveStackedPcsVerifier, tcs::RecursiveMerkleTreeTcs,
            RecursiveBasefoldVerifier,
        },
        challenger::{CanObserveVariable, DuplexChallengerVariable},
        jagged::{
            jagged_eval::RecursiveJaggedEvalSumcheckConfig,
            verifier::{RecursiveJaggedPcsVerifier, RecursiveMachineJaggedPcsVerifier},
        },
        witness::Witnessable,
    };

    type SC = SP1GlobalContext;
    type JC = SP1InnerPcs;
    type GC = SP1GlobalContext;
    type F = SP1Field;
    type EF = SP1ExtensionField;
    type C = AsmConfig;
    type Prover = JaggedProver<SP1GlobalContext, SP1InnerPcsProver>;

    #[allow(clippy::type_complexity)]
    fn generate_jagged_proof(
        jagged_verifier: &JaggedPcsVerifier<GC, JC>,
        round_mles: Rounds<Vec<PaddedMle<F>>>,
        eval_point: Point<EF>,
    ) -> (
        JaggedPcsProof<GC, SP1PcsProof<GC>>,
        Rounds<<GC as IopCtx>::Digest>,
        Rounds<Evaluations<EF>>,
    ) {
        let jagged_prover = Prover::from_verifier(jagged_verifier);

        let mut challenger = jagged_verifier.challenger();

        let mut prover_data = Rounds::new();
        let mut commitments = Rounds::new();
        for round in round_mles.iter() {
            let (commit, data) = jagged_prover.commit_multilinears(round.clone()).ok().unwrap();
            challenger.observe(commit);
            let data_bytes = bincode::serialize(&data).unwrap();
            let data = bincode::deserialize(&data_bytes).unwrap();
            prover_data.push(data);
            commitments.push(commit);
        }

        let mut evaluation_claims = Rounds::new();
        for round in round_mles.iter() {
            let mut evals = Evaluations::default();
            for mle in round.iter() {
                let eval = mle.eval_at(&eval_point);
                evals.push(eval);
            }
            evaluation_claims.push(evals);
        }

        let proof = jagged_prover
            .prove_trusted_evaluations(
                eval_point.clone(),
                evaluation_claims.clone(),
                prover_data,
                &mut challenger,
            )
            .ok()
            .unwrap();

        (proof, commitments, evaluation_claims)
    }

    #[test]
    fn test_jagged_verifier() {
        setup_logger();

        let row_counts_rounds = vec![
            vec![
                1 << 13,
                1 << 8,
                1 << 11,
                1 << 7,
                1 << 16,
                1 << 14,
                1 << 20,
                1 << 7,
                1 << 9,
                1 << 11,
                1 << 8,
                1 << 7,
                1 << 14,
                1 << 10,
                1 << 14,
                1 << 8,
            ],
            vec![1 << 8],
        ];
        let column_counts_rounds = vec![
            vec![47, 41, 41, 58, 52, 109, 428, 50, 53, 93, 100, 83, 31, 68, 134, 80],
            vec![512],
        ];

        let num_rounds = row_counts_rounds.len();

        let log_stacking_height = 21;
        let max_log_row_count = 20;

        let row_counts = row_counts_rounds.into_iter().collect::<Rounds<Vec<usize>>>();
        let column_counts = column_counts_rounds.into_iter().collect::<Rounds<Vec<usize>>>();

        assert!(row_counts.len() == column_counts.len());

        let mut rng = thread_rng();

        let round_mles = row_counts
            .iter()
            .zip(column_counts.iter())
            .map(|(row_counts, col_counts)| {
                row_counts
                    .iter()
                    .zip(col_counts.iter())
                    .map(|(num_rows, num_cols)| {
                        if *num_rows == 0 {
                            PaddedMle::zeros(*num_cols, max_log_row_count)
                        } else {
                            let mle = Mle::<F>::rand(&mut rng, *num_cols, num_rows.ilog(2));
                            PaddedMle::padded_with_zeros(Arc::new(mle), max_log_row_count)
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Rounds<_>>();

        let jagged_verifier = JaggedPcsVerifier::<GC, JC>::new_from_basefold_params(
            FriConfig::default_fri_config(),
            log_stacking_height,
            max_log_row_count as usize,
            num_rounds,
        );

        let eval_point = (0..max_log_row_count).map(|_| rng.gen::<EF>()).collect::<Point<_>>();

        // Generate the jagged proof.
        let (proof, mut commitments, evaluation_claims) =
            generate_jagged_proof(&jagged_verifier, round_mles, eval_point.clone());

        let mut challenger = jagged_verifier.challenger();

        for commitment in commitments.iter() {
            // Ensure that the commitments are in the correct field.
            challenger.observe(*commitment);
        }

        let evaluation_claims = evaluation_claims
            .iter()
            .map(|round| {
                round.iter().flat_map(|evals| evals.iter().cloned()).collect::<MleEval<_>>()
            })
            .collect::<Vec<_>>();

        jagged_verifier
            .verify_trusted_evaluations(
                &commitments,
                eval_point.clone(),
                &evaluation_claims,
                &proof,
                &mut challenger,
            )
            .unwrap();

        // Define the verification circuit.
        let mut builder = AsmBuilder::default();
        builder.cycle_tracker_v2_enter("jagged - read input");
        let mut challenger_variable = DuplexChallengerVariable::new(&mut builder);
        let commitments_var = commitments.read(&mut builder);
        let eval_point_var = eval_point.read(&mut builder);
        let evaluation_claims_var = evaluation_claims.read(&mut builder);
        let proof_var = proof.read(&mut builder);
        builder.cycle_tracker_v2_exit();
        builder.cycle_tracker_v2_enter("jagged - observe commitments");
        for commitment_var in commitments_var.iter() {
            challenger_variable.observe_slice(&mut builder, *commitment_var);
        }
        builder.cycle_tracker_v2_exit();
        let verifier = BasefoldVerifier::<SC>::new(
            FriConfig::default_fri_config(),
            num_rounds,
            log_stacking_height,
        );
        let recursive_verifier = RecursiveBasefoldVerifier::<C, SC> {
            fri_config: verifier.fri_config,
            tcs: RecursiveMerkleTreeTcs::<C, SC>(PhantomData),
        };
        let recursive_verifier =
            RecursiveStackedPcsVerifier::new(recursive_verifier, log_stacking_height);

        let recursive_jagged_verifier = RecursiveJaggedPcsVerifier::<SC, C> {
            stacked_pcs_verifier: recursive_verifier,
            max_log_row_count: max_log_row_count as usize,
            jagged_evaluator: RecursiveJaggedEvalSumcheckConfig::<SP1GlobalContext>(PhantomData),
        };

        let recursive_jagged_verifier = RecursiveMachineJaggedPcsVerifier::new(
            &recursive_jagged_verifier,
            vec![column_counts[0].clone(), column_counts[1].clone()],
        );

        builder.cycle_tracker_v2_enter("jagged-verifier");
        recursive_jagged_verifier.verify_trusted_evaluations(
            &mut builder,
            &commitments_var,
            eval_point_var,
            &evaluation_claims_var,
            &proof_var,
            &mut challenger_variable,
        );
        builder.cycle_tracker_v2_exit();

        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();

        // Compile the verification circuit.
        let program = compiler.compile_inner(block).validate().unwrap();

        // Run the verification circuit with the proof artifacts.
        let mut witness_stream = Vec::new();
        Witnessable::<AsmConfig>::write(&commitments, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&eval_point, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&evaluation_claims, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&proof, &mut witness_stream);
        let mut executor =
            Executor::<F, EF, SP1DiffusionMatrix>::new(Arc::new(program.clone()), inner_perm());
        executor.witness_stream = witness_stream.into();
        executor.run().unwrap();

        // Run the verification circuit with the proof artifacts with an expected failure.
        let mut witness_stream = Vec::new();
        commitments.rounds[0][0] += F::one();
        Witnessable::<AsmConfig>::write(&commitments, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&eval_point, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&evaluation_claims, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&proof, &mut witness_stream);
        let mut executor =
            Executor::<F, EF, SP1DiffusionMatrix>::new(Arc::new(program), inner_perm());
        executor.witness_stream = witness_stream.into();
        executor.run().expect_err("invalid proof should not be verified");
    }
}
