use crate::prover::Record;
use crate::record::MachineRecord;
use crate::VerifierPublicValuesConstraintFolder;
use crate::GKR_GRINDING_BITS;
use crate::{
    air::{InteractionScope, MachineAir},
    beta_seed_dim_for_scope, pv_interaction_max_arity, Chip, ShardContext,
};
use itertools::Itertools;
use slop_air::BaseAir;
use slop_algebra::AbstractField;
use slop_challenger::GrindingChallenger;
use slop_challenger::{CanObserve, FieldChallenger, IopCtx, VariableLengthChallenger};
use slop_multilinear::{
    full_geq, partial_lagrange_blocking, Mle, MleEval, MultilinearPcsChallenger, Point,
};
use slop_sumcheck::{partially_verify_sumcheck_proof, SumcheckError};
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};
use thiserror::Error;

use super::{
    global_output_sum, ChipEvaluation, GlobalInteractionOutput, LogUpEvaluations, LogUpGkrOutput,
    LogupGkrProof,
};

/// An error type for `LogUp` GKR.
#[derive(Debug, Error)]
pub enum LogupGkrVerificationError<EF> {
    /// The sumcheck claim is not consistent with the calculated one from the prover messages.
    #[error("inconsistent sumcheck claim at round {0}")]
    InconsistentSumcheckClaim(usize),
    /// Inconsistency between the calculated evaluation and the sumcheck evaluation.
    #[error("inconsistent evaluation at round {0}")]
    InconsistentEvaluation(usize),
    /// Error when verifying sumcheck proof.
    #[error("sumcheck error: {0}")]
    SumcheckError(#[from] SumcheckError),
    /// The proof shape does not match the expected one for the given number of interactions.
    #[error("invalid shape")]
    InvalidShape,
    /// The size of the first layer does not match the expected one.
    #[error("invalid first layer dimension: {0} != {1}")]
    InvalidFirstLayerDimension(u32, u32),
    /// The dimension of the last layer does not match the expected one.
    #[error("invalid last layer dimension: {0} != {1}")]
    InvalidLastLayerDimension(usize, usize),
    /// The trace point does not match the claimed opening point.
    #[error("trace point mismatch")]
    TracePointMismatch,
    /// The cumulative sum does not match the claimed one.
    #[error("cumulative sum mismatch: {0} != {1}")]
    CumulativeSumMismatch(EF, EF),
    /// The numerator evaluation does not match the expected one.
    #[error("numerator evaluation mismatch: {0} != {1}")]
    NumeratorEvaluationMismatch(EF, EF),
    /// The denominator evaluation does not match the expected one.
    #[error("denominator evaluation mismatch: {0} != {1}")]
    DenominatorEvaluationMismatch(EF, EF),
    /// The denominator guts had zero in it.
    #[error("denominator evaluation has zero value")]
    ZeroDenominator,
    /// Invalid grinding witness.
    #[error("Invalid proof of work witness")]
    Pow,
    /// The public values verification failed.
    #[error("public values verification failed")]
    InvalidPublicValues,
    /// The global cumulative sum claimed in the proof does not match the recomputed one.
    #[error("global cumulative sum mismatch: {0} != {1}")]
    GlobalCumulativeSumMismatch(EF, EF),
    /// A global-scope interaction appeared on a machine without a global round.
    #[error("global-scope interaction on a machine without a global round")]
    GlobalScopeWithoutGlobalRound,
}

/// Apply the transition fold at the "one entry per interaction" layer of a machine with a global
/// round: convert the local-only interaction tree's claim `(numerator, denominator)` at `z_local`
/// into the full-circuit claim at `z_full`, splicing in the exposed global-interaction outputs.
///
/// Sampling `k_full - k_local` fresh challenges `z_extra` (the high interaction bits absent from
/// the local tree), `z_full = z_extra ++ z_local`. With `eq_factor = Π (1 - z_extra_j)`,
/// `eq = partial_lagrange(z_full)`, and `g = 2^k_local` the global block start, the full claim
/// (using that `eq` sums to `1` over the hypercube, so the padding denominators contribute a base
/// of `1`) is:
///
/// ```text
/// numerator   = eq_factor · numerator_local             + Σ_i eq[g + i] · N_glob_i
/// denominator = 1 + eq_factor · (denominator_local - 1) + Σ_i eq[g + i] · (D_glob_i - 1)
/// ```
///
/// Soundness of the splice hinges on the global block starting at `2^k_local` — NOT at
/// `num_local`: every index below `2^k_local` enters this identity as `eq_factor · eq_local`, the
/// basis carrying the local tree's claim, so the identity pins the local tree's padding slots
/// `[num_local, 2^k_local)` to the full circuit's true `(0, 1)` padding there, while each global
/// output lands on an `eq` basis function no local-tree slot can reach. (With the global block at
/// `num_local` instead, a malicious prover could shift value between an unconstrained
/// local-padding slot and the overlapping exposed global output, forging the local cumulative
/// sum.)
///
/// Both the prover and the verifier call this at the same transcript position with the same
/// exposed `global_outputs`, so it must stay a pure function of its inputs and the challenger.
pub fn transition_fold<GC: IopCtx>(
    k_local: usize,
    k_full: usize,
    global_outputs: &[GlobalInteractionOutput<GC::EF>],
    eval_point: &mut Point<GC::EF>,
    numerator_eval: &mut GC::EF,
    denominator_eval: &mut GC::EF,
    challenger: &mut GC::Challenger,
) {
    let num_extra = k_full - k_local;
    let z_extra =
        (0..num_extra).map(|_| challenger.sample_ext_element::<GC::EF>()).collect::<Vec<_>>();
    let eq_factor = z_extra.iter().map(|&z| GC::EF::one() - z).product::<GC::EF>();
    // `z_full = z_extra (the high interaction bits) ++ z_local`.
    let mut z_full = Point::from(z_extra);
    z_full.extend(eval_point);

    let global_block_start = 1usize << k_local;
    let mut numerator = eq_factor * *numerator_eval;
    let mut denominator = GC::EF::one() + eq_factor * (*denominator_eval - GC::EF::one());

    if num_extra > 1 {
        let eq = partial_lagrange_blocking(&z_full);
        let eq = eq.as_slice();

        for (i, (global_numerator, global_denominator)) in global_outputs.iter().enumerate() {
            let weight = eq[global_block_start + i];
            numerator += weight * *global_numerator;
            denominator += weight * (*global_denominator - GC::EF::one());
        }
    } else if !global_outputs.is_empty() {
        // An optimization for the case when `global_outputs.len()` is much less than `2^k_local`.
        // In that case, the entire range of global outputs, has the `z_extra` bit fixed at 1.
        // Moreover, only the lowest `var_diff` bits vary, while the rest are fixed at 0.
        // (With no global outputs at all — the global-round-without-globals boundary, where
        // `num_extra == 0` and `z_full` has only `k_local` coordinates — there are no weights to
        // accumulate and the fold only rewrites the claim's basis.)
        let var_diff = k_local - global_outputs.len().next_power_of_two().ilog2() as usize;
        let (constant_vars, suffix) = z_full.split_at(var_diff + 1);
        let (z_fixed_at_one, vars_fixed_at_zero) = constant_vars.split_at(1);
        let prefix: GC::EF = z_fixed_at_one
            .iter()
            .copied()
            .chain(vars_fixed_at_zero.iter().map(|x| GC::EF::one() - *x))
            .product();
        let eq = partial_lagrange_blocking(&suffix);
        let eq = eq.as_slice();
        for (i, (global_numerator, global_denominator)) in global_outputs.iter().enumerate() {
            let weight = prefix * eq[i];
            numerator += weight * *global_numerator;
            denominator += weight * (*global_denominator - GC::EF::one());
        }
    }

    *numerator_eval = numerator;
    *denominator_eval = denominator;
    *eval_point = z_full;
}

/// Verifier for `LogUp` GKR.
#[derive(Clone, Debug, Copy, Default, PartialEq, Eq, Hash)]
pub struct LogUpGkrVerifier<GC, SC>(PhantomData<(GC, SC)>);

/// The `(local, global)` public-value interaction digests.
pub type PublicValuesDigests<GC> = (<GC as IopCtx>::EF, <GC as IopCtx>::EF);

impl<GC: IopCtx, SC: ShardContext<GC>> LogUpGkrVerifier<GC, SC> {
    /// Verify the public values satisfy the required constraints, and return the
    /// `(local, global)` interaction digests.
    pub fn verify_public_values(
        challenge: GC::EF,
        alpha: &GC::EF,
        beta_seed: &Point<GC::EF>,
        global_challenges: Option<&(GC::EF, Point<GC::EF>)>,
        public_values: &[GC::F],
    ) -> Result<PublicValuesDigests<GC>, LogupGkrVerificationError<GC::EF>> {
        let betas = slop_multilinear::partial_lagrange_blocking(beta_seed).into_buffer().into_vec();
        let global_alpha_betas = global_challenges.map(|(global_alpha, global_beta_seed)| {
            let global_betas = slop_multilinear::partial_lagrange_blocking(global_beta_seed)
                .into_buffer()
                .into_vec();
            (global_alpha, global_betas)
        });
        let mut folder = VerifierPublicValuesConstraintFolder::<GC> {
            perm_challenges: (alpha, &betas),
            global_perm_challenges: global_alpha_betas
                .as_ref()
                .map(|(global_alpha, global_betas)| (*global_alpha, global_betas.as_slice())),
            alpha: challenge,
            accumulator: GC::EF::zero(),
            local_interaction_digest: GC::EF::zero(),
            global_interaction_digest: GC::EF::zero(),
            public_values,
            _marker: PhantomData,
        };
        Record::<_, SC>::eval_public_values(&mut folder);
        if folder.accumulator == GC::EF::zero() {
            Ok((folder.local_interaction_digest, folder.global_interaction_digest))
        } else {
            Err(LogupGkrVerificationError::InvalidPublicValues)
        }
    }

    /// Verify the `LogUp` GKR proof.
    ///
    /// # Errors
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    pub fn verify_logup_gkr(
        shard_chips: &BTreeSet<Chip<GC::F, SC::Air>>,
        degrees: &BTreeMap<String, Point<GC::F>>,
        max_log_row_count: usize,
        global_challenges: Option<&(GC::EF, Point<GC::EF>)>,
        claimed_global_cumulative_sum: Option<GC::EF>,
        proof: &LogupGkrProof<<GC::Challenger as GrindingChallenger>::Witness, GC::EF>,
        public_values: &[GC::F],
        challenger: &mut GC::Challenger,
    ) -> Result<(), LogupGkrVerificationError<GC::EF>> {
        let LogupGkrProof {
            circuit_output,
            global_interaction_outputs,
            round_proofs,
            logup_evaluations,
            witness,
        } = proof;

        let LogUpGkrOutput { numerator, denominator } = circuit_output;

        // The global challenge pair and the claimed global cumulative sum come together.
        if global_challenges.is_some() != claimed_global_cumulative_sum.is_some() {
            return Err(LogupGkrVerificationError::InvalidShape);
        }

        let beta_seed_dim = beta_seed_dim_for_scope(
            shard_chips.iter(),
            InteractionScope::Local,
            pv_interaction_max_arity::<Record<GC, SC>>(),
        );

        // Check proof of work (grinding to find a number that hashes to have
        // `GKR_GRINDING_BITS` zeroes at the beginning).
        if !challenger.check_witness(GKR_GRINDING_BITS, *witness) {
            return Err(LogupGkrVerificationError::Pow);
        }

        let alpha = challenger.sample_ext_element::<GC::EF>();
        let beta_seed = (0..beta_seed_dim)
            .map(|_| challenger.sample_ext_element::<GC::EF>())
            .collect::<Point<_>>();
        let pv_challenge = challenger.sample_ext_element::<GC::EF>();
        let (local_pv_digest, global_pv_digest) = LogUpGkrVerifier::<GC, SC>::verify_public_values(
            pv_challenge,
            &alpha,
            &beta_seed,
            global_challenges,
            public_values,
        )?;
        let cumulative_sum = -local_pv_digest;

        // The scope of every interaction of the shard.
        let interaction_scopes = shard_chips
            .iter()
            .flat_map(|chip| chip.sends().iter().chain(chip.receives().iter()))
            .map(|interaction| interaction.scope)
            .collect::<Vec<_>>();
        let has_global_round = global_challenges.is_some();
        if !has_global_round && interaction_scopes.contains(&InteractionScope::Global) {
            return Err(LogupGkrVerificationError::GlobalScopeWithoutGlobalRound);
        }

        // The interaction-dimension shape of the circuit, in grouped order: the local-scope
        // interactions form the low block `[0, num_local)`, the slots `[num_local, 2^k_local)` are
        // padding, and the global-scope interactions form the block `[2^k_local, 2^k_local +
        // num_global)` (see `transition_fold` for why the global block must not start below
        // `2^k_local`), followed by padding up to `2^k_full`. The prover derives the same shape
        // from the same chip data.
        let num_local =
            interaction_scopes.iter().filter(|scope| **scope == InteractionScope::Local).count();
        let num_global = interaction_scopes.len() - num_local;
        // The circuit output always has one variable, so the proved tree has at least one.
        let k_local = num_local.next_power_of_two().ilog2().max(1) as usize;
        // The full dimension covers the local block padded to `2^k_local` plus the global block
        // above it; with at least one global interaction it strictly exceeds `k_local`.
        let k_full = if num_global > 0 {
            ((1usize << k_local) + num_global).next_power_of_two().ilog2() as usize
        } else {
            k_local
        };
        // The rounds reducing the interaction dimension: the local-only tree (`k_local - 1`
        // combination rounds) plus the round consuming the "one entry per interaction" layer on a
        // global round, else the full tree.
        let num_interaction_rounds = if has_global_round { k_local } else { k_full };

        // The circuit output is the top `level-1` layer: a single pair of fractions.
        if numerator.guts().dimensions.sizes() != [2, 1]
            || denominator.guts().dimensions.sizes() != [2, 1]
        {
            return Err(LogupGkrVerificationError::InvalidShape);
        }

        // Observe the output claims.
        challenger.observe_variable_length_extension_slice(numerator.guts().as_slice());
        challenger.observe_variable_length_extension_slice(denominator.guts().as_slice());

        if denominator.guts().as_slice().iter().any(slop_algebra::Field::is_zero) {
            return Err(LogupGkrVerificationError::ZeroDenominator);
        }

        // Observe the exposed global-interaction outputs at the same transcript position as the
        // prover (before the first evaluation point). Their count is fixed by the shard's global
        // interactions, and they are bound to the committed traces below through the transition
        // fold and the remaining rounds.
        if global_interaction_outputs.len() != num_global {
            return Err(LogupGkrVerificationError::InvalidShape);
        }
        for (global_numerator, global_denominator) in global_interaction_outputs {
            challenger.observe_ext_element(*global_numerator);
            challenger.observe_ext_element(*global_denominator);
        }
        if global_interaction_outputs
            .iter()
            .any(|(_, denominator)| slop_algebra::Field::is_zero(denominator))
        {
            return Err(LogupGkrVerificationError::ZeroDenominator);
        }

        // Combine the two output fractions into the final numerator/denominator and verify the
        // local cumulative sum with a single division.
        let output_numerator = numerator.guts().as_slice();
        let output_denominator = denominator.guts().as_slice();
        let local_output_sum = (output_numerator[0] * output_denominator[1]
            + output_numerator[1] * output_denominator[0])
            / (output_denominator[0] * output_denominator[1]);
        if local_output_sum != cumulative_sum {
            return Err(LogupGkrVerificationError::CumulativeSumMismatch(
                local_output_sum,
                cumulative_sum,
            ));
        }

        // Bind the claimed global cumulative sum (a proof output; its cross-shard cancellation is
        // checked elsewhere) to the exposed global outputs plus the global public-value digest.
        if let Some(claimed) = claimed_global_cumulative_sum {
            let expected = global_output_sum(global_interaction_outputs) + global_pv_digest;
            if claimed != expected {
                return Err(LogupGkrVerificationError::GlobalCumulativeSumMismatch(
                    claimed, expected,
                ));
            }
        }

        // Assert that the size of the first layer matches the expected one.
        let initial_number_of_variables = numerator.num_variables();
        if initial_number_of_variables != 1 {
            return Err(LogupGkrVerificationError::InvalidFirstLayerDimension(
                initial_number_of_variables,
                1,
            ));
        }
        // Sample the first evaluation point.
        let first_eval_point = challenger.sample_point::<GC::EF>(initial_number_of_variables);

        // Follow the GKR protocol layer by layer.
        let mut numerator_eval = numerator.blocking_eval_at(&first_eval_point)[0];
        let mut denominator_eval = denominator.blocking_eval_at(&first_eval_point)[0];
        let mut eval_point = first_eval_point;

        if round_proofs.len() != num_interaction_rounds + max_log_row_count - 1 {
            return Err(LogupGkrVerificationError::InvalidShape);
        }
        // On a global round, the transition fold is applied right before the round that consumes
        // the "one entry per interaction" layer (after the `k_local - 1` local tree rounds).
        let local_rounds = num_interaction_rounds - 1;

        for (i, round_proof) in round_proofs.iter().enumerate() {
            // On a global round, splice the exposed global outputs into the claim at the boundary
            // between the local-only tree and the full circuit below it.
            if has_global_round && i == local_rounds {
                transition_fold::<GC>(
                    k_local,
                    k_full,
                    global_interaction_outputs,
                    &mut eval_point,
                    &mut numerator_eval,
                    &mut denominator_eval,
                    challenger,
                );
            }
            // Get the batching challenge for combining the claims.
            let lambda = challenger.sample_ext_element::<GC::EF>();
            // Check that the claimed sum is consistent with the previous round values.
            let expected_claim = numerator_eval * lambda + denominator_eval;
            if round_proof.sumcheck_proof.claimed_sum != expected_claim {
                return Err(LogupGkrVerificationError::InconsistentSumcheckClaim(i));
            }
            // Verify the sumcheck proof over the current number of variables (the transition fold
            // jumps the interaction dimension from `k_local` to `k_full`).
            partially_verify_sumcheck_proof(
                &round_proof.sumcheck_proof,
                challenger,
                eval_point.dimension(),
                3,
            )?;
            // Verify that the evaluation claim is consistent with the prover messages.
            let (point, final_eval) = round_proof.sumcheck_proof.point_and_eval.clone();
            let eq_eval = Mle::full_lagrange_eval(&point, &eval_point);
            let numerator_sumcheck_eval = round_proof.numerator_0 * round_proof.denominator_1
                + round_proof.numerator_1 * round_proof.denominator_0;
            let denominator_sumcheck_eval = round_proof.denominator_0 * round_proof.denominator_1;
            let expected_final_eval =
                eq_eval * (numerator_sumcheck_eval * lambda + denominator_sumcheck_eval);
            if final_eval != expected_final_eval {
                return Err(LogupGkrVerificationError::InconsistentEvaluation(i));
            }

            // Observe the prover message.
            challenger.observe_ext_element(round_proof.numerator_0);
            challenger.observe_ext_element(round_proof.numerator_1);
            challenger.observe_ext_element(round_proof.denominator_0);
            challenger.observe_ext_element(round_proof.denominator_1);

            // Get the evaluation point for the claims of the next round.
            eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();
            // Sample the last coordinate and add to the point.
            let last_coordinate = challenger.sample_ext_element::<GC::EF>();
            eval_point.add_dimension_back(last_coordinate);
            // Update the evaluation of the numerator and denominator at the last coordinate.
            numerator_eval = round_proof.numerator_0
                + (round_proof.numerator_1 - round_proof.numerator_0) * last_coordinate;
            denominator_eval = round_proof.denominator_0
                + (round_proof.denominator_1 - round_proof.denominator_0) * last_coordinate;
        }

        // Verify that the last layer evaluations are consistent with the evaluations of the traces.
        // The leaf layer always carries the full interaction dimension (`k_full`), regardless of
        // the smaller local-only tree above the transition fold.
        let (interaction_point, trace_point) = eval_point.split_at(k_full);
        // Assert that the number of trace variables matches the expected one.
        let trace_variables = trace_point.dimension();
        if trace_variables != max_log_row_count {
            return Err(LogupGkrVerificationError::InvalidLastLayerDimension(
                trace_variables,
                max_log_row_count,
            ));
        }

        // Assert that the trace point is the same as the claimed opening point
        let LogUpEvaluations { point, chip_openings } = logup_evaluations;
        if point != &trace_point {
            return Err(LogupGkrVerificationError::TracePointMismatch);
        }

        let betas = partial_lagrange_blocking(&beta_seed);
        let global_alpha_betas = global_challenges
            .map(|(global_alpha, seed)| (*global_alpha, partial_lagrange_blocking(seed)));

        // Compute the expected opening of the last layer numerator and denominator values from the
        // trace openings.
        let mut numerator_values = Vec::with_capacity(interaction_scopes.len());
        let mut denominator_values = Vec::with_capacity(interaction_scopes.len());
        let mut point_extended = point.clone();
        point_extended.add_dimension(GC::EF::zero());
        let len = shard_chips.len();
        challenger.observe(GC::F::from_canonical_usize(len));
        for ((chip, openings), threshold) in
            shard_chips.iter().zip_eq(chip_openings.values()).zip_eq(degrees.values())
        {
            // Observe the opening
            challenger
                .observe_variable_length_extension_slice(&openings.preprocessed_trace_evaluations);
            if openings.preprocessed_trace_evaluations.evaluations().sizes()
                != [chip.air.preprocessed_width()]
            {
                return Err(LogupGkrVerificationError::InvalidShape);
            }
            if has_global_round {
                challenger
                    .observe_variable_length_extension_slice(&openings.global_trace_evaluations);
            }
            if openings.global_trace_evaluations.evaluations().sizes() != [chip.air.global_width()]
            {
                return Err(LogupGkrVerificationError::InvalidShape);
            }
            challenger.observe_variable_length_extension_slice(&openings.main_trace_evaluations);
            if openings.main_trace_evaluations.evaluations().sizes() != [chip.air.width()] {
                return Err(LogupGkrVerificationError::InvalidShape);
            }

            if threshold.dimension() != point_extended.dimension() {
                return Err(LogupGkrVerificationError::InvalidShape);
            }

            let geq_eval = full_geq(threshold, &point_extended);
            let ChipEvaluation {
                main_trace_evaluations,
                preprocessed_trace_evaluations,
                global_trace_evaluations,
            } = openings;
            for (interaction, is_send) in chip
                .sends()
                .iter()
                .map(|s| (s, true))
                .chain(chip.receives().iter().map(|r| (r, false)))
            {
                // Select the challenge pair by the interaction's scope.
                let (alpha, betas) = match interaction.scope {
                    InteractionScope::Local => (alpha, betas.as_slice()),
                    InteractionScope::Global => global_alpha_betas
                        .as_ref()
                        .map(|(global_alpha, global_betas)| {
                            (*global_alpha, global_betas.as_slice())
                        })
                        .ok_or(LogupGkrVerificationError::GlobalScopeWithoutGlobalRound)?,
                };
                let (real_numerator, real_denominator) = interaction.eval(
                    preprocessed_trace_evaluations,
                    global_trace_evaluations,
                    main_trace_evaluations,
                    alpha,
                    betas,
                );
                let padding_trace_opening =
                    MleEval::from(vec![GC::EF::zero(); main_trace_evaluations.num_polynomials()]);
                let padding_preprocessed_opening = MleEval::from(vec![
                            GC::EF::zero();
                            preprocessed_trace_evaluations.num_polynomials()
                        ]);
                let padding_global_opening =
                    MleEval::from(vec![GC::EF::zero(); global_trace_evaluations.num_polynomials()]);
                let (padding_numerator, padding_denominator) = interaction.eval(
                    &padding_preprocessed_opening,
                    &padding_global_opening,
                    &padding_trace_opening,
                    alpha,
                    betas,
                );

                let numerator_eval = real_numerator - padding_numerator * geq_eval;
                let denominator_eval =
                    real_denominator + (GC::EF::one() - padding_denominator) * geq_eval;
                let numerator_eval = if is_send { numerator_eval } else { -numerator_eval };
                numerator_values.push(numerator_eval);
                denominator_values.push(denominator_eval);
            }
        }
        // Regroup the per-interaction values into the circuit's grouped order: the local block,
        // padding up to `2^k_local`, then the global block. Without a global round this is the
        // identity.
        let global_block_start = 1usize << k_local;
        let mut grouped_numerator = vec![GC::EF::zero(); global_block_start + num_global];
        let mut grouped_denominator = vec![GC::EF::one(); global_block_start + num_global];
        let (mut local_index, mut global_index) = (0, 0);
        for (scope, (numerator_value, denominator_value)) in interaction_scopes
            .iter()
            .zip_eq(numerator_values.iter().zip_eq(denominator_values.iter()))
        {
            let grouped = match scope {
                InteractionScope::Local => {
                    local_index += 1;
                    local_index - 1
                }
                InteractionScope::Global => {
                    global_index += 1;
                    global_block_start + global_index - 1
                }
            };
            grouped_numerator[grouped] = *numerator_value;
            grouped_denominator[grouped] = *denominator_value;
        }
        let mut numerator_values = grouped_numerator;
        let mut denominator_values = grouped_denominator;
        // Convert the values to a multilinear polynomials.
        // Pad the numerator values with zeros.
        numerator_values.resize(1 << interaction_point.dimension(), GC::EF::zero());
        let numerator = Mle::from(numerator_values);
        // Pad the denominator values with ones.
        denominator_values.resize(1 << interaction_point.dimension(), GC::EF::one());
        let denominator = Mle::from(denominator_values);

        let expected_numerator_eval = numerator.blocking_eval_at(&interaction_point)[0];
        let expected_denominator_eval = denominator.blocking_eval_at(&interaction_point)[0];
        if numerator_eval != expected_numerator_eval {
            return Err(LogupGkrVerificationError::NumeratorEvaluationMismatch(
                numerator_eval,
                expected_numerator_eval,
            ));
        }
        if denominator_eval != expected_denominator_eval {
            return Err(LogupGkrVerificationError::DenominatorEvaluationMismatch(
                denominator_eval,
                expected_denominator_eval,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rand::{thread_rng, Rng};
    use slop_algebra::extension::BinomialExtensionField;
    use slop_alloc::CpuBackend;
    use slop_challenger::IopCtx;
    use slop_matrix::dense::RowMajorMatrix;
    use slop_multilinear::{Mle, PaddedMle, Padding, Point};
    use sp1_primitives::{SP1Field, SP1GlobalContext};

    use super::*;
    use crate::{
        combine_interaction_layer, prove_gkr_round, GkrCircuitLayer, InteractionLayer,
        LogUpGkrCpuLayer, LogupGkrCpuTraceGenerator, LogupGkrRoundProof,
    };

    type GC = SP1GlobalContext;
    type EF = BinomialExtensionField<SP1Field, 4>;
    type Challenger = <SP1GlobalContext as IopCtx>::Challenger;

    /// The interaction-dimension counts `(k_local, k_full)`, mirroring the derivation in
    /// `verify_logup_gkr`.
    fn shape_counts(num_local: usize, num_global: usize) -> (usize, usize) {
        let k_local = num_local.next_power_of_two().ilog2().max(1) as usize;
        let k_full = if num_global > 0 {
            ((1usize << k_local) + num_global).next_power_of_two().ilog2() as usize
        } else {
            k_local
        };
        (k_local, k_full)
    }

    /// Prove one interaction-dimension GKR round through the production round prover.
    fn prove_interaction_round(
        layer: InteractionLayer<EF, EF>,
        eval_point: &Point<EF>,
        numerator_eval: EF,
        denominator_eval: EF,
        challenger: &mut Challenger,
    ) -> LogupGkrRoundProof<EF> {
        let layer: GkrCircuitLayer<SP1Field, EF> = GkrCircuitLayer::InteractionLayer(layer);
        prove_gkr_round(layer, eval_point, numerator_eval, denominator_eval, challenger)
    }

    /// The prover's post-round transcript ritual: observe the four openings, move to the sumcheck
    /// point extended by a freshly sampled last coordinate, and fold the claims.
    fn advance_round(
        round_proof: &LogupGkrRoundProof<EF>,
        eval_point: &mut Point<EF>,
        numerator_eval: &mut EF,
        denominator_eval: &mut EF,
        challenger: &mut Challenger,
    ) {
        challenger.observe_ext_element(round_proof.numerator_0);
        challenger.observe_ext_element(round_proof.numerator_1);
        challenger.observe_ext_element(round_proof.denominator_0);
        challenger.observe_ext_element(round_proof.denominator_1);
        *eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();
        let last_coordinate = challenger.sample_ext_element::<EF>();
        eval_point.add_dimension_back(last_coordinate);
        *numerator_eval = round_proof.numerator_0
            + (round_proof.numerator_1 - round_proof.numerator_0) * last_coordinate;
        *denominator_eval = round_proof.denominator_0
            + (round_proof.denominator_1 - round_proof.denominator_0) * last_coordinate;
    }

    /// A proof of the two-stream protocol over a random leaf layer, together with the dense leaf
    /// polynomials for checking the final claims.
    struct TwoStreamProof {
        circuit_output: LogUpGkrOutput<EF>,
        global_outputs: Vec<GlobalInteractionOutput<EF>>,
        round_proofs: Vec<LogupGkrRoundProof<EF>>,
        leaf_numerator: Mle<EF>,
        leaf_denominator: Mle<EF>,
        k_local: usize,
        k_full: usize,
        has_global_round: bool,
        max_log_row_count: usize,
    }

    /// A random first layer — one "chip" whose columns sit at the grouped `o_full` indices: random
    /// local columns at `[0, num_local)`, constant `(0, 1)` padding columns over the gap
    /// `[num_local, 2^k_local)`, and random global columns at `[2^k_local, 2^k_local +
    /// num_global)` — split by the last row variable into the `_0`/`_1` halves, together with the
    /// dense leaf polynomials over (interaction, row): index `j * 2^m + 2r + b` holds the `_b`
    /// half's row `r` of column `j`, zero/one-padded beyond the columns.
    fn random_first_layer(
        num_local: usize,
        num_global: usize,
        max_log_row_count: usize,
    ) -> (LogUpGkrCpuLayer<EF, EF>, Vec<EF>, Vec<EF>) {
        let mut rng = thread_rng();
        let (k_local, k_full) = shape_counts(num_local, num_global);
        let num_row_variables = max_log_row_count - 1;
        let half_rows = 1 << num_row_variables;
        let width = if num_global > 0 { (1 << k_local) + num_global } else { num_local };
        let in_gap = |j: usize| j >= num_local && j < (1 << k_local);
        let mut random_matrix = |gap_value: EF| {
            let values = (0..half_rows * width)
                .map(|i| if in_gap(i % width) { gap_value } else { rng.gen::<EF>() })
                .collect::<Vec<_>>();
            Mle::from(RowMajorMatrix::new(values, width))
        };
        let [numerator_0, numerator_1] = std::array::from_fn(|_| random_matrix(EF::zero()));
        let [denominator_0, denominator_1] = std::array::from_fn(|_| random_matrix(EF::one()));

        let leaf_size = 1 << (k_full + max_log_row_count);
        let mut leaf_numerator = vec![EF::zero(); leaf_size];
        let mut leaf_denominator = vec![EF::one(); leaf_size];
        for j in 0..width {
            for r in 0..half_rows {
                leaf_numerator[(j << max_log_row_count) + 2 * r] =
                    numerator_0.guts().as_slice()[r * width + j];
                leaf_numerator[(j << max_log_row_count) + 2 * r + 1] =
                    numerator_1.guts().as_slice()[r * width + j];
                leaf_denominator[(j << max_log_row_count) + 2 * r] =
                    denominator_0.guts().as_slice()[r * width + j];
                leaf_denominator[(j << max_log_row_count) + 2 * r + 1] =
                    denominator_1.guts().as_slice()[r * width + j];
            }
        }

        let pad = |mle: Mle<EF>, padding: Padding<EF, CpuBackend>| {
            PaddedMle::padded(Arc::new(mle), num_row_variables as u32, padding)
        };
        let one_padding = || Padding::Constant((EF::one(), width, CpuBackend));
        let zero_padding = || Padding::Constant((EF::zero(), width, CpuBackend));
        let first_layer = LogUpGkrCpuLayer {
            numerator_0: vec![pad(numerator_0, zero_padding())],
            denominator_0: vec![pad(denominator_0, one_padding())],
            numerator_1: vec![pad(numerator_1, zero_padding())],
            denominator_1: vec![pad(denominator_1, one_padding())],
            // The single test "chip" covers the whole grouped index space `[0, width)`
            // contiguously (its columns include the gap's constant padding columns).
            interaction_ranges: vec![(0..width, width..width)],
            num_row_variables,
            num_interaction_variables: k_full,
        };
        (first_layer, leaf_numerator, leaf_denominator)
    }

    /// Absorb the circuit output and the exposed global outputs into the transcript, exactly as
    /// `verify_logup_gkr` does before the first evaluation point is sampled.
    fn observe_output_and_globals<GCtx: IopCtx<F = SP1Field, EF = EF>>(
        circuit_output: &LogUpGkrOutput<EF>,
        global_outputs: &[GlobalInteractionOutput<EF>],
        challenger: &mut GCtx::Challenger,
    ) {
        challenger
            .observe_variable_length_extension_slice(circuit_output.numerator.guts().as_slice());
        challenger
            .observe_variable_length_extension_slice(circuit_output.denominator.guts().as_slice());
        for (global_numerator, global_denominator) in global_outputs {
            challenger.observe_ext_element(*global_numerator);
            challenger.observe_ext_element(*global_denominator);
        }
    }

    /// Prove the grouped two-stream GKR protocol over a random single-chip leaf layer whose
    /// columns sit at the grouped `o_full` indices: `num_local` local interactions, the padding
    /// gap, then `num_global` global ones, over `2^max_log_row_count` rows.
    ///
    /// With `compensate_padding_attack`, act as a malicious prover mounting the trade-off that the
    /// `2^k_local` global-block start defends against: inject a nonzero fraction into the local
    /// tree's padding slot `num_local` and compensate the first exposed global output so that,
    /// under the old `[num_local, ..)` global indexing, the fold identity — and hence the whole
    /// proof — would still verify while the local cumulative sum is forged.
    fn prove_two_stream(
        num_local: usize,
        num_global: usize,
        max_log_row_count: usize,
        has_global_round: bool,
        compensate_padding_attack: bool,
    ) -> TwoStreamProof {
        assert!(has_global_round || num_global == 0);
        let (k_local, k_full) = shape_counts(num_local, num_global);
        let global_block_start = 1usize << k_local;

        let (first_layer, leaf_numerator, leaf_denominator) =
            random_first_layer(num_local, num_global, max_log_row_count);

        // Run the row tree down to one row variable through the production transitions, then
        // extract the base of `2^(k_full + 1)` per-interaction fraction pairs.
        let generator = LogupGkrCpuTraceGenerator::<SP1Field, EF, ()>::default();
        let mut row_layers = vec![first_layer];
        while row_layers.last().unwrap().num_row_variables > 1 {
            row_layers.push(generator.layer_transition(row_layers.last().unwrap()));
        }
        let base = generator.extract_outputs(row_layers.last().unwrap());

        // The first interaction level (`il_0`) combines the base pairs into the "one entry per
        // interaction" layer `o_full`.
        let mut o_full_numerator = base.numerator.guts().as_slice().to_vec();
        let mut o_full_denominator = base.denominator.guts().as_slice().to_vec();
        let il_0 = combine_interaction_layer(&mut o_full_numerator, &mut o_full_denominator);

        // The global interactions' totals (the block starting at `2^k_local`), exposed in the
        // clear.
        let mut global_outputs = (0..num_global)
            .map(|i| {
                let index = global_block_start + i;
                (o_full_numerator[index], o_full_denominator[index])
            })
            .collect::<Vec<_>>();

        // The malicious padding slot value, spliced into the local tree below.
        let padding_override = compensate_padding_attack.then(|| {
            assert!(num_local < global_block_start, "attack needs a padding slot");
            let (true_numerator, true_denominator) = global_outputs[0];
            // An arbitrary injected fraction `a / b` with the compensating global-output shift
            // that would keep the old `[num_local, ..)`-indexed fold identity intact.
            let b = EF::from_canonical_u32(7);
            let a = true_numerator * (b - EF::one()) / true_denominator;
            global_outputs[0] = (true_numerator - a, true_denominator - (b - EF::one()));
            (a, b)
        });

        // The tree proved down to the output: the local-only block on a global round (padded up to
        // `2^k_local`), else all of `o_full`.
        let (mut tree_numerator, mut tree_denominator) = if has_global_round {
            let mut numerator = vec![EF::zero(); 1 << k_local];
            let mut denominator = vec![EF::one(); 1 << k_local];
            numerator[..num_local].copy_from_slice(&o_full_numerator[..num_local]);
            denominator[..num_local].copy_from_slice(&o_full_denominator[..num_local]);
            if let Some((a, b)) = padding_override {
                numerator[num_local] = a;
                denominator[num_local] = b;
            }
            (numerator, denominator)
        } else {
            (o_full_numerator, o_full_denominator)
        };
        let mut tree_layers = Vec::new();
        while tree_numerator.len() > 2 {
            tree_layers.push(combine_interaction_layer(&mut tree_numerator, &mut tree_denominator));
        }
        let circuit_output = LogUpGkrOutput {
            numerator: Mle::from(tree_numerator),
            denominator: Mle::from(tree_denominator),
        };

        // Prove the rounds: the interaction tree (coarsest level first), the transition fold on a
        // global round, `il_0`, then the row rounds (shallowest layer first). Mirror the real
        // prover's transcript: absorb the circuit output and the exposed global outputs before
        // sampling the first evaluation point.
        let mut challenger = GC::default_challenger();
        observe_output_and_globals::<GC>(&circuit_output, &global_outputs, &mut challenger);
        let first_eval_point = challenger.sample_point::<EF>(1);
        let mut numerator_eval = circuit_output.numerator.blocking_eval_at(&first_eval_point)[0];
        let mut denominator_eval =
            circuit_output.denominator.blocking_eval_at(&first_eval_point)[0];
        let mut eval_point = first_eval_point;
        let mut round_proofs = Vec::new();

        for layer in tree_layers.into_iter().rev() {
            let round_proof = prove_interaction_round(
                layer,
                &eval_point,
                numerator_eval,
                denominator_eval,
                &mut challenger,
            );
            advance_round(
                &round_proof,
                &mut eval_point,
                &mut numerator_eval,
                &mut denominator_eval,
                &mut challenger,
            );
            round_proofs.push(round_proof);
        }
        if has_global_round {
            transition_fold::<GC>(
                k_local,
                k_full,
                &global_outputs,
                &mut eval_point,
                &mut numerator_eval,
                &mut denominator_eval,
                &mut challenger,
            );
        }
        let round_proof = prove_interaction_round(
            il_0,
            &eval_point,
            numerator_eval,
            denominator_eval,
            &mut challenger,
        );
        advance_round(
            &round_proof,
            &mut eval_point,
            &mut numerator_eval,
            &mut denominator_eval,
            &mut challenger,
        );
        round_proofs.push(round_proof);
        for layer in row_layers.into_iter().rev() {
            let round_proof = prove_gkr_round(
                GkrCircuitLayer::Layer(layer),
                &eval_point,
                numerator_eval,
                denominator_eval,
                &mut challenger,
            );
            advance_round(
                &round_proof,
                &mut eval_point,
                &mut numerator_eval,
                &mut denominator_eval,
                &mut challenger,
            );
            round_proofs.push(round_proof);
        }

        TwoStreamProof {
            circuit_output,
            global_outputs,
            round_proofs,
            leaf_numerator: Mle::from(leaf_numerator),
            leaf_denominator: Mle::from(leaf_denominator),
            k_local,
            k_full,
            has_global_round,
            max_log_row_count,
        }
    }

    /// Verify a `TwoStreamProof` by replicating the round section of `verify_logup_gkr` (which
    /// itself needs a full machine's chips and trace openings), calling the production
    /// `transition_fold` at the same position, and check the final claims against the dense leaf
    /// polynomials.
    fn verify_two_stream(proof: &TwoStreamProof) -> Result<(), LogupGkrVerificationError<EF>> {
        let TwoStreamProof {
            circuit_output,
            global_outputs,
            round_proofs,
            leaf_numerator,
            leaf_denominator,
            k_local,
            k_full,
            has_global_round,
            max_log_row_count,
        } = proof;
        let num_interaction_rounds = if *has_global_round { *k_local } else { *k_full };
        if round_proofs.len() != num_interaction_rounds + max_log_row_count - 1 {
            return Err(LogupGkrVerificationError::InvalidShape);
        }
        let local_rounds = num_interaction_rounds - 1;

        let mut challenger = GC::default_challenger();
        observe_output_and_globals::<GC>(circuit_output, global_outputs, &mut challenger);
        let first_eval_point = challenger.sample_point::<EF>(1);
        let mut numerator_eval = circuit_output.numerator.blocking_eval_at(&first_eval_point)[0];
        let mut denominator_eval =
            circuit_output.denominator.blocking_eval_at(&first_eval_point)[0];
        let mut eval_point = first_eval_point;

        for (i, round_proof) in round_proofs.iter().enumerate() {
            if *has_global_round && i == local_rounds {
                transition_fold::<GC>(
                    *k_local,
                    *k_full,
                    global_outputs,
                    &mut eval_point,
                    &mut numerator_eval,
                    &mut denominator_eval,
                    &mut challenger,
                );
            }
            let lambda = challenger.sample_ext_element::<EF>();
            let expected_claim = numerator_eval * lambda + denominator_eval;
            if round_proof.sumcheck_proof.claimed_sum != expected_claim {
                return Err(LogupGkrVerificationError::InconsistentSumcheckClaim(i));
            }
            partially_verify_sumcheck_proof(
                &round_proof.sumcheck_proof,
                &mut challenger,
                eval_point.dimension(),
                3,
            )?;
            let (point, final_eval) = round_proof.sumcheck_proof.point_and_eval.clone();
            let eq_eval = Mle::full_lagrange_eval(&point, &eval_point);
            let numerator_sumcheck_eval = round_proof.numerator_0 * round_proof.denominator_1
                + round_proof.numerator_1 * round_proof.denominator_0;
            let denominator_sumcheck_eval = round_proof.denominator_0 * round_proof.denominator_1;
            let expected_final_eval =
                eq_eval * (numerator_sumcheck_eval * lambda + denominator_sumcheck_eval);
            if final_eval != expected_final_eval {
                return Err(LogupGkrVerificationError::InconsistentEvaluation(i));
            }
            challenger.observe_ext_element(round_proof.numerator_0);
            challenger.observe_ext_element(round_proof.numerator_1);
            challenger.observe_ext_element(round_proof.denominator_0);
            challenger.observe_ext_element(round_proof.denominator_1);
            eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();
            let last_coordinate = challenger.sample_ext_element::<EF>();
            eval_point.add_dimension_back(last_coordinate);
            numerator_eval = round_proof.numerator_0
                + (round_proof.numerator_1 - round_proof.numerator_0) * last_coordinate;
            denominator_eval = round_proof.denominator_0
                + (round_proof.denominator_1 - round_proof.denominator_0) * last_coordinate;
        }

        let (interaction_point, trace_point) = eval_point.split_at(*k_full);
        assert_eq!(trace_point.dimension(), *max_log_row_count);
        assert_eq!(interaction_point.dimension(), *k_full);
        assert_eq!(numerator_eval, leaf_numerator.blocking_eval_at(&eval_point)[0]);
        assert_eq!(denominator_eval, leaf_denominator.blocking_eval_at(&eval_point)[0]);
        Ok(())
    }

    /// Round-trip of the grouped two-stream protocol on a machine with a global round: the local
    /// tree is smaller than the full interaction dimension (`k_local < k_full`), so the transition
    /// fold samples an extra challenge and splices in the exposed global outputs.
    #[test]
    fn test_two_stream_gkr_rounds_with_global_fold() {
        let (num_local, num_global, max_log_row_count) = (5, 6, 3);
        let proof = prove_two_stream(num_local, num_global, max_log_row_count, true, false);
        assert_eq!(proof.k_local, 3);
        assert_eq!(proof.k_full, 4);
        assert_eq!(proof.round_proofs.len(), proof.k_local + max_log_row_count - 1);
        verify_two_stream(&proof).unwrap();

        // The output is the local-only cumulative sum.
        let numerator = proof.circuit_output.numerator.guts().as_slice();
        let denominator = proof.circuit_output.denominator.guts().as_slice();
        let local_sum = (numerator[0] * denominator[1] + numerator[1] * denominator[0])
            / (denominator[0] * denominator[1]);
        let leaf_numerator = proof.leaf_numerator.guts().as_slice();
        let leaf_denominator = proof.leaf_denominator.guts().as_slice();
        let expected_local_sum = (0..num_local << max_log_row_count)
            .map(|i| leaf_numerator[i] / leaf_denominator[i])
            .sum::<EF>();
        assert_eq!(local_sum, expected_local_sum);
        // The exposed global outputs are the global interactions' totals, read at the global
        // block starting at `2^k_local`.
        let rows = 1 << max_log_row_count;
        for (i, (global_numerator, global_denominator)) in proof.global_outputs.iter().enumerate() {
            let expected = (0..rows)
                .map(|r| {
                    let index = (((1 << proof.k_local) + i) << max_log_row_count) + r;
                    leaf_numerator[index] / leaf_denominator[index]
                })
                .sum::<EF>();
            assert_eq!(*global_numerator / *global_denominator, expected);
        }
    }

    /// A fold spanning multiple extra challenges (`k_full - k_local > 1`).
    #[test]
    fn test_two_stream_gkr_rounds_multiple_extra_challenges() {
        let (num_local, num_global, max_log_row_count) = (5, 9, 3);
        let proof = prove_two_stream(num_local, num_global, max_log_row_count, true, false);
        assert_eq!(proof.k_local, 3);
        assert_eq!(proof.k_full, 5);
        verify_two_stream(&proof).unwrap();
    }

    /// An all-global shard: the proved local tree is pure padding and the local cumulative sum is
    /// zero.
    #[test]
    fn test_two_stream_gkr_rounds_all_global() {
        let (num_local, num_global, max_log_row_count) = (0, 3, 3);
        let proof = prove_two_stream(num_local, num_global, max_log_row_count, true, false);
        assert_eq!(proof.k_local, 1);
        assert_eq!(proof.k_full, 3);
        verify_two_stream(&proof).unwrap();
        let numerator = proof.circuit_output.numerator.guts().as_slice();
        assert!(numerator.iter().all(slop_algebra::Field::is_zero));
    }

    /// Without a global round the full interaction tree is proved down to the output and no fold
    /// is applied.
    #[test]
    fn test_two_stream_gkr_rounds_no_global() {
        let (num_local, max_log_row_count) = (11, 3);
        let proof = prove_two_stream(num_local, 0, max_log_row_count, false, false);
        assert_eq!(proof.k_local, 4);
        assert_eq!(proof.k_full, 4);
        assert_eq!(proof.round_proofs.len(), proof.k_full + max_log_row_count - 1);
        verify_two_stream(&proof).unwrap();
    }

    /// A machine with a global round whose shard has no global-scope interactions: the prover
    /// still takes the global path (`k_full == k_local`, no exposed outputs) and the transition
    /// fold is a transcript no-op at the same round position on both sides.
    #[test]
    fn test_two_stream_gkr_rounds_global_round_without_globals() {
        let (num_local, max_log_row_count) = (11, 3);
        let proof = prove_two_stream(num_local, 0, max_log_row_count, true, false);
        assert_eq!(proof.k_local, 4);
        assert_eq!(proof.k_full, 4);
        assert!(proof.global_outputs.is_empty());
        assert_eq!(proof.round_proofs.len(), proof.k_local + max_log_row_count - 1);
        verify_two_stream(&proof).unwrap();
    }

    /// Tampering with an exposed global output must break the transition fold's binding of the
    /// exposed values to the circuit, even though the tampered value is internally consistent as a
    /// fraction.
    #[test]
    fn test_two_stream_gkr_rounds_tampered_global_output() {
        let mut proof = prove_two_stream(5, 6, 3, true, false);
        proof.global_outputs[2].0 += EF::one();
        assert!(verify_two_stream(&proof).is_err());
    }

    /// The compensated-padding attack: inject a fraction into the local tree's padding slot
    /// `num_local` and shift the first exposed global output to compensate. Under a global block
    /// indexed at `[num_local, ..)` the two adjustments would cancel inside the fold (sharing an
    /// `eq` basis function) and the forged proof would verify with a corrupted local cumulative
    /// sum; with the global block at `2^k_local` they land on independent basis functions and the
    /// proof must be rejected.
    #[test]
    fn test_two_stream_gkr_rounds_compensated_padding_attack() {
        let proof = prove_two_stream(5, 6, 3, true, true);
        assert!(verify_two_stream(&proof).is_err());
    }
}
