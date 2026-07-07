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

use super::{ChipEvaluation, LogUpEvaluations, LogUpGkrOutput, LogupGkrProof};

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
        let LogupGkrProof { circuit_output, round_proofs, logup_evaluations, witness } = proof;

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
        if global_challenges.is_none() && interaction_scopes.contains(&InteractionScope::Global) {
            return Err(LogupGkrVerificationError::GlobalScopeWithoutGlobalRound);
        }

        // Calculate the interaction number.
        let num_of_interactions = interaction_scopes.len();
        let number_of_interaction_variables = num_of_interactions.next_power_of_two().ilog2();

        let expected_size = 1 << (number_of_interaction_variables + 1);

        if numerator.guts().dimensions.sizes() != [expected_size, 1]
            || denominator.guts().dimensions.sizes() != [expected_size, 1]
        {
            return Err(LogupGkrVerificationError::InvalidShape);
        }

        // Observe the output claims.
        challenger.observe_variable_length_extension_slice(numerator.guts().as_slice());
        challenger.observe_variable_length_extension_slice(denominator.guts().as_slice());

        if denominator.guts().as_slice().iter().any(slop_algebra::Field::is_zero) {
            return Err(LogupGkrVerificationError::ZeroDenominator);
        }

        // Split the output layer's cumulative sum by interaction scope.
        let (local_output_sum, global_output_sum) =
            circuit_output.cumulative_sums_by_scope(&interaction_scopes);

        // Verify that the local cumulative sum matches the local public-value digest.
        if local_output_sum != cumulative_sum {
            return Err(LogupGkrVerificationError::CumulativeSumMismatch(
                local_output_sum,
                cumulative_sum,
            ));
        }

        // Bind the claimed global cumulative sum (a proof output) to the recomputed one. The
        // cross-shard checks on the exposed values are deferred.
        if let Some(claimed) = claimed_global_cumulative_sum {
            let expected = global_output_sum + global_pv_digest;
            if claimed != expected {
                return Err(LogupGkrVerificationError::GlobalCumulativeSumMismatch(
                    claimed, expected,
                ));
            }
        }

        // Assert that the size of the first layer matches the expected one.
        let initial_number_of_variables = numerator.num_variables();
        if initial_number_of_variables != number_of_interaction_variables + 1 {
            return Err(LogupGkrVerificationError::InvalidFirstLayerDimension(
                initial_number_of_variables,
                number_of_interaction_variables + 1,
            ));
        }
        // Sample the first evaluation point.
        let first_eval_point = challenger.sample_point::<GC::EF>(initial_number_of_variables);

        // Follow the GKR protocol layer by layer.
        let mut numerator_eval = numerator.blocking_eval_at(&first_eval_point)[0];
        let mut denominator_eval = denominator.blocking_eval_at(&first_eval_point)[0];
        let mut eval_point = first_eval_point;

        if round_proofs.len() + 1 != max_log_row_count {
            return Err(LogupGkrVerificationError::InvalidShape);
        }

        for (i, round_proof) in round_proofs.iter().enumerate() {
            // Get the batching challenge for combining the claims.
            let lambda = challenger.sample_ext_element::<GC::EF>();
            // Check that the claimed sum is consistent with the previous round values.
            let expected_claim = numerator_eval * lambda + denominator_eval;
            if round_proof.sumcheck_proof.claimed_sum != expected_claim {
                return Err(LogupGkrVerificationError::InconsistentSumcheckClaim(i));
            }
            // Verify the sumcheck proof.
            partially_verify_sumcheck_proof(
                &round_proof.sumcheck_proof,
                challenger,
                i + number_of_interaction_variables as usize + 1,
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
        let (interaction_point, trace_point) =
            eval_point.split_at(number_of_interaction_variables as usize);
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
        let has_global_round = global_challenges.is_some();

        // Compute the expected opening of the last layer numerator and denominator values from the
        // trace openings.
        let mut numerator_values = Vec::with_capacity(num_of_interactions);
        let mut denominator_values = Vec::with_capacity(num_of_interactions);
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
