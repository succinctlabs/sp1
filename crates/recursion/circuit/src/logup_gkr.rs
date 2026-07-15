use itertools::Itertools;
use sp1_recursion_compiler::circuit::CircuitV2Builder;
use sp1_recursion_compiler::prelude::*;
use std::{collections::BTreeSet, marker::PhantomData, ops::Deref};

use slop_algebra::AbstractField;
use slop_multilinear::{full_geq, Mle, MleEval, Point};
use sp1_hypercube::{
    air::{InteractionScope, MachineAir},
    beta_seed_dim_for_scope, pv_interaction_max_arity, Chip, ChipEvaluation, LogUpEvaluations,
    LogUpGkrOutput, LogupGkrProof, LogupGkrRoundProof,
};
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::ir::Builder;

use crate::shard::RecursiveVerifierPublicValuesConstraintFolder;
use crate::{
    challenger::{CanObserveVariable, FieldChallengerVariable},
    sumcheck::{evaluate_mle_ext, verify_sumcheck},
    symbolic::IntoSymbolic,
    witness::{WitnessWriter, Witnessable},
    CircuitConfig, SP1FieldConfigVariable,
};
use sp1_hypercube::{MachineRecord, GKR_GRINDING_BITS};

/// The shared global `LogUp` challenge pair `(alpha, beta_seed)`.
pub type GlobalChallenge =
    (Ext<SP1Field, SP1ExtensionField>, Point<Ext<SP1Field, SP1ExtensionField>>);

/// Verifier for `LogUp` GKR.
#[derive(Clone, Debug, Copy, Default, PartialEq, Eq, Hash)]
pub struct RecursiveLogUpGkrVerifier<C, SC, A>(PhantomData<(C, SC, A)>);

impl<C, SC, A> RecursiveLogUpGkrVerifier<C, SC, A>
where
    C: CircuitConfig,
    SC: SP1FieldConfigVariable<C>,
    A: MachineAir<SP1Field>,
{
    /// Verify the public values satisfy the required constraints, and return the
    /// `(local, global)` interaction digests.
    pub fn verify_public_values(
        builder: &mut Builder<C>,
        challenge: Ext<SP1Field, SP1ExtensionField>,
        alpha: &Ext<SP1Field, SP1ExtensionField>,
        beta_seed: &Point<Ext<SP1Field, SP1ExtensionField>>,
        global_challenge: Option<&GlobalChallenge>,
        public_values: &[Felt<SP1Field>],
    ) -> (SymbolicExt<SP1Field, SP1ExtensionField>, SymbolicExt<SP1Field, SP1ExtensionField>) {
        let beta_symbolic = IntoSymbolic::<C>::as_symbolic(beta_seed);
        let betas =
            slop_multilinear::partial_lagrange_blocking(&beta_symbolic).into_buffer().into_vec();
        let global_betas = global_challenge.map(|(_, seed)| {
            slop_multilinear::partial_lagrange_blocking(&IntoSymbolic::<C>::as_symbolic(seed))
                .into_buffer()
                .into_vec()
        });
        let global_perm_challenges = match (global_challenge, global_betas.as_ref()) {
            (Some((global_alpha, _)), Some(global_betas)) => {
                Some((global_alpha, global_betas.as_slice()))
            }
            _ => None,
        };
        let mut folder = RecursiveVerifierPublicValuesConstraintFolder {
            perm_challenges: (alpha, &betas),
            global_perm_challenges,
            alpha: challenge,
            accumulator: SymbolicExt::zero(),
            local_interaction_digest: SymbolicExt::zero(),
            global_interaction_digest: SymbolicExt::zero(),
            public_values,
            _marker: PhantomData,
        };
        A::Record::eval_public_values(&mut folder);
        // Check that the constraints hold.
        builder.assert_ext_eq(folder.accumulator, SymbolicExt::zero());
        (folder.local_interaction_digest, folder.global_interaction_digest)
    }

    /// Verify the `LogUp` GKR proof.
    ///
    /// # Errors
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    pub fn verify_logup_gkr(
        builder: &mut Builder<C>,
        shard_chips: &BTreeSet<Chip<SP1Field, A>>,
        degrees: &[Point<Felt<SP1Field>>],
        max_log_row_count: usize,
        global_challenge: Option<&GlobalChallenge>,
        global_cumulative_sum: Option<Ext<SP1Field, SP1ExtensionField>>,
        proof: &LogupGkrProof<Felt<SP1Field>, Ext<SP1Field, SP1ExtensionField>>,
        public_values: &[Felt<SP1Field>],
        challenger: &mut SC::FriChallengerVariable,
    ) {
        let LogupGkrProof { circuit_output, round_proofs, logup_evaluations, witness } = proof;
        let LogUpGkrOutput { numerator, denominator } = circuit_output;

        // Check proof of work (grinding to find a number that hashes to have
        // `GKR_GRINDING_BITS` zeroes at the beginning).
        challenger.check_witness(builder, GKR_GRINDING_BITS, *witness);

        // Sample the permutation challenges. The local beta-seed dimension is scope-filtered to
        // match the native verifier; the global challenge pair is sampled earlier in `verify_shard`.
        let alpha = challenger.sample_ext(builder);
        let beta_seed_dim = beta_seed_dim_for_scope(
            shard_chips.iter(),
            InteractionScope::Local,
            pv_interaction_max_arity::<A::Record>(),
        );
        let beta_seed =
            Point::from_iter((0..beta_seed_dim).map(|_| challenger.sample_ext(builder)));
        // Sample the public value challenge.
        let pv_challenge = challenger.sample_ext(builder);

        builder.cycle_tracker_v2_enter("verify-public-values");
        let (local_pv_digest, global_pv_digest) =
            RecursiveLogUpGkrVerifier::<C, SC, A>::verify_public_values(
                builder,
                pv_challenge,
                &alpha,
                &beta_seed,
                global_challenge,
                public_values,
            );
        let cumulative_sum = -local_pv_digest;
        builder.cycle_tracker_v2_exit();

        // Observe the output claims.
        challenger.observe_variable_length_extension_slice(builder, numerator.guts().as_slice());
        challenger.observe_variable_length_extension_slice(builder, denominator.guts().as_slice());

        // Verify the local cumulative sum against the public-value digest; on a global round, also
        // bind the claimed global cumulative sum to the recomputed one. The output layer has two
        // entries per interaction, ordered as `shard_chips.flat_map(sends ++ receives)`.
        if global_challenge.is_some() {
            let interaction_scopes = shard_chips
                .iter()
                .flat_map(|c| c.sends().iter().chain(c.receives().iter()))
                .map(|i| i.scope)
                .collect::<Vec<_>>();
            let numerators = numerator.guts().as_slice();
            let denominators = denominator.guts().as_slice();
            let mut local_sum = SymbolicExt::<SP1Field, SP1ExtensionField>::zero();
            let mut global_sum = SymbolicExt::<SP1Field, SP1ExtensionField>::zero();
            for (j, scope) in interaction_scopes.iter().enumerate() {
                let value = numerators[2 * j] / denominators[2 * j]
                    + numerators[2 * j + 1] / denominators[2 * j + 1];
                match scope {
                    InteractionScope::Local => local_sum += value,
                    InteractionScope::Global => global_sum += value,
                }
            }
            builder.assert_ext_eq(local_sum, cumulative_sum);
            if let Some(global_cumulative_sum) = global_cumulative_sum {
                builder.assert_ext_eq(global_cumulative_sum, global_sum + global_pv_digest);
            }
        } else {
            let output_cumulative_sum = numerator
                .guts()
                .as_slice()
                .iter()
                .zip_eq(denominator.guts().as_slice().iter())
                .map(|(n, d)| *n / *d)
                .sum::<SymbolicExt<SP1Field, SP1ExtensionField>>();
            builder.assert_ext_eq(output_cumulative_sum, cumulative_sum);
        }

        // Calculate the interaction number.
        let num_of_interactions =
            shard_chips.iter().map(|c| c.sends().len() + c.receives().len()).sum::<usize>();
        let number_of_interaction_variables = num_of_interactions.next_power_of_two().ilog2();

        // Assert that the size of the first layer matches the expected one.
        let initial_number_of_variables = number_of_interaction_variables + 1;
        // let initial_number_of_variables = numerator.num_variables();
        // assert_eq!(initial_number_of_variables, number_of_interaction_variables + 1);

        // Sample the first evaluation point.
        let first_eval_point = challenger.sample_point(builder, initial_number_of_variables);

        // Follow the GKR protocol layer by layer.
        let mut numerator_eval = IntoSymbolic::<C>::as_symbolic(
            &evaluate_mle_ext(builder, numerator.clone(), first_eval_point.clone())[0],
        );
        let mut denominator_eval = IntoSymbolic::<C>::as_symbolic(
            &evaluate_mle_ext(builder, denominator.clone(), first_eval_point.clone())[0],
        );
        let mut eval_point = first_eval_point;
        for round_proof in round_proofs.iter() {
            // Get the batching challenge for combining the claims.
            let lambda = challenger.sample_ext(builder);
            // Check that the claimed sum is consistent with the previous round values.
            let expected_claim = numerator_eval * lambda + denominator_eval;
            builder.assert_ext_eq(round_proof.sumcheck_proof.claimed_sum, expected_claim);

            // Verify the sumcheck proof.
            verify_sumcheck::<C, SC>(builder, challenger, &round_proof.sumcheck_proof);
            // Verify that the evaluation claim is consistent with the prover messages.
            let (point, final_eval) = round_proof.sumcheck_proof.point_and_eval.clone();
            let point = IntoSymbolic::<C>::as_symbolic(&point);
            let eval_point_symbolic = IntoSymbolic::<C>::as_symbolic(&eval_point);
            let eq_eval = Mle::full_lagrange_eval(&point, &eval_point_symbolic);
            let numerator_sumcheck_eval = round_proof.numerator_0 * round_proof.denominator_1
                + round_proof.numerator_1 * round_proof.denominator_0;
            let denominator_sumcheck_eval = round_proof.denominator_0 * round_proof.denominator_1;
            let expected_final_eval =
                eq_eval * (numerator_sumcheck_eval * lambda + denominator_sumcheck_eval);
            builder.assert_ext_eq(final_eval, expected_final_eval);

            // Observe the prover message.
            challenger.observe_ext_element(builder, round_proof.numerator_0);
            challenger.observe_ext_element(builder, round_proof.numerator_1);
            challenger.observe_ext_element(builder, round_proof.denominator_0);
            challenger.observe_ext_element(builder, round_proof.denominator_1);

            // Get the evaluation point for the claims of the next round.
            eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();
            // Sample the last coordinate and add to the point.
            let last_coordinate = challenger.sample_ext(builder);
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
        assert_eq!(trace_variables, max_log_row_count);

        // Assert that the trace point is the same as the claimed opening point
        let LogUpEvaluations { point, chip_openings } = logup_evaluations;
        for (value, expected) in point.iter().zip_eq(trace_point.iter()) {
            builder.assert_ext_eq(*value, *expected);
        }

        // Compute the expected opening of the last layer numerator and denominator values from the
        // trace openings.
        let mut numerator_values =
            Vec::<SymbolicExt<SP1Field, SP1ExtensionField>>::with_capacity(num_of_interactions);
        let mut denominator_values =
            Vec::<SymbolicExt<SP1Field, SP1ExtensionField>>::with_capacity(num_of_interactions);
        let mut point_extended = IntoSymbolic::<C>::as_symbolic(point);

        let alpha = IntoSymbolic::<C>::as_symbolic(&alpha);
        let betas = slop_multilinear::partial_lagrange_blocking(&IntoSymbolic::<C>::as_symbolic(
            &beta_seed,
        ));
        let global_alpha = global_challenge.map(|(ga, _)| IntoSymbolic::<C>::as_symbolic(ga));
        let global_betas = global_challenge.map(|(_, gseed)| {
            slop_multilinear::partial_lagrange_blocking(&IntoSymbolic::<C>::as_symbolic(gseed))
        });
        point_extended.add_dimension(SymbolicExt::zero());
        let len = shard_chips.len();
        let len_felt: Felt<_> = builder.constant(SP1Field::from_canonical_usize(len));
        challenger.observe(builder, len_felt);
        for ((chip, openings), threshold) in
            shard_chips.iter().zip_eq(chip_openings.values()).zip_eq(degrees)
        {
            // Observe the opening. On a global round the global openings are observed between the
            // preprocessed and main openings, matching the native verifier.
            challenger.observe_variable_length_extension_slice(
                builder,
                openings.preprocessed_trace_evaluations.deref(),
            );
            if global_challenge.is_some() {
                challenger.observe_variable_length_extension_slice(
                    builder,
                    openings.global_trace_evaluations.deref(),
                );
            }
            challenger.observe_variable_length_extension_slice(
                builder,
                openings.main_trace_evaluations.deref(),
            );
            let threshold = threshold.iter().map(|x| SymbolicExt::from(*x)).collect::<Point<_>>();
            let geq_eval = full_geq(&threshold, &point_extended);
            let ChipEvaluation {
                main_trace_evaluations,
                preprocessed_trace_evaluations,
                global_trace_evaluations,
            } = openings;

            let padding_global_opening =
                MleEval::from(vec![SP1Field::zero(); global_trace_evaluations.num_polynomials()]);
            for (interaction, is_send) in chip
                .sends()
                .iter()
                .map(|s| (s, true))
                .chain(chip.receives().iter().map(|r| (r, false)))
            {
                // Select the challenge pair by the interaction's scope.
                let (alpha, betas) = match interaction.scope {
                    InteractionScope::Local => (alpha, betas.as_slice()),
                    InteractionScope::Global => (
                        global_alpha.expect("global interaction without a global challenge"),
                        global_betas
                            .as_ref()
                            .expect("global interaction without a global challenge")
                            .as_slice(),
                    ),
                };
                let (real_numerator, real_denominator) = interaction.eval(
                    preprocessed_trace_evaluations,
                    global_trace_evaluations,
                    main_trace_evaluations,
                    alpha,
                    betas,
                );
                let padding_trace_opening =
                    MleEval::from(vec![SP1Field::zero(); main_trace_evaluations.num_polynomials()]);
                let padding_preprocessed_opening = MleEval::from(vec![
                    SP1Field::zero();
                    preprocessed_trace_evaluations.num_polynomials()
                ]);
                let (padding_numerator, padding_denominator) = interaction.eval(
                    &padding_preprocessed_opening,
                    &padding_global_opening,
                    &padding_trace_opening,
                    alpha,
                    betas,
                );

                let numerator_eval = real_numerator - padding_numerator * geq_eval;
                let denominator_eval = real_denominator
                    + (SymbolicExt::<SP1Field, SP1ExtensionField>::one() - padding_denominator)
                        * geq_eval;
                let numerator_eval = if is_send { numerator_eval } else { -numerator_eval };
                numerator_values.push(numerator_eval);
                denominator_values.push(denominator_eval);
            }
        }
        // Convert the values to a multilinear polynomials.
        // Pad the numerator values with zeros.
        numerator_values.resize(1 << interaction_point.dimension(), SymbolicExt::zero());
        let numerator_values = numerator_values
            .into_iter()
            .map(|x| builder.eval(x))
            .collect::<Vec<Ext<SP1Field, SP1ExtensionField>>>();
        let numerator = Mle::from(numerator_values);
        // Pad the denominator values with ones.
        denominator_values.resize(1 << interaction_point.dimension(), SymbolicExt::one());
        let denominator_values = denominator_values
            .into_iter()
            .map(|x| builder.eval(x))
            .collect::<Vec<Ext<SP1Field, SP1ExtensionField>>>();
        let denominator = Mle::from(denominator_values);

        let expected_numerator_eval =
            evaluate_mle_ext(builder, numerator, interaction_point.clone())[0];
        let expected_denominator_eval =
            evaluate_mle_ext(builder, denominator, interaction_point.clone())[0];

        builder.assert_ext_eq(numerator_eval, expected_numerator_eval);
        builder.assert_ext_eq(denominator_eval, expected_denominator_eval);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for LogupGkrRoundProof<T> {
    type WitnessVariable = LogupGkrRoundProof<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let numerator_0 = self.numerator_0.read(builder);
        let numerator_1 = self.numerator_1.read(builder);
        let denominator_0 = self.denominator_0.read(builder);
        let denominator_1 = self.denominator_1.read(builder);
        let sumcheck_proof = self.sumcheck_proof.read(builder);
        Self::WitnessVariable {
            numerator_0,
            numerator_1,
            denominator_0,
            denominator_1,
            sumcheck_proof,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.numerator_0.write(witness);
        self.numerator_1.write(witness);
        self.denominator_0.write(witness);
        self.denominator_1.write(witness);
        self.sumcheck_proof.write(witness);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for LogUpGkrOutput<T> {
    type WitnessVariable = LogUpGkrOutput<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let numerator = self.numerator.read(builder);
        let denominator = self.denominator.read(builder);
        Self::WitnessVariable { numerator, denominator }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.numerator.write(witness);
        self.denominator.write(witness);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for ChipEvaluation<T> {
    type WitnessVariable = ChipEvaluation<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let main_trace_evaluations = self.main_trace_evaluations.read(builder);
        let preprocessed_trace_evaluations = self.preprocessed_trace_evaluations.read(builder);
        let global_trace_evaluations = self.global_trace_evaluations.read(builder);
        Self::WitnessVariable {
            main_trace_evaluations,
            preprocessed_trace_evaluations,
            global_trace_evaluations,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.main_trace_evaluations.write(witness);
        self.preprocessed_trace_evaluations.write(witness);
        self.global_trace_evaluations.write(witness);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for LogUpEvaluations<T> {
    type WitnessVariable = LogUpEvaluations<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let point = self.point.read(builder);
        let chip_openings = self.chip_openings.read(builder);
        Self::WitnessVariable { point, chip_openings }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.point.write(witness);
        self.chip_openings.write(witness);
    }
}

impl<C: CircuitConfig, T1: Witnessable<C>, T2: Witnessable<C>> Witnessable<C>
    for LogupGkrProof<T1, T2>
{
    type WitnessVariable = LogupGkrProof<T1::WitnessVariable, T2::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let circuit_output = self.circuit_output.read(builder);
        let round_proofs = self.round_proofs.read(builder);
        let logup_evaluations = self.logup_evaluations.read(builder);
        let witness = self.witness.read(builder);
        Self::WitnessVariable { circuit_output, round_proofs, logup_evaluations, witness }
    }
    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.circuit_output.write(witness);
        self.round_proofs.write(witness);
        self.logup_evaluations.write(witness);
        self.witness.write(witness);
    }
}
