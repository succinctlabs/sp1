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
        let LogupGkrProof {
            circuit_output,
            global_interaction_outputs,
            round_proofs,
            logup_evaluations,
            witness,
        } = proof;
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

        // The scope of every interaction of the shard, and the grouped interaction-dimension
        // shape, mirroring the native verifier's derivation: the local-scope interactions form
        // the low block `[0, num_local)`, the slots `[num_local, 2^k_local)` are padding, and the
        // global-scope interactions form the block starting at `2^k_local` (see the native
        // `transition_fold` for why the global block must not start below `2^k_local`), followed
        // by padding up to `2^k_full`.
        let interaction_scopes = shard_chips
            .iter()
            .flat_map(|c| c.sends().iter().chain(c.receives().iter()))
            .map(|i| i.scope)
            .collect::<Vec<_>>();
        let has_global_round = global_challenge.is_some();
        let num_local =
            interaction_scopes.iter().filter(|scope| **scope == InteractionScope::Local).count();
        let num_global = interaction_scopes.len() - num_local;
        let k_local = num_local.next_power_of_two().ilog2().max(1) as usize;
        let k_full = if num_global > 0 {
            ((1usize << k_local) + num_global).next_power_of_two().ilog2() as usize
        } else {
            k_local
        };
        let global_block_start = 1usize << k_local;
        let num_interaction_rounds = if has_global_round { k_local } else { k_full };

        // The circuit output is the top `level-1` layer: a single pair of fractions. The shape is
        // fixed for the proof, so this is a host-side structural check.
        assert_eq!(numerator.guts().dimensions.sizes(), [2, 1]);
        assert_eq!(denominator.guts().dimensions.sizes(), [2, 1]);

        // Observe the output claims.
        challenger.observe_variable_length_extension_slice(builder, numerator.guts().as_slice());
        challenger.observe_variable_length_extension_slice(builder, denominator.guts().as_slice());

        // Observe the exposed global-interaction outputs at the same transcript position as the
        // prover (before the first evaluation point). Their count is fixed by the shard's global
        // interactions, and they are bound to the committed traces below through the transition
        // fold and the remaining rounds.
        assert_eq!(global_interaction_outputs.len(), num_global);
        for (global_numerator, global_denominator) in global_interaction_outputs {
            challenger.observe_ext_element(builder, *global_numerator);
            challenger.observe_ext_element(builder, *global_denominator);
        }

        // Combine the two output fractions into the final numerator/denominator and verify the
        // local cumulative sum with a single division. The in-circuit divisions implicitly reject
        // zero denominators (no inverse witness exists).
        let output_numerator = numerator.guts().as_slice();
        let output_denominator = denominator.guts().as_slice();
        let local_output_sum = (output_numerator[0] * output_denominator[1]
            + output_numerator[1] * output_denominator[0])
            / (output_denominator[0] * output_denominator[1]);
        builder.assert_ext_eq(local_output_sum, cumulative_sum);

        // Bind the claimed global cumulative sum (a proof output; its cross-shard cancellation is
        // checked elsewhere) to the exposed global outputs plus the global public-value digest.
        if let Some(global_cumulative_sum) = global_cumulative_sum {
            let global_sum = global_interaction_outputs
                .iter()
                .map(|(n, d)| *n / *d)
                .sum::<SymbolicExt<SP1Field, SP1ExtensionField>>();
            builder.assert_ext_eq(global_cumulative_sum, global_sum + global_pv_digest);
        }

        // The circuit output has one variable; the round count covers the interaction rounds (the
        // local-only tree and the round consuming the "one entry per interaction" layer on a
        // global round, else the full tree) plus the row rounds.
        let initial_number_of_variables = 1;
        assert_eq!(round_proofs.len(), num_interaction_rounds + max_log_row_count - 1);
        // On a global round, the transition fold is applied right before the round that consumes
        // the "one entry per interaction" layer (after the `k_local - 1` local tree rounds).
        let local_rounds = num_interaction_rounds - 1;

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
        for (i, round_proof) in round_proofs.iter().enumerate() {
            // On a global round, splice the exposed global outputs into the claim at the boundary
            // between the local-only tree and the full circuit below it. Mirrors the native
            // `transition_fold`: sample the `k_full - k_local` fresh high interaction bits,
            // prepend them to the point, and fold the exposed outputs in at the global block
            // starting at `2^k_local`. (With no global interactions the fold is a transcript
            // no-op and is skipped.)
            if has_global_round && i == local_rounds && num_global > 0 {
                let num_extra = k_full - k_local;
                let z_extra = (0..num_extra)
                    .map(|_| challenger.sample_ext(builder))
                    .collect::<Vec<Ext<SP1Field, SP1ExtensionField>>>();
                let eq_factor = z_extra
                    .iter()
                    .map(|z| SymbolicExt::<SP1Field, SP1ExtensionField>::one() - *z)
                    .product::<SymbolicExt<SP1Field, SP1ExtensionField>>();
                // `z_full = z_extra (the high interaction bits) ++ z_local`.
                let mut z_full = Point::from_iter(z_extra);
                z_full.extend(&eval_point);
                let mut new_numerator = eq_factor * numerator_eval;
                let mut new_denominator = SymbolicExt::<SP1Field, SP1ExtensionField>::one()
                    + eq_factor
                        * (denominator_eval - SymbolicExt::<SP1Field, SP1ExtensionField>::one());
                if num_extra > 1 {
                    let eq = slop_multilinear::partial_lagrange_blocking(
                        &IntoSymbolic::<C>::as_symbolic(&z_full),
                    )
                    .into_buffer()
                    .into_vec();
                    for (j, (global_numerator, global_denominator)) in
                        global_interaction_outputs.iter().enumerate()
                    {
                        let weight = eq[global_block_start + j];
                        new_numerator += weight * *global_numerator;
                        new_denominator += weight
                            * (*global_denominator
                                - SymbolicExt::<SP1Field, SP1ExtensionField>::one());
                    }
                    let new_numerator: Ext<SP1Field, SP1ExtensionField> =
                        builder.eval(new_numerator);
                    let new_denominator: Ext<SP1Field, SP1ExtensionField> =
                        builder.eval(new_denominator);
                    numerator_eval = new_numerator.into();
                    denominator_eval = new_denominator.into();
                    eval_point = z_full;
                } else {
                    // An optimization for the case when `global_outputs.len()` is much less than `2^k_local`.
                    // In that case, the entire range of global outputs, has the `z_extra` bit fixed at 1.
                    // Moreover, only the lowest `var_diff` bits vary, while the rest are fixed at 0.
                    let var_diff = k_local
                        - global_interaction_outputs.len().next_power_of_two().ilog2() as usize;
                    let (constant_vars, suffix) = z_full.split_at(var_diff + 1);
                    let (z_fixed_at_one, vars_fixed_at_zero) = constant_vars.split_at(1);
                    let prefix: SymbolicExt<_, _> = z_fixed_at_one
                        .iter()
                        .map(|x| IntoSymbolic::<C>::as_symbolic(x))
                        .chain(
                            vars_fixed_at_zero
                                .iter()
                                .map(|x| SymbolicExt::one() - IntoSymbolic::<C>::as_symbolic(x)),
                        )
                        .product();
                    let eq = slop_multilinear::partial_lagrange_blocking(
                        &IntoSymbolic::<C>::as_symbolic(&suffix),
                    )
                    .into_buffer()
                    .into_vec();
                    for (j, (global_numerator, global_denominator)) in
                        global_interaction_outputs.iter().enumerate()
                    {
                        let weight = prefix * eq[j];
                        new_numerator += weight * *global_numerator;
                        new_denominator += weight
                            * (*global_denominator
                                - SymbolicExt::<SP1Field, SP1ExtensionField>::one());
                    }
                    let new_numerator: Ext<SP1Field, SP1ExtensionField> =
                        builder.eval(new_numerator);
                    let new_denominator: Ext<SP1Field, SP1ExtensionField> =
                        builder.eval(new_denominator);
                    numerator_eval = new_numerator.into();
                    denominator_eval = new_denominator.into();
                    eval_point = z_full;
                }
            }
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
        // The leaf layer always carries the full interaction dimension (`k_full`), regardless of
        // the smaller local-only tree above the transition fold.
        let (interaction_point, trace_point) = eval_point.split_at(k_full);
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
        let mut numerator_values = Vec::<SymbolicExt<SP1Field, SP1ExtensionField>>::with_capacity(
            interaction_scopes.len(),
        );
        let mut denominator_values = Vec::<SymbolicExt<SP1Field, SP1ExtensionField>>::with_capacity(
            interaction_scopes.len(),
        );
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
        // Regroup the per-interaction values into the circuit's grouped order: the local block,
        // padding up to `2^k_local`, then the global block. Without a global round this is the
        // identity.
        let mut grouped_numerator = vec![
            SymbolicExt::<SP1Field, SP1ExtensionField>::zero();
            global_block_start + num_global
        ];
        let mut grouped_denominator = vec![
            SymbolicExt::<SP1Field, SP1ExtensionField>::one();
            global_block_start + num_global
        ];
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
        let global_interaction_outputs = self.global_interaction_outputs.read(builder);
        let round_proofs = self.round_proofs.read(builder);
        let logup_evaluations = self.logup_evaluations.read(builder);
        let witness = self.witness.read(builder);
        Self::WitnessVariable {
            circuit_output,
            global_interaction_outputs,
            round_proofs,
            logup_evaluations,
            witness,
        }
    }
    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.circuit_output.write(witness);
        self.global_interaction_outputs.write(witness);
        self.round_proofs.write(witness);
        self.logup_evaluations.write(witness);
        self.witness.write(witness);
    }
}
