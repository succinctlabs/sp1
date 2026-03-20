#![cfg(test)]
use std::{iter, marker::PhantomData};

use crate::{
    basefold::tcs::{RecursiveMerkleTreeTcs, RecursiveTensorCsOpening},
    challenger::{CanObserveVariable, CanSampleBitsVariable, FieldChallengerVariable},
    hash::FieldHasherVariable,
    sumcheck::{evaluate_mle_ext, evaluate_mle_ext_batch},
    symbolic::IntoSymbolic,
    witness::Witnessable,
    CircuitConfig, SP1FieldConfigVariable,
};
use slop_algebra::{AbstractField, UnivariatePolynomial};
use slop_challenger::{GrindingChallenger, IopCtx};
use slop_commit::Rounds;
use slop_merkle_tree::MerkleTreeOpeningAndProof;
use slop_multilinear::{Mle, Point};
use slop_whir::{
    map_to_pow, ParsedCommitment, RoundConfig, SumcheckPoly, WhirProof, WhirProofShape,
};
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Ext, ExtensionOperand, Felt, SymbolicExt},
};

#[derive(Clone)]
pub struct RecursiveWhirVerifier<C: CircuitConfig, SC: SP1FieldConfigVariable<C>> {
    config: WhirProofShape<SP1Field>,
    _config: PhantomData<(C, SC)>,
}

pub fn write_round_config_to_challenger<
    C: CircuitConfig,
    SC: SP1FieldConfigVariable<C, F = SP1Field>,
>(
    round_param: RoundConfig,
    challenger: &mut SC::FriChallengerVariable,
    builder: &mut Builder<C>,
) {
    let RoundConfig {
        folding_factor,
        evaluation_domain_log_size,
        queries_pow_bits,
        pow_bits,
        num_queries,
        ood_samples,
        log_inv_rate,
    } = round_param.clone();

    let folding_factor_felt: Felt<_> =
        builder.constant(<SC as IopCtx>::F::from_canonical_usize(folding_factor));
    challenger.observe(builder, folding_factor_felt);

    let evaluation_domain_log_size_felt: Felt<_> =
        builder.constant(<SC as IopCtx>::F::from_canonical_usize(evaluation_domain_log_size));
    challenger.observe(builder, evaluation_domain_log_size_felt);

    let queries_pow_bits_felt: Felt<_> =
        builder.constant(<SC as IopCtx>::F::from_canonical_usize(queries_pow_bits));
    challenger.observe(builder, queries_pow_bits_felt);

    let pow_bits_felt: Vec<Felt<_>> = pow_bits
        .into_iter()
        .map(|b| builder.constant(<SC as IopCtx>::F::from_canonical_usize(b)))
        .collect();
    challenger.observe_variable_length_slice(builder, &pow_bits_felt);

    let num_queries_felt: Felt<_> =
        builder.constant(<SC as IopCtx>::F::from_canonical_usize(num_queries));
    challenger.observe(builder, num_queries_felt);

    let ood_samples_felt: Felt<_> =
        builder.constant(<SC as IopCtx>::F::from_canonical_usize(ood_samples));
    challenger.observe(builder, ood_samples_felt);

    let log_inv_rate_felt: Felt<_> =
        builder.constant(<SC as IopCtx>::F::from_canonical_usize(log_inv_rate));
    challenger.observe(builder, log_inv_rate_felt);
}

fn write_whir_config_to_challenger<
    C: CircuitConfig,
    SC: SP1FieldConfigVariable<C, F = SP1Field>,
>(
    config: WhirProofShape<SP1Field>,
    challenger: &mut SC::FriChallengerVariable,
    builder: &mut Builder<C>,
) {
    let WhirProofShape {
        domain_generator,
        starting_ood_samples,
        starting_log_inv_rate,
        starting_interleaved_log_height,
        starting_domain_log_size,
        starting_folding_pow_bits,
        round_parameters,
        final_poly_log_degree,
        final_queries,
        final_pow_bits,
        final_folding_pow_bits,
    } = config.clone();

    let domain_generator_felt: Felt<_> = builder.constant(domain_generator);
    challenger.observe(builder, domain_generator_felt);

    let starting_ood_samples_felt: Felt<_> =
        builder.constant(<SC as IopCtx>::F::from_canonical_usize(starting_ood_samples));
    challenger.observe(builder, starting_ood_samples_felt);

    let starting_log_inv_rate_felt: Felt<_> =
        builder.constant(<SC as IopCtx>::F::from_canonical_usize(starting_log_inv_rate));
    challenger.observe(builder, starting_log_inv_rate_felt);

    let starting_interleaved_log_height_felt: Felt<_> =
        builder.constant(<SC as IopCtx>::F::from_canonical_usize(starting_interleaved_log_height));
    challenger.observe(builder, starting_interleaved_log_height_felt);

    let starting_domain_log_size_felt: Felt<_> =
        builder.constant(<SC as IopCtx>::F::from_canonical_usize(starting_domain_log_size));
    challenger.observe(builder, starting_domain_log_size_felt);

    let starting_folding_pow_bits_felt: Vec<Felt<_>> = starting_folding_pow_bits
        .into_iter()
        .map(|b| builder.constant(<SC as IopCtx>::F::from_canonical_usize(b)))
        .collect();
    challenger.observe_variable_length_slice(builder, &starting_folding_pow_bits_felt);

    for round_param in round_parameters {
        write_round_config_to_challenger::<C, SC>(round_param, challenger, builder);
    }

    let final_poly_log_degree_felt: Felt<_> =
        builder.constant(<SC as IopCtx>::F::from_canonical_usize(final_poly_log_degree));
    challenger.observe(builder, final_poly_log_degree_felt);

    let final_queries_felt: Felt<_> =
        builder.constant(<SC as IopCtx>::F::from_canonical_usize(final_queries));
    challenger.observe(builder, final_queries_felt);

    let final_pow_bits_felt: Felt<_> =
        builder.constant(<SC as IopCtx>::F::from_canonical_usize(final_pow_bits));
    challenger.observe(builder, final_pow_bits_felt);

    let final_folding_pow_bits_felt: Vec<Felt<_>> = final_folding_pow_bits
        .into_iter()
        .map(|b| builder.constant(<SC as IopCtx>::F::from_canonical_usize(b)))
        .collect();
    challenger.observe_variable_length_slice(builder, &final_folding_pow_bits_felt);
}

impl<C: CircuitConfig, SC: SP1FieldConfigVariable<C, F = SP1Field>> RecursiveWhirVerifier<C, SC> {
    pub fn new(
        config: WhirProofShape<SP1Field>,
        builder: &mut Builder<C>,
        challenger: &mut SC::FriChallengerVariable,
    ) -> Self {
        write_whir_config_to_challenger::<C, SC>(config.clone(), challenger, builder);
        Self { config, _config: PhantomData }
    }
}

impl<C: CircuitConfig> IntoSymbolic<C> for SumcheckPoly<Ext<SP1Field, SP1ExtensionField>> {
    type Output = SumcheckPoly<SymbolicExt<SP1Field, SP1ExtensionField>>;

    fn as_symbolic(&self) -> Self::Output {
        SumcheckPoly(self.0.map(SymbolicExt::from))
    }
}

#[derive(Clone)]
pub struct RecursiveParsedCommitment<C: CircuitConfig, SC: FieldHasherVariable<C>> {
    pub(crate) commitment: Rounds<<SC as FieldHasherVariable<C>>::DigestVariable>,
    pub(crate) ood_points: Vec<Point<Ext<SP1Field, SP1ExtensionField>>>,
    pub(crate) ood_answers: Vec<Ext<SP1Field, SP1ExtensionField>>,
}

pub type RecursiveProverMessage = (SumcheckPoly<Ext<SP1Field, SP1ExtensionField>>, Felt<SP1Field>);
pub type MerkleProofRounds<C, SC> =
    Rounds<RecursiveTensorCsOpening<<SC as FieldHasherVariable<C>>::DigestVariable>>;

type PointAndEval<F> = (Point<F>, F);
pub struct RecursiveWhirProof<C, SC>
where
    C: CircuitConfig,
    SC: FieldHasherVariable<C>,
    <SC as FieldHasherVariable<C>>::DigestVariable: Copy,
{
    // First sumcheck
    pub initial_sumcheck_polynomials: Vec<RecursiveProverMessage>,

    // For internal rounds
    pub commitments: Vec<RecursiveParsedCommitment<C, SC>>,
    pub initial_merkle_proof: MerkleProofRounds<C, SC>,
    pub merkle_proofs: Vec<MerkleProofRounds<C, SC>>,
    pub query_proof_of_works: Vec<Felt<SP1Field>>,
    pub sumcheck_polynomials: Vec<Vec<RecursiveProverMessage>>,

    // Final round
    pub final_polynomial: Vec<Ext<SP1Field, SP1ExtensionField>>,
    pub final_merkle_proof:
        RecursiveTensorCsOpening<<SC as FieldHasherVariable<C>>::DigestVariable>,
    pub final_sumcheck_polynomials: Vec<RecursiveProverMessage>,
    pub final_pow: Felt<SP1Field>,
    pub _config: PhantomData<C>,
}

impl<C: CircuitConfig, SC: SP1FieldConfigVariable<C>> RecursiveWhirVerifier<C, SC> {
    pub(crate) fn observe_commitment(
        &self,
        builder: &mut Builder<C>,
        commitments: &Rounds<<SC as FieldHasherVariable<C>>::DigestVariable>,
        challenger: &mut SC::FriChallengerVariable,
    ) {
        for round_commitment in commitments.iter() {
            challenger.observe(builder, *round_commitment);
        }
    }

    pub(crate) fn verify_whir(
        &self,
        builder: &mut Builder<C>,
        claim: Ext<SP1Field, SP1ExtensionField>,
        num_variables: usize,
        proof: &RecursiveWhirProof<C, SC>,
        challenger: &mut SC::FriChallengerVariable,
    ) -> PointAndEval<Ext<SP1Field, SP1ExtensionField>> {
        let n_rounds = self.config.round_parameters.len();

        let ood_points: Vec<Point<Ext<SP1Field, SP1ExtensionField>>> =
            (0..self.config.starting_ood_samples)
                .map(|_| {
                    (0..num_variables)
                        .map(|_| challenger.sample_ext(builder))
                        .collect::<Vec<Ext<SP1Field, SP1ExtensionField>>>()
                        .into()
                })
                .collect();

        let commitment = &proof.commitments[0];

        for (ood_point, commitment_ood_point) in ood_points.iter().zip(commitment.ood_points.iter())
        {
            for (a, b) in ood_point.iter().zip(commitment_ood_point.iter()) {
                builder.assert_ext_eq(*a, *b);
            }
        }

        challenger.observe_ext_element_slice(builder, &commitment.ood_answers);

        // Batch the initial claim with the OOD claims of the commitment
        let claim_batching_randomness: Ext<SP1Field, SP1ExtensionField> =
            challenger.sample_ext(builder);
        let claimed_sum: Ext<SP1Field, SP1ExtensionField> = builder.eval(
            IntoSymbolic::<C>::as_symbolic(&claim_batching_randomness)
                .powers()
                .zip(iter::once(&claim).chain(&commitment.ood_answers))
                .map(|(r, &v)| v * r)
                .sum::<SymbolicExt<_, _>>(),
        );

        // Initialize the collection of points at which we will need to compute the monomial basis
        // polynomial evaluations.
        let mut final_evaluation_points = vec![commitment.ood_points.clone()];

        // Check the initial sumcheck.
        let (mut folding_randomness, mut claimed_sum) = self.verify_whir_sumcheck(
            builder,
            &proof.initial_sumcheck_polynomials,
            claimed_sum,
            num_variables - self.config.starting_interleaved_log_height,
            &self.config.starting_folding_pow_bits,
            challenger,
        );

        // This contains all the sumcheck randomnesses (these are the alphas)
        let mut concatenated_folding_randomness = folding_randomness.clone();

        // This contains all the batching randomness for sumcheck (these are the epsilons) for
        // batching in- and out-of-domain claims from round to round.
        let mut all_claim_batching_randomness = vec![claim_batching_randomness];

        // This is relative to the previous commitment (i.e. prev_commitment has a domain size of
        // this size)
        let mut domain_size =
            self.config.starting_interleaved_log_height + self.config.starting_log_inv_rate;
        let mut generator: Felt<SP1Field> = builder.constant(self.config.domain_generator);
        let mut prev_commitment = commitment;

        let mut prev_folding_factor = num_variables - self.config.starting_interleaved_log_height;
        let mut num_variables = self.config.starting_interleaved_log_height;

        for round_index in 0..n_rounds {
            let round_params = &self.config.round_parameters[round_index];
            let new_commitment = &proof.commitments[round_index + 1];

            // Observe the round commitments
            for round_commitment in new_commitment.commitment.iter() {
                challenger.observe(builder, *round_commitment);
            }

            // Squeeze the ood points
            let ood_points: Vec<Point<Ext<SP1Field, SP1ExtensionField>>> = (0..round_params
                .ood_samples)
                .map(|_| {
                    (0..num_variables)
                        .map(|_| challenger.sample_ext(builder))
                        .collect::<Vec<Ext<SP1Field, SP1ExtensionField>>>()
                        .into()
                })
                .collect();

            for (ood_point, commitment_ood_point) in
                ood_points.iter().zip(&new_commitment.ood_points)
            {
                for (ood_elem, commitment_ood_elem) in
                    ood_point.iter().zip(commitment_ood_point.iter())
                {
                    builder.assert_ext_eq(*ood_elem, *commitment_ood_elem);
                }
            }

            // Absorb the OOD answers
            challenger.observe_ext_element_slice(builder, &new_commitment.ood_answers);
            challenger.check_witness(
                builder,
                round_params.queries_pow_bits,
                proof.query_proof_of_works[round_index],
            );
            // Squeeze the STIR queries
            let id_query_indices = (0..round_params.num_queries)
                .map(|_| challenger.sample_bits(builder, domain_size))
                .collect::<Vec<_>>();
            let id_query_values: Vec<Felt<SP1Field>> = id_query_indices
                .iter()
                .map(|val| C::exp_reverse_bits(builder, generator, val.clone()))
                .collect();

            let claim_batching_randomness: Ext<SP1Field, SP1ExtensionField> =
                challenger.sample_ext(builder);

            let merkle_proofs = if round_index != 0 {
                &proof.merkle_proofs[round_index - 1]
            } else {
                &proof.initial_merkle_proof
            };

            for (merkle_proof, commitment) in
                merkle_proofs.iter().zip(prev_commitment.commitment.iter())
            {
                RecursiveMerkleTreeTcs::<C, SC>::verify_tensor_openings(
                    builder,
                    commitment,
                    &id_query_indices,
                    merkle_proof,
                );
            }

            // Chunk the Merkle openings into chunks of size `1<<prev_folding_factor`
            // so that the verifier can induce in-domain evaluation claims about the next codeword.
            // Except in the first round, the opened values in the Merkle proof are secretly
            // extension field elements, so we have to reinterpret them as such. (The
            // Merkle tree API commits to and opens only base-field values.)
            let merkle_read_values: Vec<Mle<Ext<SP1Field, SP1ExtensionField>>> = if round_index != 0
            {
                merkle_proofs
                    .iter()
                    .flat_map(|merkle_proof| {
                        merkle_proof
                            .values
                            .clone()
                            .into_buffer()
                            .into_vec()
                            .chunks_exact(sp1_recursion_executor::D)
                            .map(|felt_chunk| C::felt2ext(builder, felt_chunk.try_into().unwrap()))
                            .collect::<Vec<_>>()
                            .chunks_exact(1 << prev_folding_factor)
                            .map(|v| Mle::new(v.to_vec().into()))
                            .collect::<Vec<_>>()
                    })
                    .collect()
            } else {
                let num_openings = merkle_proofs.iter().map(|p| p.values.sizes()[1]).sum::<usize>();
                slop_whir::interleave_chain(merkle_proofs.iter().map(|p| p.values.clone()))
                    .into_buffer()
                    .to_vec()
                    .into_iter()
                    .map(|f| {
                        let e: SymbolicExt<SP1Field, SP1ExtensionField> = f.into();
                        builder.eval(e)
                    })
                    .collect::<Vec<_>>()
                    .chunks_exact(num_openings)
                    .map(|v| Mle::new(v.to_vec().into()))
                    .collect::<Vec<_>>()
            };
            // Compute the STIR values by reading the merkle values and folding across the column.
            let stir_values: Vec<Ext<SP1Field, SP1ExtensionField>> =
                evaluate_mle_ext_batch(builder, merkle_read_values, folding_randomness.clone())
                    .iter()
                    .map(|eval| eval[0])
                    .collect();

            if round_index == 0 {
                builder.cycle_tracker_v2_enter("first round stir values");
            }
            if round_index == 0 {
                builder.cycle_tracker_v2_exit();
            }

            // Update the claimed sum using the STIR values and the OOD answers.
            claimed_sum = builder.eval(
                IntoSymbolic::<C>::as_symbolic(&claim_batching_randomness)
                    .powers()
                    .zip(
                        iter::once(&claimed_sum)
                            .chain(&new_commitment.ood_answers)
                            .chain(&stir_values),
                    )
                    .map(|(r, &v)| r * v)
                    .sum::<SymbolicExt<SP1Field, SP1ExtensionField>>(),
            );

            (folding_randomness, claimed_sum) = self.verify_whir_sumcheck(
                builder,
                &proof.sumcheck_polynomials[round_index],
                claimed_sum,
                round_params.folding_factor,
                &round_params.pow_bits,
                challenger,
            );

            // Prepend the folding randomness from the sumcheck into the combined folding
            // randomness.
            concatenated_folding_randomness = folding_randomness
                .iter()
                .cloned()
                .chain(concatenated_folding_randomness.iter().cloned())
                .collect();

            all_claim_batching_randomness.push(claim_batching_randomness);

            // Add both the in-domain and out-of-domain claims to the set of final evaluation
            // points.
            final_evaluation_points.push(
                [
                    ood_points.clone(),
                    id_query_values
                        .into_iter()
                        .map(|point| {
                            map_to_pow(IntoSymbolic::<C>::as_symbolic(&point), num_variables)
                                .iter()
                                .cloned()
                                .map(|el| {
                                    let ext = el.to_operand().symbolic();
                                    builder.eval(ext)
                                })
                                .collect()
                        })
                        .collect(),
                ]
                .concat(),
            );

            domain_size = round_params.evaluation_domain_log_size;
            prev_commitment = new_commitment;
            prev_folding_factor = round_params.folding_factor;
            generator = builder.eval(IntoSymbolic::<C>::as_symbolic(&generator).square());
            num_variables -= round_params.folding_factor;
        }

        // Now, we want to verify the final evaluations
        challenger.observe_ext_element_slice(builder, &proof.final_polynomial);

        let final_poly = proof.final_polynomial.clone();
        let final_poly_uv = UnivariatePolynomial::new(IntoSymbolic::<C>::as_symbolic(&final_poly));

        challenger.check_witness(builder, self.config.final_pow_bits, proof.final_pow);

        let final_id_indices = (0..self.config.final_queries)
            .map(|_| challenger.sample_bits(builder, domain_size))
            .collect::<Vec<_>>();
        let final_id_values: Vec<Felt<SP1Field>> = final_id_indices
            .iter()
            .map(|val| <C as CircuitConfig>::exp_reverse_bits(builder, generator, val.clone()))
            .collect();

        RecursiveMerkleTreeTcs::<C, SC>::verify_tensor_openings(
            builder,
            &prev_commitment.commitment[0],
            &final_id_indices,
            &proof.final_merkle_proof,
        );

        let final_merkle_read_values: Vec<Mle<Ext<SP1Field, SP1ExtensionField>>> = proof
            .final_merkle_proof
            .values
            .clone()
            .into_buffer()
            .into_vec()
            .chunks_exact(sp1_recursion_executor::D)
            .map(|felt_slice| {
                <C as CircuitConfig>::felt2ext(builder, felt_slice.try_into().unwrap())
            })
            .collect::<Vec<_>>()
            .chunks_exact(1 << prev_folding_factor)
            .map(|v| Mle::new(v.to_vec().into()))
            .collect();

        let final_stir_values: Vec<Ext<_, _>> =
            evaluate_mle_ext_batch(builder, final_merkle_read_values, folding_randomness.clone())
                .iter()
                .map(|eval| eval[0])
                .collect();

        for (final_stir_val, final_id_val) in final_stir_values.iter().zip(final_id_values.iter()) {
            builder.assert_ext_eq(
                *final_stir_val,
                final_poly_uv.eval_at_point((*final_id_val).into()),
            );
        }

        (folding_randomness, claimed_sum) = self.verify_whir_sumcheck(
            builder,
            &proof.final_sumcheck_polynomials,
            claimed_sum,
            self.config.final_poly_log_degree,
            &self.config.final_folding_pow_bits,
            challenger,
        );

        concatenated_folding_randomness = folding_randomness
            .iter()
            .cloned()
            .chain(concatenated_folding_randomness.iter().cloned())
            .collect();

        let f: Ext<_, _> = evaluate_mle_ext(
            builder,
            proof.final_polynomial.clone().into(),
            folding_randomness.clone(),
        )[0];

        builder.cycle_tracker_v2_enter("compute summand");
        let mut summand = SymbolicExt::<SP1Field, SP1ExtensionField>::zero();
        for (i, eval_points) in final_evaluation_points.into_iter().enumerate() {
            let combination_randomness = all_claim_batching_randomness[i];
            let len = eval_points[0].len();
            let eval_randomness: Point<Ext<SP1Field, SP1ExtensionField>> =
                concatenated_folding_randomness.split_at(len).0;

            let sum_modification = IntoSymbolic::<C>::as_symbolic(&combination_randomness)
                .powers()
                .skip(1)
                .zip(eval_points)
                .map(|(r, point)| {
                    r * Mle::<SymbolicExt<SP1Field, SP1ExtensionField>>::full_monomial_basis_eq(
                        &IntoSymbolic::<C>::as_symbolic(&point),
                        &IntoSymbolic::<C>::as_symbolic(&eval_randomness),
                    )
                })
                .sum::<SymbolicExt<SP1Field, SP1ExtensionField>>();

            summand += sum_modification;
        }

        let summand: Ext<_, _> = builder.eval(summand);

        builder.cycle_tracker_v2_exit();

        // This is the claimed value of the query vector. It is trusted and assumed to be easily
        // computable by the verifier.
        let claimed_value = claimed_sum / f - summand;

        let claimed_value = builder.eval(claimed_value);
        (concatenated_folding_randomness, claimed_value)
    }

    pub(crate) fn verify_whir_sumcheck(
        &self,
        builder: &mut Builder<C>,
        sumcheck_polynomials: &[RecursiveProverMessage],
        mut claimed_sum: Ext<SP1Field, SP1ExtensionField>,
        rounds: usize,
        pow_bits: &[usize],
        challenger: &mut SC::FriChallengerVariable,
    ) -> PointAndEval<Ext<SP1Field, SP1ExtensionField>> {
        let mut randomness = Vec::with_capacity(rounds);
        for i in 0..rounds {
            let (sumcheck_poly, pow_witness) = &sumcheck_polynomials[i];
            challenger.observe_ext_element_slice(builder, &sumcheck_poly.0);

            let sum = IntoSymbolic::<C>::as_symbolic(sumcheck_poly).sum_over_hypercube();

            builder.assert_ext_eq(claimed_sum, sum);

            challenger.check_witness(builder, pow_bits[i], *pow_witness);
            let folding_randomness_single: Ext<SP1Field, SP1ExtensionField> =
                challenger.sample_ext(builder);
            randomness.push(folding_randomness_single);

            claimed_sum = builder.eval(
                IntoSymbolic::<C>::as_symbolic(sumcheck_poly)
                    .evaluate_at_point(IntoSymbolic::<C>::as_symbolic(&folding_randomness_single)),
            );
        }

        randomness.reverse();
        (randomness.into(), claimed_sum)
    }
}

impl<C: CircuitConfig, GC: IopCtx> Witnessable<C> for ParsedCommitment<GC>
where
    GC: SP1FieldConfigVariable<C>,
    <GC as IopCtx>::Digest:
        Witnessable<C, WitnessVariable = <GC as FieldHasherVariable<C>>::DigestVariable>,
    GC::F: Witnessable<C, WitnessVariable = Felt<SP1Field>>,
    GC::EF: Witnessable<C, WitnessVariable = Ext<SP1Field, SP1ExtensionField>>,
{
    type WitnessVariable = RecursiveParsedCommitment<C, GC>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let commitment_variable = self.commitment.read(builder);
        let ood_point_variable = self.ood_points.iter().map(|point| point.read(builder)).collect();
        let ood_answer_variable =
            self.ood_answers.iter().map(|answer| answer.read(builder)).collect();
        RecursiveParsedCommitment {
            commitment: commitment_variable,
            ood_points: ood_point_variable,
            ood_answers: ood_answer_variable,
        }
    }

    fn write(&self, witness: &mut impl crate::witness::WitnessWriter<C>) {
        self.commitment.write(witness);
        for point in &self.ood_points {
            point.write(witness);
        }
        for answer in &self.ood_answers {
            answer.write(witness);
        }
    }
}

impl<C: CircuitConfig> Witnessable<C> for SumcheckPoly<SP1ExtensionField> {
    type WitnessVariable = SumcheckPoly<Ext<SP1Field, SP1ExtensionField>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let coeffs = std::array::from_fn(|i| self.0[i].read(builder));
        SumcheckPoly(coeffs)
    }

    fn write(&self, witness: &mut impl crate::witness::WitnessWriter<C>) {
        for coeff in &self.0 {
            coeff.write(witness);
        }
    }
}

type DigestVariable<SC, C> = <SC as FieldHasherVariable<C>>::DigestVariable;

impl<
        GC: IopCtx<F = SP1Field, EF = SP1ExtensionField> + SP1FieldConfigVariable<C>,
        C: CircuitConfig,
    > Witnessable<C> for WhirProof<GC>
where
    <GC as IopCtx>::Digest:
        Witnessable<C, WitnessVariable = <GC as FieldHasherVariable<C>>::DigestVariable>,
    <GC::Challenger as GrindingChallenger>::Witness:
        Witnessable<C, WitnessVariable = Felt<SP1Field>>,
    GC::FriChallengerVariable:
        CanObserveVariable<C, <GC as FieldHasherVariable<C>>::DigestVariable>,
    <GC as FieldHasherVariable<C>>::DigestVariable: Copy,
    MerkleTreeOpeningAndProof<GC>:
        Witnessable<C, WitnessVariable = RecursiveTensorCsOpening<DigestVariable<GC, C>>>,
    SP1Field: Witnessable<C, WitnessVariable = Felt<SP1Field>>,
    SP1ExtensionField: Witnessable<C, WitnessVariable = Ext<SP1Field, SP1ExtensionField>>,
{
    type WitnessVariable = RecursiveWhirProof<C, GC>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let initial_sumcheck_polynomials = self
            .initial_sumcheck_polynomials
            .iter()
            .map(|(poly, pow)| (poly.read(builder), pow.read(builder)))
            .collect();
        let commitments = self.commitments.iter().map(|comm| comm.read(builder)).collect();
        let merkle_proofs = self.merkle_proofs.iter().map(|proof| proof.read(builder)).collect();
        let query_proof_of_works =
            self.query_proofs_of_work.iter().map(|pow| pow.read(builder)).collect();
        let sumcheck_polynomials = self
            .sumcheck_polynomials
            .iter()
            .map(|round| {
                round.iter().map(|(poly, pow)| (poly.read(builder), pow.read(builder))).collect()
            })
            .collect();
        let final_polynomial = self.final_polynomial.read(builder);
        let final_merkle_proof = self.final_merkle_opening_and_proof.read(builder);
        let final_sumcheck_polynomials = self
            .final_sumcheck_polynomials
            .iter()
            .map(|(poly, pow)| (poly.read(builder), pow.read(builder)))
            .collect();
        let final_pow = self.final_pow.read(builder);
        let initial_merkle_proof = self.initial_merkle_proof.read(builder);
        RecursiveWhirProof {
            initial_merkle_proof,
            initial_sumcheck_polynomials,
            commitments,
            merkle_proofs,
            query_proof_of_works,
            sumcheck_polynomials,
            final_polynomial,
            final_merkle_proof,
            final_sumcheck_polynomials,
            final_pow,
            _config: PhantomData,
        }
    }

    fn write(&self, witness: &mut impl crate::witness::WitnessWriter<C>) {
        for (poly, pow) in &self.initial_sumcheck_polynomials {
            poly.write(witness);
            pow.write(witness);
        }
        for comm in &self.commitments {
            comm.write(witness);
        }
        for proof in &self.merkle_proofs {
            proof.write(witness);
        }
        for pow in &self.query_proofs_of_work {
            pow.write(witness);
        }
        for round in &self.sumcheck_polynomials {
            for (poly, pow) in round {
                poly.write(witness);
                pow.write(witness);
            }
        }
        self.final_polynomial.write(witness);
        self.final_merkle_opening_and_proof.write(witness);
        for (poly, pow) in &self.final_sumcheck_polynomials {
            poly.write(witness);
            pow.write(witness);
        }
        self.final_pow.write(witness);
        self.initial_merkle_proof.write(witness);
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use slop_basefold::FriConfig;
    use slop_challenger::IopCtx;
    use slop_dft::p3::Radix2DitParallel;
    use slop_merkle_tree::{FieldMerkleTreeProver, MerkleTreeTcs, Poseidon2KoalaBear16Prover};
    use slop_tensor::Tensor;
    use slop_whir::{Prover, Verifier};
    use sp1_core_machine::utils::setup_logger;
    use sp1_hypercube::{prover::simple_prover, MachineProof, MachineVerifier, ShardVerifier};
    use sp1_primitives::SP1GlobalContext;
    use sp1_recursion_compiler::{circuit::AsmConfig, config::InnerConfig};
    use sp1_recursion_machine::RecursionAir;
    use std::{collections::VecDeque, sync::Arc};

    use slop_algebra::extension::BinomialExtensionField;
    use sp1_primitives::SP1DiffusionMatrix;

    use crate::{challenger::DuplexChallengerVariable, witness::Witnessable};

    use super::*;

    use slop_multilinear::MultilinearPcsProver;

    use slop_multilinear::Mle;
    use sp1_hypercube::inner_perm;
    use sp1_recursion_compiler::circuit::{AsmBuilder, AsmCompiler};
    use sp1_recursion_executor::Executor;

    use sp1_primitives::SP1Field;
    type F = SP1Field;
    type EF = BinomialExtensionField<SP1Field, 4>;

    #[tokio::test]
    async fn test_whir() {
        setup_logger();
        let config = WhirProofShape::default_whir_config();
        type C = InnerConfig;
        type SC = SP1GlobalContext;

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let num_variables: usize = 16;

        let mut challenger_prover = SC::default_challenger();
        let mut challenger_verifier = SC::default_challenger();

        let merkle_prover: Poseidon2KoalaBear16Prover = FieldMerkleTreeProver::default();

        let prover = Prover::<_, _, _>::new(Radix2DitParallel, merkle_prover, config.clone());
        config.write_to_challenger::<<SC as IopCtx>::Digest, _>(&mut challenger_prover);
        let merkle_verifier = MerkleTreeTcs::default();
        let verifier =
            Verifier::<SC>::new(merkle_verifier, config.clone(), 2, &mut challenger_verifier);

        // Two polynomials committed in separate rounds, each 2^15 entries (width 1).
        // Total = 2^16 = 2^num_variables, so no zero-padding needed.
        let poly_1: Mle<SP1Field> = Mle::rand(&mut rng, 1, num_variables as u32 - 1);
        let poly_2: Mle<SP1Field> = Mle::rand(&mut rng, 1, num_variables as u32 - 1);

        // Commit each round separately.
        let (commitment_1, prover_data_1, _) =
            prover.commit_multilinear(vec![poly_1.clone()].into()).unwrap();
        let (commitment_2, prover_data_2, _) =
            prover.commit_multilinear(vec![poly_2.clone()].into()).unwrap();
        let commitments = vec![commitment_1, commitment_2];

        // Build the concatenated polynomial for computing eval_claim.
        // For width-1 MLEs, transpose is a no-op on data, so we just concatenate.
        let mut concat_vec: Vec<SP1Field> = poly_1.guts().as_slice().to_vec();
        concat_vec.extend(poly_2.guts().as_slice().iter().copied());
        let polynomial_concat: Mle<SP1Field> =
            Mle::new(Tensor::from(concat_vec).reshape([1 << num_variables, 1]));

        // Compute evaluation claim at a random point.
        let eval_point: Point<EF> = (0..num_variables).map(|_| rng.gen()).collect();
        let eval_claim: EF = polynomial_concat.eval_at(&eval_point)[0];

        // Observe all commitments into both challengers.
        verifier.observe_commitment(&commitments, &mut challenger_prover, 2).unwrap();
        verifier.observe_commitment(&commitments, &mut challenger_verifier, 2).unwrap();

        // Prove using prove_trusted_evaluation.
        let prover_datas = vec![prover_data_1, prover_data_2].into_iter().collect();
        let proof = prover
            .prove_trusted_evaluation(eval_point, eval_claim, prover_datas, &mut challenger_prover)
            .unwrap();

        // Verify natively.
        let round_areas = proof
            .initial_merkle_proof
            .iter()
            .map(|p| p.proof.width << config.starting_interleaved_log_height)
            .collect::<Vec<_>>();
        let (point, value) = verifier
            .verify(
                &commitments,
                &round_areas,
                num_variables,
                eval_claim,
                &proof,
                &mut challenger_verifier,
            )
            .unwrap();

        // Recursive circuit verification.
        let mut builder = AsmBuilder::default();
        let mut witness_stream = Vec::new();
        let mut challenger_variable = DuplexChallengerVariable::new(&mut builder);

        // Write and read both commitment digests.
        Witnessable::<AsmConfig>::write(&commitment_1, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&commitment_2, &mut witness_stream);
        let commitment_var_1 = commitment_1.read(&mut builder);
        let commitment_var_2 = commitment_2.read(&mut builder);

        let recursive_verifier = RecursiveWhirVerifier::<C, SC>::new(
            config.clone(),
            &mut builder,
            &mut challenger_variable,
        );

        recursive_verifier.observe_commitment(
            &mut builder,
            &[commitment_var_1, commitment_var_2].into_iter().collect(),
            &mut challenger_variable,
        );

        Witnessable::<AsmConfig>::write(&point, &mut witness_stream);
        let point = point.read(&mut builder);

        Witnessable::<AsmConfig>::write(&value, &mut witness_stream);
        let value = value.read(&mut builder);

        Witnessable::<AsmConfig>::write(&proof, &mut witness_stream);
        let proof = proof.read(&mut builder);

        Witnessable::<AsmConfig>::write(&eval_claim, &mut witness_stream);
        let eval_claim_var = eval_claim.read(&mut builder);

        let (point_var, claim_var) = recursive_verifier.verify_whir(
            &mut builder,
            eval_claim_var,
            num_variables,
            &proof,
            &mut challenger_variable,
        );

        for (coord, coord_var) in point_var.iter().zip(point.iter()) {
            builder.assert_ext_eq(*coord, *coord_var);
        }

        builder.assert_ext_eq(claim_var, value);

        let mut buf = VecDeque::<u8>::new();
        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
        let mut executor =
            Executor::<F, EF, SP1DiffusionMatrix>::new(program.clone(), inner_perm());
        executor.witness_stream = witness_stream.into();
        executor.debug_stdout = Box::new(&mut buf);
        executor.run().unwrap();

        type A = RecursionAir<SP1Field, 3, 2>;
        let machine = A::compress_machine();
        let log_stacking_height = 22;
        let max_log_row_count = 21;
        let verifier = ShardVerifier::from_basefold_parameters(
            FriConfig::default_fri_config(),
            log_stacking_height,
            max_log_row_count,
            machine,
        );
        let prover = simple_prover(verifier.clone());

        let (pk, vk) = prover.setup(program).await;

        let records = vec![executor.record.clone()];

        let pk = unsafe { pk.into_inner() };
        let mut shard_proofs = Vec::with_capacity(records.len());
        for record in records {
            let proof = prover.prove_shard(pk.clone(), record).await;
            shard_proofs.push(proof);
        }

        assert!(shard_proofs.len() == 1);

        let proof = MachineProof { shard_proofs };

        let machine_verifier = MachineVerifier::new(verifier);
        tracing::debug_span!("verify the proof")
            .in_scope(|| machine_verifier.verify(&vk, &proof))
            .unwrap();
    }
}
