use itertools::Itertools;
use std::iter::once;

use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractField, UnivariatePolynomial};
use slop_challenger::{
    CanObserve, CanSampleBits, FieldChallenger, GrindingChallenger, IopCtx,
    VariableLengthChallenger,
};
use slop_commit::Rounds;
use slop_merkle_tree::{MerkleTreeOpeningAndProof, MerkleTreeTcs};
use slop_multilinear::{Mle, MultilinearPcsVerifier, Point};
use slop_utils::reverse_bits_len;
use thiserror::Error;

use crate::{config::WhirProofShape, interleave_chain};

#[derive(Clone)]
pub struct Verifier<GC>
where
    GC: IopCtx,
{
    pub config: WhirProofShape<GC::F>,
    merkle_verifier: MerkleTreeTcs<GC>,
    pub num_expected_commitments: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedCommitment<GC>
where
    GC: IopCtx,
{
    pub commitment: Rounds<GC::Digest>,
    pub ood_points: Vec<Point<GC::EF>>,
    pub ood_answers: Vec<GC::EF>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SumcheckPoly<F>(pub [F; 3]);

impl<F> SumcheckPoly<F>
where
    F: AbstractField,
{
    /// Equivalent to `eval_one_plus_eval_zero` for the `UnivariatePolynomial` struct.
    pub fn sum_over_hypercube(&self) -> F {
        let [c0, c1, c2] = self.0.clone();
        c0.double() + c1 + c2
    }

    // Equivalent to `eval_at_point` for the `UnivariatePolynomial` struct.
    pub fn evaluate_at_point(&self, point: F) -> F {
        let [c0, c1, c2] = self.0.clone();
        c0 + c1 * point.clone() + c2 * point.square()
    }
}

pub type ProofOfWork<GC> = <<GC as IopCtx>::Challenger as GrindingChallenger>::Witness;
pub type ProverMessage<GC> = (SumcheckPoly<<GC as IopCtx>::EF>, ProofOfWork<GC>);

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "GC: IopCtx")]
pub struct WhirProof<GC>
where
    GC: IopCtx,
{
    // First sumcheck
    pub initial_sumcheck_polynomials: Vec<(SumcheckPoly<GC::EF>, ProofOfWork<GC>)>,
    pub initial_merkle_proof: Rounds<MerkleTreeOpeningAndProof<GC>>,

    // For internal rounds
    pub commitments: Vec<ParsedCommitment<GC>>,
    pub merkle_proofs: Vec<Rounds<MerkleTreeOpeningAndProof<GC>>>,
    pub query_proofs_of_work: Vec<ProofOfWork<GC>>,
    pub sumcheck_polynomials: Vec<Vec<ProverMessage<GC>>>,

    // Final round
    pub final_polynomial: Vec<GC::EF>,
    pub final_merkle_opening_and_proof: MerkleTreeOpeningAndProof<GC>,
    pub final_sumcheck_polynomials: Vec<ProverMessage<GC>>,
    pub final_pow: ProofOfWork<GC>,
}

#[derive(Debug, Error)]
pub enum WhirProofError {
    #[error("invalid number of OOD samples: expected {0}, got {1}")]
    InvalidNumberOfOODSamples(usize, usize),
    #[error("sumcheck error: {0}, {1}")]
    SumcheckError(SumcheckError, usize),
    #[error("invalid proof of work")]
    PowError,
    #[error("invalid OOD evaluation")]
    InvalidOOD,
    #[error("invalid Merkle authentication")]
    InvalidMerkleAuthentication,
    #[error("invalid degree of final polynomial: expected {0}, got {1}")]
    InvalidDegreeFinalPolynomial(usize, usize),
    #[error("final query mismatch")]
    FinalQueryMismatch,
    #[error("final eval error")]
    FinalEvalError,
    #[error("invalid number of commitments: expected {0}, got {1}")]
    InvalidNumberOfCommitments(usize, usize),
    #[error("proof has incorrect shape")]
    IncorrectShape,
}

impl From<(SumcheckError, usize)> for WhirProofError {
    fn from(value: (SumcheckError, usize)) -> Self {
        WhirProofError::SumcheckError(value.0, value.1)
    }
}

#[derive(Debug, Error)]
pub enum SumcheckError {
    #[error("expected {0} sumcheck polynomials, got {1}")]
    InvalidNumberOfSumcheckPoly(usize, usize),
    #[error("invalid sum")]
    InvalidSum,
    #[error("invalid proof of work")]
    PowError,
    #[error("invalid shape of proof of work")]
    InvalidShape,
}

pub fn map_to_pow<F: AbstractField>(mut elem: F, len: usize) -> Point<F> {
    assert!(len > 0);
    let mut res = Vec::with_capacity(len);
    for _ in 0..len {
        res.push(elem.clone());
        elem = elem.square();
    }
    res.reverse();
    res.into()
}

impl<GC> Verifier<GC>
where
    GC: IopCtx,
    GC::Challenger: VariableLengthChallenger<GC::F, GC::Digest>,
{
    pub fn new(
        merkle_verifier: MerkleTreeTcs<GC>,
        config: WhirProofShape<GC::F>,
        num_expected_commitments: usize,
        challenger: &mut GC::Challenger,
    ) -> Self {
        assert_ne!(num_expected_commitments, 0, "commitment must exist");
        config.write_to_challenger::<GC::Digest, GC::Challenger>(challenger);
        Self { merkle_verifier, config, num_expected_commitments }
    }

    pub fn observe_commitment(
        &self,
        commitment: &[GC::Digest],
        challenger: &mut GC::Challenger,
        expected_length: usize,
    ) -> Result<(), WhirProofError> {
        if commitment.len() != expected_length {
            Err(WhirProofError::InvalidNumberOfCommitments(expected_length, commitment.len()))
        } else {
            challenger.observe_constant_length_digest_slice(commitment);
            Ok(())
        }
    }

    /// The claim is that < f, v > = claim.
    /// WHIR reduces it to a claim that v(point) = claim'
    pub fn verify(
        &self,
        commitments: &[GC::Digest],
        round_areas: &[usize],
        num_variables: usize,
        claim: GC::EF,
        proof: &WhirProof<GC>,
        challenger: &mut GC::Challenger,
    ) -> Result<(Point<GC::EF>, GC::EF), WhirProofError> {
        let config = &self.config;
        let n_rounds = config.round_parameters.len();

        if n_rounds == 0
            || proof.merkle_proofs.len() != n_rounds - 1
            || proof.query_proofs_of_work.len() != n_rounds
            || proof.sumcheck_polynomials.len() != n_rounds
            || proof.commitments.len() != n_rounds + 1
            || round_areas.len() != self.num_expected_commitments
            || proof.initial_merkle_proof.len() != self.num_expected_commitments
        {
            return Err(WhirProofError::IncorrectShape);
        }

        if commitments.len() != self.num_expected_commitments {
            return Err(WhirProofError::InvalidNumberOfCommitments(
                self.num_expected_commitments,
                commitments.len(),
            ));
        }

        for (merkle_proof, area) in proof.initial_merkle_proof.iter().zip_eq(round_areas.iter()) {
            if merkle_proof.proof.width << self.config.starting_interleaved_log_height != *area {
                println!(
                    "proof width: {}, proof log height: {}, expected area {}, area: {}",
                    merkle_proof.proof.width,
                    merkle_proof.proof.log_tensor_height,
                    area,
                    merkle_proof.proof.width << merkle_proof.proof.log_tensor_height
                );
                return Err(WhirProofError::IncorrectShape);
            }
        }

        let ood_points: Vec<Point<GC::EF>> = (0..config.starting_ood_samples)
            .map(|_| {
                (0..num_variables)
                    .map(|_| challenger.sample_ext_element())
                    .collect::<Vec<GC::EF>>()
                    .into()
            })
            .collect();

        // Because of the length checks at the start of the verification, the checked access isn't
        // expected to produce an error.
        let commitment = proof.commitments.first().ok_or(WhirProofError::IncorrectShape)?;

        if ood_points != commitment.ood_points {
            return Err(WhirProofError::InvalidOOD);
        }

        if commitments.to_vec() != commitment.commitment.clone().into_iter().collect::<Vec<_>>() {
            return Err(WhirProofError::InvalidMerkleAuthentication);
        }

        // Check that the number of OOD answers in the proof matches the expected value.
        if commitment.ood_answers.len() != config.starting_ood_samples {
            return Err(WhirProofError::InvalidNumberOfOODSamples(
                config.starting_ood_samples,
                commitment.ood_answers.len(),
            ));
        }

        challenger.observe_ext_element_slice(&commitment.ood_answers);

        // Batch the initial claim with the OOD claims of the commitment
        let claim_batching_randomness: GC::EF = challenger.sample_ext_element();
        let claimed_sum: GC::EF = claim_batching_randomness
            .powers()
            .zip(std::iter::once(&claim).chain(&commitment.ood_answers))
            .map(|(r, &v)| v * r)
            .sum();

        // Initialize the collection of points at which we will need to compute the monomial basis
        // polynomial evaluations.
        let mut final_evaluation_points = vec![commitment.ood_points.clone()];

        // Check the initial sumcheck.
        let (mut folding_randomness, mut claimed_sum) = self
            .verify_sumcheck(
                &proof.initial_sumcheck_polynomials,
                claimed_sum,
                num_variables - config.starting_interleaved_log_height,
                &config.starting_folding_pow_bits,
                challenger,
            )
            .map_err(|err| (err, 0))?;

        // This contains all the sumcheck randomnesses (these are the alphas)
        let mut concatenated_folding_randomness = folding_randomness.clone();

        // This contains all the batching randomness for sumcheck (these are the epsilons) for
        // batching in- and out-of-domain claims from round to round.
        let mut all_claim_batching_randomness = vec![claim_batching_randomness];

        // This is relative to the previous commitment (i.e. prev_commitment has a domain size of
        // this size)
        let mut domain_size = config.starting_interleaved_log_height + config.starting_log_inv_rate;
        let mut generator = config.domain_generator;
        let mut prev_commitment = commitment;

        let mut prev_folding_factor = num_variables - config.starting_interleaved_log_height;
        let mut num_variables = config.starting_interleaved_log_height;

        for round_index in 0..n_rounds {
            let round_params = &config.round_parameters[round_index];
            // Because of the length checks at the start of the verification, the checked access isn't
            // expected to produce an error.
            let new_commitment =
                proof.commitments.get(round_index + 1).ok_or(WhirProofError::IncorrectShape)?;
            if new_commitment.ood_answers.len() != round_params.ood_samples {
                return Err(WhirProofError::InvalidNumberOfOODSamples(
                    round_params.ood_samples,
                    new_commitment.ood_answers.len(),
                ));
            }

            // Observe the commitments
            new_commitment.commitment.iter().for_each(|c| {
                challenger.observe(*c);
            });

            // Squeeze the ood points
            let ood_points: Vec<Point<GC::EF>> = (0..round_params.ood_samples)
                .map(|_| {
                    (0..num_variables)
                        .map(|_| challenger.sample_ext_element())
                        .collect::<Vec<GC::EF>>()
                        .into()
                })
                .collect();

            if ood_points != new_commitment.ood_points {
                return Err(WhirProofError::InvalidOOD);
            }

            // Absorb the OOD answers
            challenger.observe_ext_element_slice(&new_commitment.ood_answers);
            if !challenger.check_witness(
                round_params.queries_pow_bits,
                proof.query_proofs_of_work[round_index],
            ) {
                return Err(WhirProofError::PowError);
            }

            // Squeeze the STIR queries
            let id_query_indices = (0..round_params.num_queries)
                .map(|_| challenger.sample_bits(domain_size))
                .collect::<Vec<_>>();
            let id_query_values: Vec<GC::F> = id_query_indices
                .iter()
                .map(|val| reverse_bits_len(*val, domain_size))
                .map(|pos| generator.exp_u64(pos as u64))
                .collect();
            let claim_batching_randomness: GC::EF = challenger.sample_ext_element();

            let merkle_proof = if round_index != 0 {
                &proof.merkle_proofs[round_index - 1]
            } else {
                &proof.initial_merkle_proof
            };

            if round_index != 0 && merkle_proof.len() != 1 {
                return Err(WhirProofError::IncorrectShape);
            }

            for (merkle_commitment, merkle_proof) in
                prev_commitment.commitment.iter().zip(merkle_proof.iter())
            {
                self.merkle_verifier
                    .verify_tensor_openings(
                        merkle_commitment,
                        &id_query_indices,
                        &merkle_proof.values,
                        &merkle_proof.proof,
                    )
                    .map_err(|_| WhirProofError::InvalidMerkleAuthentication)?;
            }

            // Chunk the Merkle openings into chunks of size `1<<prev_folding_factor`
            // so that the verifier can induce in-domain evaluation claims about the next codeword.
            // Except in the first round, the opened values in the Merkle proof are secretly
            // extension field elements, so we have to reinterpret them as such. (The
            // Merkle tree API commits to and opens only base-field values.)
            let merkle_read_values: Vec<Mle<GC::EF>> = if round_index != 0 {
                merkle_proof
                    .iter()
                    .flat_map(|proof| {
                        proof
                            .values
                            .clone()
                            .into_buffer()
                            .into_extension::<GC::EF>()
                            .to_vec()
                            .chunks_exact(1 << prev_folding_factor)
                            .map(|v| Mle::new(v.to_vec().into()))
                            .collect::<Vec<_>>()
                    })
                    .collect()
            } else {
                let num_openings = merkle_proof.iter().map(|p| p.values.sizes()[1]).sum::<usize>();
                interleave_chain(merkle_proof.iter().map(|p| p.values.clone()))
                    .into_buffer()
                    .to_vec()
                    .into_iter()
                    .map(GC::EF::from)
                    .collect::<Vec<_>>()
                    .chunks_exact(num_openings)
                    .map(|v| Mle::new(v.to_vec().into()))
                    .collect::<Vec<_>>()
            };

            // Compute the STIR values by reading the merkle values and folding across the column.
            let stir_values: Vec<GC::EF> = merkle_read_values
                .iter()
                .map(|coeffs| coeffs.blocking_eval_at(&folding_randomness.clone().into())[0])
                .collect();

            // Update the claimed sum using the STIR values and the OOD answers.
            claimed_sum = claim_batching_randomness
                .powers()
                .zip(once(&claimed_sum).chain(&new_commitment.ood_answers).chain(&stir_values))
                .map(|(r, &v)| r * v)
                .sum();

            (folding_randomness, claimed_sum) = self
                .verify_sumcheck(
                    &proof.sumcheck_polynomials[round_index],
                    claimed_sum,
                    round_params.folding_factor,
                    &round_params.pow_bits,
                    challenger,
                )
                .map_err(|err| (err, round_index + 1))?;

            // Prepend the folding randomness from the sumcheck into the combined folding
            // randomness.
            concatenated_folding_randomness =
                [folding_randomness.clone(), concatenated_folding_randomness].concat();

            all_claim_batching_randomness.push(claim_batching_randomness);

            // Add both the in-domain and out-of-domain claims to the set of final evaluation
            // points.
            final_evaluation_points.push(
                [
                    ood_points.clone(),
                    id_query_values
                        .into_iter()
                        .map(|point| map_to_pow(point, num_variables).to_extension())
                        .collect(),
                ]
                .concat(),
            );

            domain_size = round_params.evaluation_domain_log_size;
            prev_commitment = new_commitment;
            prev_folding_factor = round_params.folding_factor;
            generator = generator.square();
            num_variables -= round_params.folding_factor;
            if prev_commitment.commitment.len() != 1 {
                return Err(WhirProofError::IncorrectShape);
            }
        }

        // Now, we want to verify the final evaluations
        if proof.final_polynomial.len() != 1 << config.final_poly_log_degree {
            return Err(WhirProofError::InvalidDegreeFinalPolynomial(
                1 << config.final_poly_log_degree,
                proof.final_polynomial.len(),
            ));
        }

        challenger.observe_constant_length_extension_slice(&proof.final_polynomial);

        let final_poly = proof.final_polynomial.clone();
        let final_poly_uv = UnivariatePolynomial::new(final_poly.clone());

        if !challenger.check_witness(config.final_pow_bits, proof.final_pow) {
            return Err(WhirProofError::PowError);
        }

        let final_id_indices = (0..config.final_queries)
            .map(|_| challenger.sample_bits(domain_size))
            .collect::<Vec<_>>();
        let final_id_values: Vec<GC::F> = final_id_indices
            .iter()
            .map(|val| reverse_bits_len(*val, domain_size))
            .map(|pos| generator.exp_u64(pos as u64))
            .collect();

        self.merkle_verifier
            .verify_tensor_openings(
                &prev_commitment.commitment[0],
                &final_id_indices,
                &proof.final_merkle_opening_and_proof.values,
                &proof.final_merkle_opening_and_proof.proof,
            )
            .map_err(|_| WhirProofError::InvalidMerkleAuthentication)?;

        let final_merkle_read_values: Vec<Mle<GC::EF>> = proof
            .final_merkle_opening_and_proof
            .values
            .clone()
            .into_buffer()
            .into_extension::<GC::EF>()
            .to_vec()
            .chunks_exact(1 << prev_folding_factor)
            .map(|v| Mle::new(v.to_vec().into()))
            .collect();

        // Compute the STIR values by reading the merkle values and folding across the column
        let final_stir_values: Vec<GC::EF> = final_merkle_read_values
            .iter()
            .map(|coeffs| coeffs.blocking_eval_at(&folding_randomness.clone().into())[0])
            .collect();

        if final_stir_values
            != final_id_values
                .into_iter()
                .map(|val| final_poly_uv.eval_at_point(val.into()))
                .collect::<Vec<_>>()
        {
            return Err(WhirProofError::FinalQueryMismatch);
        }

        (folding_randomness, claimed_sum) = self
            .verify_sumcheck(
                &proof.final_sumcheck_polynomials,
                claimed_sum,
                config.final_poly_log_degree,
                &config.final_folding_pow_bits,
                challenger,
            )
            .map_err(|err| (err, n_rounds + 1))?;

        concatenated_folding_randomness =
            [folding_randomness.clone(), concatenated_folding_randomness].concat();

        let f = Mle::new(proof.final_polynomial.clone().into())
            .blocking_eval_at(&Point::from(folding_randomness))[0];

        let mut summand = GC::EF::zero();
        for (i, eval_points) in
            final_evaluation_points.into_iter().enumerate().filter(|(_, ep)| !ep.is_empty())
        {
            let combination_randomness = all_claim_batching_randomness[i];
            let len = eval_points[0].len();
            let eval_randomness: Point<GC::EF> =
                concatenated_folding_randomness[..len].to_vec().into();

            let sum_modification = combination_randomness
                .powers()
                .skip(1)
                .zip(eval_points)
                .map(|(r, point)| r * { Mle::full_monomial_basis_eq(&point, &eval_randomness) })
                .sum::<GC::EF>();

            summand += sum_modification;
        }

        // This is the claimed value of the query vector. It is trusted and assumed to be easily
        // computable by the verifier.
        let claimed_value = claimed_sum / f - summand;

        Ok((concatenated_folding_randomness.into(), claimed_value))
    }

    // Verifies the sumcheck polynomial, returning the new claim value
    fn verify_sumcheck(
        &self,
        sumcheck_polynomials: &[(SumcheckPoly<GC::EF>, ProofOfWork<GC>)],
        mut claimed_sum: GC::EF,
        rounds: usize,
        pow_bits: &[usize],
        challenger: &mut GC::Challenger,
    ) -> Result<(Vec<GC::EF>, GC::EF), SumcheckError> {
        if sumcheck_polynomials.len() != rounds {
            return Err(SumcheckError::InvalidNumberOfSumcheckPoly(
                rounds,
                sumcheck_polynomials.len(),
            ));
        }
        if pow_bits.len() < rounds {
            return Err(SumcheckError::InvalidShape);
        }
        let mut randomness = Vec::with_capacity(rounds);
        for i in 0..rounds {
            let (sumcheck_poly, pow_witness) = &sumcheck_polynomials[i];
            challenger.observe_ext_element_slice(&sumcheck_poly.0);
            if sumcheck_poly.sum_over_hypercube() != claimed_sum {
                return Err(SumcheckError::InvalidSum);
            }

            if !challenger.check_witness(pow_bits[i], *pow_witness) {
                return Err(SumcheckError::PowError);
            }

            let folding_randomness_single: GC::EF = challenger.sample_ext_element();
            randomness.push(folding_randomness_single);

            claimed_sum = sumcheck_poly.evaluate_at_point(folding_randomness_single);
        }

        randomness.reverse();
        Ok((randomness, claimed_sum))
    }
}

impl<GC> MultilinearPcsVerifier<GC> for Verifier<GC>
where
    GC: IopCtx,
{
    type Proof = WhirProof<GC>;

    type VerifierError = WhirProofError;

    fn num_expected_commitments(&self) -> usize {
        self.num_expected_commitments
    }

    fn verify_trusted_evaluation(
        &self,
        commitments: &[<GC as IopCtx>::Digest],
        round_polynomial_sizes: &[usize],
        point: Point<<GC as IopCtx>::EF>,
        evaluation_claims: <GC as IopCtx>::EF,
        proof: &Self::Proof,
        challenger: &mut <GC as IopCtx>::Challenger,
    ) -> Result<(), Self::VerifierError> {
        let (randomness, claimed_value) = self.verify(
            commitments,
            round_polynomial_sizes,
            point.dimension(),
            evaluation_claims,
            proof,
            challenger,
        )?;
        let (folding_point, stacking_point) =
            point.split_at(point.dimension() - self.config.starting_interleaved_log_height);
        let point = stacking_point
            .iter()
            .copied()
            .chain(folding_point.iter().copied())
            .collect::<Point<_>>();
        if Mle::full_lagrange_eval(&randomness, &point) != claimed_value {
            return Err(WhirProofError::FinalEvalError);
        }
        Ok(())
    }

    /// The jagged verifier will assume that the underlying PCS will pad commitments to a multiple
    /// of `1<<log.stacking_height(verifier)`.
    fn log_stacking_height(verifier: &Self) -> u32 {
        verifier.config.starting_interleaved_log_height as u32
    }

    /// Functionality to deduce round by round from the proof the multiples of `1<<log.stacking_height`
    /// corresponding to the round's total polynomial size.
    fn round_multiples(proof: &<Self as MultilinearPcsVerifier<GC>>::Proof) -> Vec<usize> {
        proof.initial_merkle_proof.iter().map(|merkle_proof| merkle_proof.proof.width).collect()
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use slop_algebra::AbstractField;
    use slop_multilinear::monomial_basis_evals_blocking;

    use crate::verifier::map_to_pow;

    type F = slop_koala_bear::KoalaBear;
    #[test]
    fn test_monomial_basis_evals_and_map_to_pow() {
        let mut rng = rand::thread_rng();
        let x = rng.gen::<F>();
        let point = map_to_pow(x, 12);
        let select = monomial_basis_evals_blocking(&point);
        let select_vec = select.as_slice().to_vec();

        for (i, elem) in select_vec.iter().enumerate() {
            assert_eq!(*elem, x.exp_u64(i as u64));
        }
    }
}
