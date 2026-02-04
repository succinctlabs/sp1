use slop_algebra::AbstractField;
use std::{fmt::Debug, marker::PhantomData, sync::Arc};

use derive_where::derive_where;

use itertools::Itertools;
use slop_algebra::TwoAdicField;
use slop_alloc::CpuBackend;
use slop_basefold::{BasefoldProof, BasefoldVerifier, RsCodeWord};
use slop_challenger::{
    CanObserve, CanSampleBits, FieldChallenger, GrindingChallenger, IopCtx,
    VariableLengthChallenger,
};
use slop_commit::{Message, Rounds};
use slop_dft::p3::Radix2DitParallel;
use slop_futures::OwnedBorrow;
use slop_merkle_tree::{ComputeTcsOpenings, MerkleTreeOpeningAndProof, TensorCsProver};
use slop_multilinear::{
    partial_lagrange_blocking, Evaluations, Mle, MultilinearPcsChallenger, Point,
};
use slop_tensor::Tensor;
use thiserror::Error;

use crate::{CpuDftEncoder, FriCpuProver};

#[derive(Debug, Clone)]
#[derive_where(Serialize, Deserialize; ProverData, Tensor<F, CpuBackend>)]
pub struct BasefoldProverData<F, ProverData> {
    pub tcs_prover_data: ProverData,
    pub encoded_messages: Message<RsCodeWord<F, CpuBackend>>,
}

#[derive(Debug, Error)]
pub enum BasefoldProverError<TcsError> {
    #[error("Commit error: {0}")]
    TcsCommitError(TcsError),
    #[error("Commit phase error: {0}")]
    #[allow(clippy::type_complexity)]
    CommitPhaseError(TcsError),
}

pub type BaseFoldConfigProverError<GC, P> =
    BasefoldProverError<<P as TensorCsProver<GC, CpuBackend>>::ProverError>;

/// A prover for the BaseFold protocol.
///
/// The [BasefoldProver] struct implements the interactive parts of the Basefold PCS while
/// abstracting some of the key parts.
#[derive(Clone)]
pub struct BasefoldProver<GC: IopCtx<F: TwoAdicField>, P: ComputeTcsOpenings<GC, CpuBackend>> {
    pub encoder: CpuDftEncoder<GC::F>,
    pub tcs_prover: P,
}

impl<GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>, P: ComputeTcsOpenings<GC, CpuBackend>>
    BasefoldProver<GC, P>
{
    #[inline]
    pub const fn from_parts(encoder: CpuDftEncoder<GC::F>, tcs_prover: P) -> Self {
        Self { encoder, tcs_prover }
    }

    #[inline]
    pub fn new(verifier: &BasefoldVerifier<GC>) -> Self
    where
        P: Default,
    {
        let tcs_prover = P::default();
        let encoder =
            CpuDftEncoder { config: verifier.fri_config, dft: Arc::new(Radix2DitParallel) };
        Self { encoder, tcs_prover }
    }

    #[inline]
    #[allow(clippy::type_complexity)]
    pub fn commit_mles<M>(
        &self,
        mles: Message<M>,
    ) -> Result<
        (GC::Digest, BasefoldProverData<GC::F, P::ProverData>),
        BaseFoldConfigProverError<GC, P>,
    >
    where
        M: OwnedBorrow<Mle<GC::F>>,
    {
        // Encode the guts of the mle via Reed-Solomon encoding.

        let encoded_messages = self.encoder.encode_batch(mles.clone()).unwrap();

        // Commit to the encoded messages.
        let (commitment, tcs_prover_data) = self
            .tcs_prover
            .commit_tensors(encoded_messages.clone())
            .map_err(BaseFoldConfigProverError::<GC, P>::TcsCommitError)?;

        Ok((commitment, BasefoldProverData { encoded_messages, tcs_prover_data }))
    }

    #[inline]
    pub fn prove_trusted_mle_evaluations(
        &self,
        mut eval_point: Point<GC::EF>,
        mle_rounds: Rounds<Message<Mle<GC::F>>>,
        evaluation_claims: Rounds<Evaluations<GC::EF>>,
        prover_data: Rounds<BasefoldProverData<GC::F, P::ProverData>>,
        challenger: &mut GC::Challenger,
    ) -> Result<BasefoldProof<GC>, BaseFoldConfigProverError<GC, P>> {
        let fri_prover = FriCpuProver::<GC, P>(PhantomData);
        // Get all the mles from all rounds in order.
        let mles = mle_rounds
            .iter()
            .flat_map(|round| round.clone().into_iter())
            .collect::<Message<Mle<_, _>>>();

        let encoded_messages = prover_data
            .iter()
            .flat_map(|data| data.encoded_messages.iter().cloned())
            .collect::<Message<RsCodeWord<_, _>>>();

        let evaluation_claims = evaluation_claims.into_iter().flatten().collect::<Vec<_>>();

        // Sample batching coefficients via partial Lagrange basis.
        let total_len = mles.iter().map(|mle| mle.num_polynomials()).sum::<usize>();
        let num_batching_variables = total_len.next_power_of_two().ilog2();
        let batching_point = challenger.sample_point::<GC::EF>(num_batching_variables);

        let batching_coefficients = partial_lagrange_blocking(&batching_point);

        // Batch the mles and codewords.
        let (mle_batch, codeword_batch, batched_eval_claim) = fri_prover.batch(
            &batching_coefficients,
            mles,
            encoded_messages,
            evaluation_claims,
            &self.encoder,
        );
        // From this point on, run the BaseFold protocol on the random linear combination codeword,
        // the random linear combination multilinear, and the random linear combination of the
        // evaluation claims.
        let mut current_mle = mle_batch;
        let mut current_codeword = codeword_batch;
        // Initialize the vecs that go into a BaseFoldProof.
        let log_len = current_mle.num_variables();
        let mut univariate_messages: Vec<[GC::EF; 2]> = vec![];
        let mut fri_commitments = vec![];
        let mut commit_phase_data = vec![];
        let mut current_batched_eval_claim = batched_eval_claim;
        let mut commit_phase_values = vec![];

        assert_eq!(
            current_mle.num_variables(),
            eval_point.dimension() as u32,
            "eval point dimension mismatch"
        );
        // Observe the number of FRI rounds. In principle, the prover is bound to this number already
        // because it is determined by the heights of the codewords and the log_blowup, but we
        // observe it here for extra security.
        challenger.observe(GC::F::from_canonical_usize(eval_point.dimension()));
        for _ in 0..eval_point.dimension() {
            // Compute claims for `g(X_0, X_1, ..., X_{d-1}, 0)` and `g(X_0, X_1, ..., X_{d-1}, 1)`.
            let last_coord = eval_point.remove_last_coordinate();
            let zero_values = current_mle.fixed_at_zero(&eval_point);
            let zero_val = zero_values[0];
            let one_val = (current_batched_eval_claim - zero_val) / last_coord + zero_val;
            let uni_poly = [zero_val, one_val];
            univariate_messages.push(uni_poly);

            uni_poly.iter().for_each(|elem| challenger.observe_ext_element(*elem));

            // Perform a single round of the FRI commit phase, returning the commitment, folded
            // codeword, and folding parameter.
            let (beta, folded_mle, folded_codeword, commitment, leaves, prover_data) = fri_prover
                .commit_phase_round(current_mle, current_codeword, &self.tcs_prover, challenger)
                .map_err(BasefoldProverError::CommitPhaseError)?;

            fri_commitments.push(commitment);
            commit_phase_data.push(prover_data);
            commit_phase_values.push(leaves);

            current_mle = folded_mle;
            current_codeword = folded_codeword;
            current_batched_eval_claim = zero_val + beta * one_val;
        }

        let final_poly = fri_prover.final_poly(current_codeword);
        challenger.observe_ext_element(final_poly);

        let fri_config = self.encoder.config();
        let pow_bits = fri_config.proof_of_work_bits;
        let pow_witness = challenger.grind(pow_bits);
        // FRI Query Phase.
        let query_indices: Vec<usize> = (0..fri_config.num_queries)
            .map(|_| challenger.sample_bits(log_len as usize + fri_config.log_blowup()))
            .collect();

        // Open the original polynomials at the query indices.
        let mut component_polynomials_query_openings_and_proofs = vec![];
        for prover_data in prover_data {
            let BasefoldProverData { encoded_messages, tcs_prover_data } = prover_data;
            let values =
                self.tcs_prover.compute_openings_at_indices(encoded_messages, &query_indices);
            let proof = self
                .tcs_prover
                .prove_openings_at_indices(tcs_prover_data, &query_indices)
                .map_err(BaseFoldConfigProverError::<GC, P>::TcsCommitError)
                .unwrap();
            let opening = MerkleTreeOpeningAndProof::<GC> { values, proof };
            component_polynomials_query_openings_and_proofs.push(opening);
        }

        // Provide openings for the FRI query phase.
        let mut query_phase_openings_and_proofs = vec![];
        let mut indices = query_indices;
        for (leaves, data) in commit_phase_values.into_iter().zip_eq(commit_phase_data) {
            for index in indices.iter_mut() {
                *index >>= 1;
            }
            let leaves: Message<Tensor<GC::F>> = leaves.into();
            let values = self.tcs_prover.compute_openings_at_indices(leaves, &indices);

            let proof = self
                .tcs_prover
                .prove_openings_at_indices(data, &indices)
                .map_err(BaseFoldConfigProverError::<GC, P>::TcsCommitError)?;
            let opening = MerkleTreeOpeningAndProof { values, proof };
            query_phase_openings_and_proofs.push(opening);
        }

        Ok(BasefoldProof {
            univariate_messages,
            fri_commitments,
            component_polynomials_query_openings_and_proofs,
            query_phase_openings_and_proofs,
            final_poly,
            pow_witness,
        })
    }

    pub fn prove_untrusted_evaluations(
        &self,
        eval_point: Point<GC::EF>,
        mle_rounds: Rounds<Message<Mle<GC::F>>>,
        evaluation_claims: Rounds<Evaluations<GC::EF>>,
        prover_data: Rounds<BasefoldProverData<GC::F, P::ProverData>>,
        challenger: &mut GC::Challenger,
    ) -> Result<BasefoldProof<GC>, BaseFoldConfigProverError<GC, P>> {
        // Observe the evaluation claims.
        for round in evaluation_claims.iter() {
            // We assume that in the process of producing `commitments`, the prover is bound
            // to the number of polynomials in each round. Thus, we can observe the evaluation
            // claims without observing their length.
            for mle_eval in round.iter() {
                challenger.observe_constant_length_extension_slice(mle_eval);
            }
        }

        self.prove_trusted_mle_evaluations(
            eval_point,
            mle_rounds,
            evaluation_claims,
            prover_data,
            challenger,
        )
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use slop_baby_bear::baby_bear_poseidon2::BabyBearDegree4Duplex;
    use slop_basefold::{BasefoldVerifier, FriConfig};
    use slop_challenger::CanObserve;
    use slop_koala_bear::KoalaBearDegree4Duplex;
    use slop_merkle_tree::{
        ComputeTcsOpenings, Poseidon2BabyBear16Prover, Poseidon2KoalaBear16Prover,
    };
    use slop_multilinear::MleEval;

    use super::*;

    #[test]
    fn test_baby_bear_basefold_prover() {
        test_basefold_prover_backend::<BabyBearDegree4Duplex, Poseidon2BabyBear16Prover>();
    }

    #[test]
    fn test_koala_bear_basefold_prover() {
        test_basefold_prover_backend::<KoalaBearDegree4Duplex, Poseidon2KoalaBear16Prover>();
    }

    fn test_basefold_prover_backend<
        GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
        P: ComputeTcsOpenings<GC, CpuBackend> + Default,
    >()
    where
        rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
        rand::distributions::Standard: rand::distributions::Distribution<GC::EF>,
    {
        let num_variables = 16;
        let round_widths = [vec![16, 10, 14], vec![20, 78, 34], vec![10, 10]];

        let mut rng = thread_rng();
        let round_mles = round_widths
            .iter()
            .map(|widths| {
                widths
                    .iter()
                    .map(|&w| Mle::<GC::F>::rand(&mut rng, w, num_variables))
                    .collect::<Message<_>>()
            })
            .collect::<Rounds<_>>();

        let verifier =
            BasefoldVerifier::<GC>::new(FriConfig::default_fri_config(), round_widths.len());
        let prover = BasefoldProver::<GC, P>::new(&verifier);

        let mut challenger = GC::default_challenger();
        let mut commitments = vec![];
        let mut prover_data = Rounds::new();
        let mut eval_claims = Rounds::new();
        let point = Point::<GC::EF>::rand(&mut rng, num_variables);
        for mles in round_mles.iter() {
            let (commitment, data) = prover.commit_mles(mles.clone()).unwrap();
            challenger.observe(commitment);
            commitments.push(commitment);
            prover_data.push(data);
            let evaluations =
                mles.iter().map(|mle| mle.eval_at(&point)).collect::<Evaluations<_>>();
            eval_claims.push(evaluations);
        }

        let proof = prover
            .prove_trusted_mle_evaluations(
                point.clone(),
                round_mles,
                eval_claims.clone(),
                prover_data,
                &mut challenger,
            )
            .unwrap();

        let mut challenger = GC::default_challenger();
        for commitment in commitments.iter() {
            challenger.observe(*commitment);
        }

        let eval_claims = eval_claims
            .into_iter()
            .map(|round| round.into_iter().flat_map(|x| x.into_iter()).collect::<MleEval<_>>())
            .collect::<Vec<_>>();
        verifier
            .verify_mle_evaluations(&commitments, point, &eval_claims, &proof, &mut challenger)
            .unwrap();
    }
}
