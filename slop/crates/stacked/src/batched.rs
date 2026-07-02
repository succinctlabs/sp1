use std::marker::PhantomData;

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField};
use slop_alloc::Buffer;
use slop_challenger::{GrindingChallenger, IopCtx, VariableLengthChallenger};
use slop_commit::{Message, Rounds};
use slop_futures::OwnedBorrow;
use slop_multilinear::{
    partial_lagrange_blocking, BatchPcsProver, BatchPcsVerifier, Mle, MleEncoder, MleEval,
    MultilinearPcsChallenger, Point,
};
use slop_tensor::Tensor;
use thiserror::Error;

#[derive(Clone, Serialize, Deserialize)]
pub struct EqBatchedProof<Proof, Witness> {
    /// The inner base-PCS proof for the batched evaluation claim.
    pub inner_proof: Proof,
    /// The grinding witness for the batching randomness.
    pub batch_grinding_witness: Witness,
}

/// The public statement for a batched multi-oracle opening: the shared evaluation point and the
/// per-oracle evaluation claims (one flattened [`MleEval`] per committed round). Shared by the
/// prover and the verifier; the commitments and the prover's MLEs / prover data are passed
/// separately. Producers holding per-table [`Evaluations`] flatten each round into a single
/// `MleEval` when building the claim (see [`StackedPcsProver`](crate::StackedPcsProver)).
#[derive(Debug, Clone)]
pub struct EqBatchedEvalClaim<GC: IopCtx> {
    /// The point at which every batched oracle is evaluated.
    pub point: Point<GC::EF>,
    /// The claimed evaluations, one flattened `MleEval` per committed round (in commitment order).
    pub evaluations: Vec<MleEval<GC::EF>>,
}

#[derive(Error, Debug)]
pub enum EqBatchedVerifierError<InnerError> {
    #[error("Inner PCS verification failed with error: {0}")]
    InnerVerificationFailed(#[from] InnerError),
    #[error("Batch POW witness incorrect")]
    BatchPow,
    #[error("Incorrect shape")]
    IncorrectShape,
}

#[derive(Clone)]
pub struct EqBatchedVerifier<GC, Verifier> {
    pub inner: Verifier,
    pub pow_bits: usize,
    _marker: PhantomData<GC>,
}

impl<GC: IopCtx, Verifier: BatchPcsVerifier<GC>> EqBatchedVerifier<GC, Verifier> {
    #[inline]
    pub const fn new(inner: Verifier, pow_bits: usize) -> Self {
        Self { inner, pow_bits, _marker: PhantomData }
    }

    pub fn verify_mle_evaluations(
        &self,
        commitments: &[GC::Digest],
        claim: &EqBatchedEvalClaim<GC>,
        proof: &EqBatchedProof<Verifier::Proof, <GC::Challenger as GrindingChallenger>::Witness>,
        challenger: &mut GC::Challenger,
    ) -> Result<(), EqBatchedVerifierError<Verifier::VerifierError>> {
        let EqBatchedEvalClaim { point, evaluations } = claim;

        // Check batch grinding witness.
        if !challenger.check_witness(self.pow_bits, proof.batch_grinding_witness) {
            return Err(EqBatchedVerifierError::BatchPow);
        }

        // Sample the challenge used to batch all the different polynomials. The batching runs over
        // every committed column, one round per commitment.
        let total_len =
            evaluations.iter().map(|batch_claims| batch_claims.num_polynomials()).sum::<usize>();

        let num_batching_variables = total_len.next_power_of_two().ilog2();
        let batching_point = challenger.sample_point::<GC::EF>(num_batching_variables);
        let batching_coefficients = partial_lagrange_blocking(&batching_point);

        // Compute the batched evaluation claim.
        let eval_claim = evaluations
            .iter()
            .flat_map(|batch_claims| batch_claims.iter())
            .zip(batching_coefficients.as_slice())
            .map(|(eval, batch_power)| *eval * *batch_power)
            .sum::<GC::EF>();

        if evaluations.len() != commitments.len() {
            return Err(EqBatchedVerifierError::IncorrectShape);
        }

        // The virtual oracle is just the random linear combination of the component polynomials:
        // for each query, the opened values (one round per commitment, in commitment order) are
        // flattened and combined against the batching coefficients, which are laid out in that same
        // order.
        let to_virtual_oracle = |values: Rounds<&[GC::F]>, _index: usize| -> GC::EF {
            values
                .iter()
                .flat_map(|round| round.iter())
                .zip(batching_coefficients.as_slice())
                .map(|(value, batching_coefficient)| *batching_coefficient * *value)
                .sum()
        };

        self.inner.verify(
            commitments,
            point,
            eval_claim,
            to_virtual_oracle,
            &proof.inner_proof,
            challenger,
        )?;
        Ok(())
    }

    pub fn verify_untrusted_evaluations(
        &self,
        commitments: &[GC::Digest],
        claim: &EqBatchedEvalClaim<GC>,
        proof: &EqBatchedProof<Verifier::Proof, <GC::Challenger as GrindingChallenger>::Witness>,
        challenger: &mut GC::Challenger,
    ) -> Result<(), EqBatchedVerifierError<Verifier::VerifierError>> {
        // Observe the evaluation claims (one flattened `MleEval` per committed round).
        for mle_eval in claim.evaluations.iter() {
            // We assume that in the process of producing `commitments`, the prover is bound
            // to the number of polynomials in each round. Thus, we can observe the evaluation
            // claims without observing their length.
            challenger.observe_constant_length_extension_slice(mle_eval);
        }

        self.verify_mle_evaluations(commitments, claim, proof, challenger)
    }
}

#[derive(Clone)]
pub struct EqBatchedProver<GC, Prover> {
    pub prover: Prover,
    pub batch_grinding_bits: usize,
    _marker: PhantomData<GC>,
}

#[derive(
    Debug, Clone, Default, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct CpuBatcher<GC>(pub PhantomData<GC>);

impl<GC: IopCtx> CpuBatcher<GC> {
    #[allow(clippy::type_complexity)]
    pub(crate) fn batch<M, E: MleEncoder<GC::F>>(
        &self,
        batching_coefficients: &Tensor<GC::EF>,
        mles: Message<M>,
        evaluation_claims: Vec<MleEval<GC::EF>>,
        encoder: &E,
    ) -> (Mle<GC::EF>, E::Codeword, GC::EF)
    where
        M: OwnedBorrow<Mle<GC::F>>,
    {
        let num_variables = mles.first().unwrap().as_ref().borrow().num_variables() as usize;

        let mut batching_coefficients_iter = batching_coefficients.as_slice().iter();

        // Compute the random linear combination of the MLEs of the columns of the matrices
        let mut batch_mle = Mle::from(vec![GC::EF::zero(); 1 << num_variables]);
        for mle in mles.iter() {
            let mle: &Mle<_, _> = mle.as_ref().borrow();
            let batch_size = mle.num_polynomials();
            let coeffs = batching_coefficients_iter.by_ref().take(batch_size).collect::<Vec<_>>();
            // Batch the mles as an inner product.
            batch_mle.guts_mut().as_mut_slice().iter_mut().zip_eq(mle.hypercube_iter()).for_each(
                |(batch, row)| {
                    let batch_row =
                        coeffs.iter().zip_eq(row).map(|(a, b)| **a * *b).sum::<GC::EF>();
                    *batch += batch_row;
                },
            );
        }

        let batched_eval_claim = evaluation_claims
            .iter()
            .flat_map(|batch_claims| unsafe {
                batch_claims.evaluations().storage.copy_into_host_vec()
            })
            .zip(batching_coefficients.as_slice())
            .map(|(eval, batch_power)| eval * *batch_power)
            .sum::<GC::EF>();

        let batch_mle_f = Buffer::from(batch_mle.clone().into_guts().storage.as_slice().to_vec())
            .flatten_to_base::<GC::F>();
        let batch_mle_f = Tensor::from(batch_mle_f).reshape([1 << num_variables, GC::EF::D]);
        let batch_codeword = encoder.encode(Mle::new(batch_mle_f));

        (batch_mle, batch_codeword, batched_eval_claim)
    }
}

type BatchedProveResult<GC, P> = Result<
    EqBatchedProof<
        <P as BatchPcsProver<GC>>::Proof,
        <<GC as IopCtx>::Challenger as GrindingChallenger>::Witness,
    >,
    <P as BatchPcsProver<GC>>::ProverError,
>;

impl<GC: IopCtx, P: BatchPcsProver<GC>> EqBatchedProver<GC, P> {
    pub fn new(prover: P, batch_grinding_bits: usize) -> Self {
        Self { prover, batch_grinding_bits, _marker: PhantomData }
    }

    pub fn commit_mles(
        &self,
        mles: Message<Mle<GC::F>>,
    ) -> Result<(GC::Digest, P::ProverData), P::ProverError> {
        self.prover.commit_mles(mles)
    }

    #[inline]
    pub fn prove_trusted_mle_evaluations(
        &self,
        claim: &EqBatchedEvalClaim<GC>,
        mle_rounds: Rounds<Message<Mle<GC::F>>>,
        prover_data: Rounds<P::ProverData>,
        challenger: &mut GC::Challenger,
    ) -> BatchedProveResult<GC, P> {
        let batcher = CpuBatcher::<GC>(PhantomData);
        // Get all the mles from all rounds in order.
        let mles = mle_rounds
            .iter()
            .flat_map(|round| round.clone().into_iter())
            .collect::<Message<Mle<_, _>>>();

        // One flattened `MleEval` per committed round, already in batched-column order.
        let evaluation_claims = claim.evaluations.clone();

        // Grind for batch randomness.
        let batch_grinding_witness = challenger.grind(self.batch_grinding_bits);

        // Sample batching coefficients via partial Lagrange basis.
        let total_len = mles.iter().map(|mle| mle.num_polynomials()).sum::<usize>();
        let num_batching_variables = total_len.next_power_of_two().ilog2();
        let batching_point = challenger.sample_point::<GC::EF>(num_batching_variables);

        let batching_coefficients = partial_lagrange_blocking(&batching_point);

        // Batch the mles and codewords.
        let (mle_batch, codeword_batch, batched_eval_claim) =
            batcher.batch(&batching_coefficients, mles, evaluation_claims, self.prover.encoder());

        // Run the BaseFold protocol on the random linear combination codeword,
        // the random linear combination multilinear, and the random linear combination of the
        // evaluation claims.
        let inner_proof = self.prover.prove(
            &claim.point,
            batched_eval_claim,
            mle_batch,
            codeword_batch,
            prover_data,
            challenger,
        )?;
        Ok(EqBatchedProof { inner_proof, batch_grinding_witness })
    }

    pub fn prove_untrusted_evaluations(
        &self,
        claim: &EqBatchedEvalClaim<GC>,
        mle_rounds: Rounds<Message<Mle<GC::F>>>,
        prover_data: Rounds<P::ProverData>,
        challenger: &mut GC::Challenger,
    ) -> BatchedProveResult<GC, P> {
        // Observe the evaluation claims (one flattened `MleEval` per committed round).
        for mle_eval in claim.evaluations.iter() {
            // We assume that in the process of producing `commitments`, the prover is bound
            // to the number of polynomials in each round. Thus, we can observe the evaluation
            // claims without observing their length.
            challenger.observe_constant_length_extension_slice(mle_eval);
        }

        self.prove_trusted_mle_evaluations(claim, mle_rounds, prover_data, challenger)
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use slop_algebra::TwoAdicField;
    use slop_alloc::CpuBackend;
    use slop_baby_bear::baby_bear_poseidon2::BabyBearDegree4Duplex;
    use slop_basefold::BasefoldVerifier;
    use slop_basefold::FriConfig;
    use slop_basefold::BATCH_GRINDING_BITS;
    use slop_basefold_prover::BasefoldProver;
    use slop_challenger::CanObserve;
    use slop_challenger::IopCtx;
    use slop_commit::Message;
    use slop_commit::Rounds;
    use slop_koala_bear::KoalaBearDegree4Duplex;
    use slop_merkle_tree::ComputeTcsOpenings;
    use slop_merkle_tree::Poseidon2BabyBear16Prover;
    use slop_merkle_tree::Poseidon2KoalaBear16Prover;
    use slop_multilinear::Evaluations;
    use slop_multilinear::Mle;
    use slop_multilinear::MleEval;
    use slop_multilinear::Point;

    use crate::EqBatchedEvalClaim;
    use crate::EqBatchedProver;
    use crate::EqBatchedVerifier;

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

        let verifier = BasefoldVerifier::<GC>::new(
            FriConfig::default_fri_config(),
            round_widths.len(),
            num_variables,
        );
        let prover = BasefoldProver::<GC, P>::new(&verifier);
        let prover = EqBatchedProver::new(prover, BATCH_GRINDING_BITS);
        let verifier = EqBatchedVerifier::new(verifier, BATCH_GRINDING_BITS);

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

        // Flatten each round's per-table evals into a single `MleEval` (one per commitment).
        let evaluations = eval_claims
            .into_iter()
            .map(|round| round.into_iter().flatten().collect::<MleEval<_>>())
            .collect::<Vec<_>>();
        let claim = EqBatchedEvalClaim { point: point.clone(), evaluations };
        let proof = prover
            .prove_trusted_mle_evaluations(&claim, round_mles, prover_data, &mut challenger)
            .unwrap();

        let mut challenger = GC::default_challenger();
        for commitment in commitments.iter() {
            challenger.observe(*commitment);
        }

        verifier.verify_mle_evaluations(&commitments, &claim, &proof, &mut challenger).unwrap();
    }
}
