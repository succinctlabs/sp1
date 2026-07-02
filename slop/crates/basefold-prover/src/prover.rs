use slop_algebra::AbstractField;
use std::{fmt::Debug, marker::PhantomData, sync::Arc};

use derive_where::derive_where;

use itertools::Itertools;
use slop_algebra::TwoAdicField;
use slop_alloc::CpuBackend;
use slop_basefold::{BasefoldProof, BasefoldVerifier, RsCodeWord};
use slop_challenger::{CanObserve, CanSampleBits, FieldChallenger, GrindingChallenger, IopCtx};
use slop_commit::{Message, Rounds};
use slop_dft::p3::Radix2DitParallel;
use slop_futures::OwnedBorrow;
use slop_merkle_tree::{ComputeTcsOpenings, MerkleTreeOpeningAndProof, TensorCsProver};
use slop_multilinear::{BatchPcsProver, Mle, MleEncoder, Point};
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
    #[error("incorrect shape")]
    IncorrectShape,
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
    pub num_encoding_variables: u32,
    pub tcs_prover: P,
}

impl<GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>, P: ComputeTcsOpenings<GC, CpuBackend>>
    BasefoldProver<GC, P>
{
    #[inline]
    pub const fn from_parts(
        encoder: CpuDftEncoder<GC::F>,
        tcs_prover: P,
        num_encoding_variables: u32,
    ) -> Self {
        Self { encoder, tcs_prover, num_encoding_variables }
    }

    #[inline]
    pub fn new(verifier: &BasefoldVerifier<GC>) -> Self
    where
        P: Default,
    {
        let tcs_prover = P::default();
        let encoder =
            CpuDftEncoder { config: verifier.fri_config, dft: Arc::new(Radix2DitParallel) };
        let num_encoding_variables = verifier.num_encoding_variables;
        Self { encoder, tcs_prover, num_encoding_variables }
    }

    /// Reed–Solomon encode a batch of MLEs at an arbitrary `log_blowup` and commit to the resulting
    /// codewords.
    ///
    /// This is the general commit primitive; [`Self::commit_mles`] is the specialization at the
    /// encoder's configured blowup. Committing at a *reduced* blowup is how the ZK stacked PCS keeps
    /// the committed tensor the same size after appending its hiding rows. The MLE row counts must
    /// already be powers of two (the DFT encoder requires it); the caller does any padding the
    /// reduced rate assumes.
    #[inline]
    #[allow(clippy::type_complexity)]
    pub fn commit_mles_with_log_blowup<M>(
        &self,
        mles: Message<M>,
        log_blowup: usize,
    ) -> Result<
        (GC::Digest, BasefoldProverData<GC::F, P::ProverData>),
        BaseFoldConfigProverError<GC, P>,
    >
    where
        M: OwnedBorrow<Mle<GC::F>>,
    {
        // Encode the guts of the mles via Reed-Solomon encoding at the requested blowup.
        let encoded_messages = self.encoder.encode_batch_with_log_blowup(mles, log_blowup);

        // Commit to the encoded messages.
        let (commitment, tcs_prover_data) = self
            .tcs_prover
            .commit_tensors(encoded_messages.clone())
            .map_err(BaseFoldConfigProverError::<GC, P>::TcsCommitError)?;

        Ok((commitment, BasefoldProverData { encoded_messages, tcs_prover_data }))
    }

    /// Reed–Solomon encode a batch of MLEs at the encoder's configured blowup and commit to them.
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
        self.commit_mles_with_log_blowup(mles, self.encoder.config().log_blowup())
    }

    #[allow(clippy::type_complexity)]
    pub fn prove_from_prebatched_inputs(
        &self,
        mut eval_point: Point<GC::EF>,
        batched_mle: Mle<GC::EF, CpuBackend>,
        batched_eval_claim: GC::EF,
        batched_codeword: RsCodeWord<GC::F, CpuBackend>,
        prover_datas: Rounds<BasefoldProverData<GC::F, P::ProverData>>,
        challenger: &mut GC::Challenger,
    ) -> Result<BasefoldProof<GC>, BaseFoldConfigProverError<GC, P>> {
        let fri_prover = FriCpuProver::<GC, P>(PhantomData);

        let mut current_mle = batched_mle;
        let mut current_codeword = batched_codeword;

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
        // Main Basefold reduction loop
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
            let (beta, folded_mle, folded_codeword, commitment, leaves, prover_data_round) =
                fri_prover
                    .commit_phase_round(current_mle, current_codeword, &self.tcs_prover, challenger)
                    .map_err(BasefoldProverError::CommitPhaseError)?;

            fri_commitments.push(commitment);
            commit_phase_data.push(prover_data_round);
            commit_phase_values.push(leaves);

            current_mle = folded_mle;
            current_codeword = folded_codeword;
            current_batched_eval_claim = zero_val + beta * one_val;
        }

        // Finalize the constant polynomial
        let final_poly = fri_prover.final_poly(current_codeword);
        challenger.observe_ext_element(final_poly);

        // Proof of work
        let fri_config = self.encoder.config();
        let pow_bits = fri_config.proof_of_work_bits;
        let pow_witness = challenger.grind(pow_bits);

        // FRI Query Phase.
        let query_indices: Vec<usize> = (0..fri_config.num_queries)
            .map(|_| challenger.sample_bits(log_len as usize + fri_config.log_blowup()))
            .collect();

        // Open each committed polynomial at the query indices.
        let mut component_polynomials_query_openings_and_proofs = vec![];
        for prover_data in prover_datas {
            let BasefoldProverData { encoded_messages, tcs_prover_data } = prover_data;
            let values =
                self.tcs_prover.compute_openings_at_indices(encoded_messages, &query_indices);
            let proof = self
                .tcs_prover
                .prove_openings_at_indices(tcs_prover_data, &query_indices)
                .map_err(BaseFoldConfigProverError::<GC, P>::TcsCommitError)
                .unwrap();
            component_polynomials_query_openings_and_proofs
                .push(MerkleTreeOpeningAndProof::<GC> { values, proof });
        }

        // Provide openings for the FRI query phase.
        let mut query_phase_openings_and_proofs = vec![];
        let mut indices = query_indices;
        for (leaves, data) in commit_phase_values.into_iter().zip_eq(commit_phase_data) {
            for index in indices.iter_mut() {
                *index >>= 1;
            }
            let leaves: Message<Tensor<GC::F, CpuBackend>> = leaves.into();
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
}

/// A [`StackedPcsProver`] is a [`BatchPcsProver`]: a Basefold prover pinned to a fixed message
/// size (`num_encoding_variables = log_stacking_height`), mirroring the
/// [`BatchPcsVerifier`](slop_multilinear::BatchPcsVerifier) impl on
/// [`crate::StackedPcsVerifier`]. The opening protocol itself is plain prebatched Basefold;
/// the stacking height fixes how long the committed MLEs are allowed to be. `batch_size` and the
/// interleaving commit play no role on this path.
///
/// This is a temporary connector until stacked is refactored based on the new basefold API.
impl<GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>, P: ComputeTcsOpenings<GC, CpuBackend>>
    BatchPcsProver<GC> for BasefoldProver<GC, P>
{
    type Proof = BasefoldProof<GC>;
    type ProverError = BasefoldProverError<P::ProverError>;
    type Encoder = CpuDftEncoder<GC::F>;
    type ProverData = BasefoldProverData<GC::F, P::ProverData>;

    fn num_queries(&self) -> usize {
        self.encoder.config().num_queries
    }

    fn num_encoding_variables(&self) -> u32 {
        self.num_encoding_variables
    }

    fn encoder(&self) -> &Self::Encoder {
        &self.encoder
    }

    fn commit_mles_with_log_blowup(
        &self,
        mles: Message<Mle<GC::F>>,
        log_blowup: usize,
    ) -> Result<(GC::Digest, Self::ProverData), Self::ProverError> {
        // Delegate to the basefold commit at the requested rate.
        self.commit_mles_with_log_blowup(mles, log_blowup)
    }

    fn prove(
        &self,
        point: &Point<GC::EF>,
        eval: GC::EF,
        batched_polynomial: Mle<GC::EF>,
        batched_codeword: <Self::Encoder as MleEncoder<GC::F>>::Codeword,
        prover_data: Rounds<Self::ProverData>,
        challenger: &mut GC::Challenger,
    ) -> Result<Self::Proof, Self::ProverError> {
        self.prove_from_prebatched_inputs(
            point.clone(),
            batched_polynomial,
            eval,
            batched_codeword,
            prover_data,
            challenger,
        )
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use slop_algebra::AbstractExtensionField;
    use slop_baby_bear::baby_bear_poseidon2::BabyBearDegree4Duplex;
    use slop_basefold::{BasefoldVerifier, FriConfig};
    use slop_challenger::CanObserve;
    use slop_koala_bear::KoalaBearDegree4Duplex;
    use slop_merkle_tree::{
        ComputeTcsOpenings, Poseidon2BabyBear16Prover, Poseidon2KoalaBear16Prover,
    };
    use slop_multilinear::BatchPcsVerifier;

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

        let mut rng = thread_rng();
        let batched_mle = Mle::<GC::EF>::rand(&mut rng, 1, num_variables);

        let verifier =
            BasefoldVerifier::<GC>::new(FriConfig::default_fri_config(), 1, num_variables);
        let prover = BasefoldProver::<GC, P>::new(&verifier);

        let mut challenger = GC::default_challenger();

        let batched_mle_f = Mle::new(batched_mle.clone().into_guts().flatten_to_base());

        let (commitment, data) = prover.commit_mles(batched_mle_f.into()).unwrap();
        challenger.observe(commitment);
        let point = Point::<GC::EF>::rand(&mut rng, num_variables);
        let evaluation = batched_mle.eval_at(&point)[0];

        let codeword =
            Clone::clone(data.encoded_messages.clone().into_iter().collect::<Vec<_>>()[0].as_ref());

        let proof = prover
            .prove(
                &point,
                evaluation,
                batched_mle,
                codeword,
                Rounds { rounds: vec![data] },
                &mut challenger,
            )
            .unwrap();

        let mut challenger = GC::default_challenger();
        challenger.observe(commitment);

        let commitments = vec![commitment];

        let oracle_evaluator = |leaves: Rounds<&[GC::F]>, _index: usize| -> GC::EF {
            std::iter::repeat(&GC::EF::one())
                .zip(leaves.iter())
                .map(|(&c, &v)| c * GC::EF::from_base_slice(v))
                .sum()
        };
        verifier
            .verify(&commitments, &point, evaluation, oracle_evaluator, &proof, &mut challenger)
            .unwrap();
    }
}
