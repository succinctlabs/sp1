use derive_where::derive_where;
use itertools::Itertools;
use slop_challenger::{FieldChallenger, GrindingChallenger, IopCtx};
use slop_commit::Rounds;
use slop_multilinear::{BatchPcsVerifier, Mle, MleEval, Point};
use thiserror::Error;

use crate::{EqBatchedEvalClaim, EqBatchedProof, EqBatchedVerifier, EqBatchedVerifierError};
#[derive(Clone)]
pub struct StackedPcsVerifier<GC, InnerVerifier> {
    pub inner_verifier: EqBatchedVerifier<GC, InnerVerifier>,
    _marker: std::marker::PhantomData<GC>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StackedVerifierError<PcsError> {
    #[error("PCS error: {0}")]
    PcsError(#[from] PcsError),
    #[error("Batch evaluations do not match the claimed evaluations")]
    StackingError,
    #[error("Proof has incorrect shape")]
    IncorrectShape,
}

#[derive_where(Debug, Clone, Serialize, Deserialize; MleEval<GC::EF>, EqBatchedProof<InnerProof, <GC::Challenger as GrindingChallenger>::Witness>)]
pub struct StackedProof<GC: IopCtx, InnerProof> {
    pub inner_proof: EqBatchedProof<InnerProof, <GC::Challenger as GrindingChallenger>::Witness>,
    pub batch_evaluations: Rounds<MleEval<GC::EF>>,
}

/// The public statement for a stacked-PCS opening.
///
/// Shared by the prover and the verifier. The commitments and the prover's witness data
/// ([`StackedProverData`](crate::StackedProverData)) are passed to the prove/verify functions
/// separately — they identify the committed data / witness, not the claim itself.
#[derive_where(Debug, Clone; Point<GC::EF>, GC::EF)]
pub struct StackedEvalClaim<GC: IopCtx> {
    /// Per-round padded areas (each a multiple of the stacking height). The verifier derives these
    /// independently from the committed shape and cross-checks them against the proof's per-round
    /// evaluation lengths; the prover's opening logic does not read them.
    pub round_areas: Vec<usize>,
    /// The point at which the stacked multilinear is evaluated.
    pub point: Point<GC::EF>,
    /// The claimed evaluation of the stacked multilinear at `point`.
    pub evaluation: GC::EF,
}

impl<GC: IopCtx, Verifier: BatchPcsVerifier<GC>> StackedPcsVerifier<GC, Verifier> {
    #[inline]
    pub const fn new(inner_verifier: EqBatchedVerifier<GC, Verifier>) -> Self {
        Self { inner_verifier, _marker: std::marker::PhantomData }
    }

    #[inline]
    pub const fn new_from_inner(inner: Verifier, pow_bits: usize) -> Self {
        Self::new(EqBatchedVerifier::new(inner, pow_bits))
    }

    pub fn log_stacking_height(&self) -> u32 {
        self.inner_verifier.inner.num_encoding_variables()
    }

    pub fn verify_untrusted_evaluation(
        &self,
        commitments: &[GC::Digest],
        claim: &StackedEvalClaim<GC>,
        proof: &StackedProof<GC, Verifier::Proof>,
        challenger: &mut GC::Challenger,
    ) -> Result<(), StackedVerifierError<EqBatchedVerifierError<Verifier::VerifierError>>>
where {
        challenger.observe_ext_element(claim.evaluation);
        self.verify_trusted_evaluation(commitments, claim, proof, challenger)
    }

    pub fn verify_trusted_evaluation(
        &self,
        commitments: &[GC::Digest],
        claim: &StackedEvalClaim<GC>,
        proof: &StackedProof<GC, Verifier::Proof>,
        challenger: &mut GC::Challenger,
    ) -> Result<(), StackedVerifierError<EqBatchedVerifierError<Verifier::VerifierError>>>
where {
        let StackedEvalClaim { round_areas, point, evaluation } = claim;

        if point.dimension() < self.log_stacking_height() as usize {
            return Err(StackedVerifierError::IncorrectShape);
        }

        // Split the point into the interleaved and batched parts.
        let (batch_point, stack_point) =
            point.split_at(point.dimension() - self.log_stacking_height() as usize);

        if proof.batch_evaluations.len() != round_areas.len()
            || commitments.len() != round_areas.len()
        {
            return Err(StackedVerifierError::IncorrectShape);
        }

        for (round_area, proof_evaluation_len) in
            round_areas.iter().zip_eq(proof.batch_evaluations.iter())
        {
            if !round_area.is_multiple_of(1 << self.log_stacking_height())
                || round_area >> self.log_stacking_height() as usize
                    != proof_evaluation_len.num_polynomials()
            {
                return Err(StackedVerifierError::IncorrectShape);
            }
        }

        // Interpolate the batch evaluations as a multilinear polynomial.
        let batch_evaluations =
            proof.batch_evaluations.iter().flatten().cloned().collect::<Mle<_>>();

        // Verify that the climed evaluations matched the interpolated evaluations.
        let expected_evaluation = batch_evaluations.blocking_eval_at(&batch_point)[0];
        if *evaluation != expected_evaluation {
            return Err(StackedVerifierError::StackingError);
        }

        // Verify the PCS proof with respect to the claimed evaluations.
        // It is assumed that the multilinear batch PCS verifier checks that the number of
        // commitments is as expected. The proof already carries one flattened `MleEval` per round.
        let batched_claim = EqBatchedEvalClaim {
            point: stack_point,
            evaluations: proof.batch_evaluations.iter().cloned().collect(),
        };
        self.inner_verifier.verify_untrusted_evaluations(
            commitments,
            &batched_claim,
            &proof.inner_proof,
            challenger,
        )?;
        Ok(())
    }
}
