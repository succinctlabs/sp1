use slop_algebra::TwoAdicField;
use slop_basefold::{BaseFoldVerifierError, BasefoldVerifier, BATCH_GRINDING_BITS};
use slop_challenger::IopCtx;
use slop_merkle_tree::MerkleTreeTcsError;
use slop_multilinear::{Mle, Point};
use slop_stacked::{EqBatchedEvalClaim, EqBatchedVerifier, EqBatchedVerifierError};
use slop_sumcheck::{partially_verify_sumcheck_proof, SumcheckError};

use crate::prover::{Proof, SparsePCSBasefoldProof};

pub struct SparsePCSVerifier<GC: IopCtx> {
    pub multilinear_verifier: EqBatchedVerifier<GC, BasefoldVerifier<GC>>,
}

#[derive(Debug)]
pub enum VerifierError<PCSError> {
    PCSError(PCSError),
    SumcheckError(SumcheckError),
    InvalidClaimedSum,
    InvalidMLEEvalClaims,
}

impl<GC: IopCtx> SparsePCSVerifier<GC>
where
    GC::F: TwoAdicField,
{
    pub fn new(verifier: BasefoldVerifier<GC>) -> Self {
        Self { multilinear_verifier: EqBatchedVerifier::new(verifier, BATCH_GRINDING_BITS) }
    }

    pub fn verify_trusted_evaluations(
        &self,
        commitment: GC::Digest,
        eval_point: &Point<GC::EF>,
        evaluation_claim: GC::EF,
        proof: &Proof<GC::EF, SparsePCSBasefoldProof<GC>>,
        challenger: &mut GC::Challenger,
    ) -> Result<(), VerifierError<EqBatchedVerifierError<BaseFoldVerifierError<MerkleTreeTcsError>>>>
    {
        // Verify the sumcheck proof
        partially_verify_sumcheck_proof(
            &proof.sparse_sumcheck_proof,
            challenger,
            proof.sparse_sumcheck_proof.point_and_eval.0.len(),
            eval_point.dimension() + 1,
        )
        .map_err(VerifierError::SumcheckError)?;

        if evaluation_claim != proof.sparse_sumcheck_proof.claimed_sum {
            return Err(VerifierError::InvalidClaimedSum);
        };

        // Check the final equation
        if proof.evaluation_claims[proof.evaluation_claims.len() - 1]
            * Mle::full_lagrange_eval(
                eval_point,
                &proof.evaluation_claims[0..proof.evaluation_claims.len() - 1].to_vec().into(),
            )
            != proof.sparse_sumcheck_proof.point_and_eval.1
        {
            return Err(VerifierError::InvalidMLEEvalClaims);
        }

        // Parse the evaluation proof
        let new_eval_point = proof.sparse_sumcheck_proof.point_and_eval.0.clone();

        let claim = EqBatchedEvalClaim {
            point: new_eval_point,
            evaluations: vec![proof.evaluation_claims.clone().into()],
        };
        self.multilinear_verifier
            .verify_untrusted_evaluations(&[commitment], &claim, &proof.pcs_proof, challenger)
            .map_err(VerifierError::PCSError)
    }
}
