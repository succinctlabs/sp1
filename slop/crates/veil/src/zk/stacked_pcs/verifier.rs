use crate::zk::inner::{
    ConstraintContextInnerExt, PcsEvalClaim, VerifierValue, ZkCnstrAndReadingCtxInner, ZkIopCtx,
    ZkPcsVerificationError, ZkPcsVerifier, ZkProtocolProof, ZkVerificationContext,
};
use derive_where::derive_where;
use itertools::Itertools;
use slop_algebra::{AbstractExtensionField, AbstractField, TwoAdicField};
use slop_basefold::BaseFoldVerifierError;
use slop_challenger::{FieldChallenger, IopCtx};
use slop_merkle_tree::MerkleTreeTcsError;
use slop_multilinear::{partial_lagrange_blocking, Point};
use slop_utils::reverse_bits_len;
use thiserror::Error;

use super::basefold_verifier_wrapper::ZkStackedPcsVerifier;
use super::ZkStackedPcsProof;

/// Type alias for `VerifierValue` when using the ZK stacked PCS.
///
/// This is the expression index type that should be used by downstream code
/// (e.g., zk-sumcheck) when working with the ZK stacked PCS verification context.
pub type StackedPcsVerifierValue<GC> = VerifierValue<GC, ZkStackedPcsProof<GC>>;

/// Type alias for `ZkVerificationContext` when using the ZK stacked PCS.
///
/// This is the verification context type that should be used by downstream code
/// (e.g., zk-sumcheck) when working with the ZK stacked PCS.
pub type StackedPcsZkVerificationContext<GC> = ZkVerificationContext<GC, ZkStackedPcsProof<GC>>;

#[derive(Debug, Error)]
pub enum ZkStackedVerifierError {
    #[error("Merkle Opening Error")]
    MerkleError(MerkleTreeTcsError),
    #[error("PCS error: {0}")]
    PcsError(BaseFoldVerifierError<MerkleTreeTcsError>),
    #[error("Inconsistent RLC commitment")]
    RLCCommitmentInconsistency,
    #[error("Proof has incorrect shape")]
    IncorrectShape(String),
}

impl<GC: ZkIopCtx> ZkStackedPcsVerifier<GC>
where
    GC::F: TwoAdicField,
{
    /// Verifies a ZK stacked PCS proof for a single evaluation claim.
    ///
    /// Returns the constraint data on success.
    /// The caller is responsible for adding constraints to the context.
    ///
    /// Beware: this verification loses a few bits of security compared to the base PCS.
    /// See the writeup for exact guarantees.
    pub fn verify_zk_stacked_pcs<C: ZkCnstrAndReadingCtxInner<GC>>(
        &self,
        commitment: &GC::Digest,
        point: &Point<GC::EF>,
        claim_expr: &C::Expr,
        proof: ZkStackedPcsProof<GC>,
        context: &mut C,
    ) -> Result<ZkStackedPcsConstraintData<GC, C>, ZkStackedVerifierError> {
        let ZkStackedPcsProof { rlc_eval_proof, rlc_eval_claim, rlc_padding_vec, log_num_polys } =
            proof;

        let verifier = &self.inner.basefold_verifier;
        let num_vars = self.inner.log_stacking_height as usize;
        let num_polys = (1 << log_num_polys) + GC::EF::D; // +deg(EF/F) for mask

        // Shape check: point must have the right dimension
        if log_num_polys + num_vars != point.dimension() {
            return Err(ZkStackedVerifierError::IncorrectShape("Inconsistent dimensions".into()));
        }

        // Enough padding for the needed query count
        let query_count = verifier.fri_config.num_queries;
        if query_count > rlc_padding_vec.len() {
            return Err(ZkStackedVerifierError::IncorrectShape(
                "Not enough padding for RLC eval".into(),
            ));
        }

        // Step 1: Read evals from context
        let Some(evals) = context.read_next(num_polys) else {
            return Err(ZkStackedVerifierError::IncorrectShape("Failed to get evals".into()));
        };

        // Step 2: Sample RLC point (dimension = log_num_polys) and RLC coefficient
        let rlc_point = {
            let mut challenger = context.challenger();
            let coords: Vec<GC::EF> =
                (0..log_num_polys).map(|_| challenger.sample_ext_element()).collect();
            Point::new(coords.into())
        };
        // Step 3: Observe RLC padding and eval claim
        context.challenger().observe_ext_element_slice(&rlc_padding_vec);
        context.challenger().observe_ext_element(rlc_eval_claim);

        // Compute expected RLC evals from the proof's query openings
        let eq_evals = partial_lagrange_blocking(&rlc_point).into_buffer().into_vec();
        let num_original = 1 << log_num_polys;
        let expected_rlc_eval: Vec<GC::EF> = rlc_eval_proof
            .component_polynomials_query_openings_and_proofs[0]
            .values
            .split()
            .map(|row| {
                let row = row.as_slice();
                let eq_sum: GC::EF = eq_evals
                    .iter()
                    .zip_eq(row[..num_original].iter())
                    .map(|(eq_val, &mle_val)| *eq_val * GC::EF::from(mle_val))
                    .sum();
                eq_sum + GC::EF::from_base_slice(&row[num_original..])
            })
            .collect();

        // Step 4: Define how to compute virtual oracle queries and verify MLE eval
        let (eval_point, _) = point.split_at(point.dimension() - log_num_polys);
        let point_dim = eval_point.dimension();
        let compute_batch_evals = |query_indices: &[usize], log_tensor_height: usize| {
            let root = GC::EF::two_adic_generator(log_tensor_height);
            let corrections = query_indices.iter().map(|&i| {
                let x = root.exp_u64(reverse_bits_len(i, log_tensor_height) as u64);
                let padding_eval = rlc_padding_vec
                    .iter()
                    .rev()
                    .fold(GC::EF::zero(), |acc, &coeff| acc * x + coeff);
                let x_to_unpadded_size = x.exp_u64(1 << point_dim);
                padding_eval * x_to_unpadded_size
            });
            expected_rlc_eval
                .into_iter()
                .zip(corrections)
                .map(|(eval, correction)| eval - correction)
                .collect()
        };

        if let Err(e) = self.verify_trusted_ext_mle_evaluation(
            commitment,
            eval_point,
            rlc_eval_claim,
            &rlc_eval_proof,
            compute_batch_evals,
            &mut context.challenger(),
        ) {
            return Err(ZkStackedVerifierError::PcsError(e));
        }

        // Build constraint data
        let claim_data = ZkStackedPcsClaimData {
            point: point.clone(),
            orig_eval_index: claim_expr.clone(),
            rlc_eval_claim,
            evals,
        };

        let constraint_data = ZkStackedPcsConstraintData {
            log_num_cols: log_num_polys,
            rlc_point,
            claim: claim_data,
        };

        Ok(constraint_data)
    }
}

/// Per-claim constraint data for a single evaluation claim within a batched proof.
#[derive(Clone)]
#[derive_where(Debug; C::Expr)]
pub struct ZkStackedPcsClaimData<GC: IopCtx, C: ConstraintContextInnerExt<GC::EF>> {
    /// Evaluation point for this claim
    pub point: Point<GC::EF>,
    /// Transcript element of the original evaluation claim
    pub orig_eval_index: C::Expr,
    /// RLC evaluation claim (a_q in the protocol)
    pub rlc_eval_claim: GC::EF,
    /// Transcript elements of the sub-polynomial evaluations (y_{q,ℓ})
    pub evals: Vec<C::Expr>,
}

/// Self-contained constraint data for a ZK stacked PCS evaluation proof.
///
/// This struct contains all the data needed to generate linear constraints
/// for the stacked PCS protocol without additional inputs.
/// Generic over the context type `C` which can be `ZkVerificationContext` or `ZkProverContext`.
#[derive(Clone)]
#[derive_where(Debug; C::Expr)]
pub struct ZkStackedPcsConstraintData<GC: IopCtx, C: ConstraintContextInnerExt<GC::EF>> {
    /// Log of the number of columns (polynomials) in the stacking
    pub log_num_cols: usize,
    /// RLC point for eq-based linear combination (dimension = log_num_cols)
    pub rlc_point: Point<GC::EF>,
    /// Constraint data for the single evaluation claim
    pub claim: ZkStackedPcsClaimData<GC, C>,
}

impl<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>> ZkProtocolProof<GC, C>
    for ZkStackedPcsConstraintData<GC, C>
{
    fn build_constraints(self) {
        let mut context = self.claim.evals[0].as_ref().clone();

        let num_original = 1 << self.log_num_cols;

        // RLC constraint: mle_eval(rlc_point, evals[0..2^p]) + evals[mask] == a_q
        // Note that mask is represented as its base field components
        let mask_sum = (0..GC::EF::D)
            .map(|i| self.claim.evals[num_original + i].clone() * GC::EF::monomial(i))
            .reduce(|acc, term| acc + term)
            .unwrap();
        let stacked_challenge_constraint =
            C::mle_eval(self.rlc_point.clone(), &self.claim.evals[0..num_original]) + mask_sum
                - self.claim.rlc_eval_claim;
        context.assert_zero(stacked_challenge_constraint);

        // MLE decomposition: mle_eval(stack_point, evals[0..2^p]) == y_q
        let (_, stack_point) =
            self.claim.point.split_at(self.claim.point.dimension() - self.log_num_cols);
        let mle_decomp_constraint = C::mle_eval(stack_point, &self.claim.evals[0..num_original])
            - self.claim.orig_eval_index.clone();
        context.assert_zero(mle_decomp_constraint);
    }
}

// ============================================================================
// ZkPcsVerifier trait implementation
// ============================================================================

impl<GC: ZkIopCtx> ZkPcsVerifier<GC> for ZkStackedPcsVerifier<GC>
where
    GC::F: TwoAdicField,
{
    type Proof = super::ZkStackedPcsProof<GC>;

    fn verify_eval(
        &self,
        ctx: &mut ZkVerificationContext<GC, Self::Proof>,
        claim: PcsEvalClaim<GC::EF, VerifierValue<GC, Self::Proof>>,
        proof: &Self::Proof,
    ) -> Result<(), ZkPcsVerificationError> {
        let commitment_index = claim.commitment_index;

        // Look up the commitment entry from context using the commitment index
        let commitment_entry = ctx.get_commitment_entry(commitment_index).ok_or_else(|| {
            ZkPcsVerificationError::VerificationFailed(format!(
                "invalid commitment index: {}",
                commitment_index.index()
            ))
        })?;

        // Verify the stacked PCS proof and get constraint data
        let constraint_data = self
            .verify_zk_stacked_pcs(
                &commitment_entry.digest,
                &claim.point,
                &claim.eval_expr,
                proof.clone(),
                ctx,
            )
            .map_err(|e| ZkPcsVerificationError::VerificationFailed(e.to_string()))?;

        // Build constraints from the constraint data
        constraint_data.build_constraints();

        Ok(())
    }
}
