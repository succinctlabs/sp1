use crate::zk::inner::{
    ConstraintContextInnerExt, PcsMultiEvalClaim, VerifierValue, ZkCnstrAndReadingCtxInner,
    ZkIopCtx, ZkPcsVerificationError, ZkPcsVerifier, ZkProtocolProof, ZkVerificationContext,
};
use derive_where::derive_where;
use itertools::Itertools;
use rayon::prelude::*;
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
pub type StackedPcsVerifierValue<GC> = VerifierValue<GC>;

/// Type alias for `ZkVerificationContext` when using the ZK stacked PCS.
///
/// This is the verification context type that should be used by downstream code
/// (e.g., zk-sumcheck) when working with the ZK stacked PCS.
pub type StackedPcsZkVerificationContext<GC> = ZkVerificationContext<GC>;

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
    /// Thin wrapper around [`verify_zk_stacked_pcs_batched`] for the single-commitment case.
    pub fn verify_zk_stacked_pcs<C: ZkCnstrAndReadingCtxInner<GC>>(
        &self,
        commitment: &GC::Digest,
        point: &Point<GC::EF>,
        claim_expr: &C::Expr,
        proof: ZkStackedPcsProof<GC>,
        context: &mut C,
    ) -> Result<ZkStackedPcsConstraintData<GC, C>, ZkStackedVerifierError> {
        self.verify_zk_stacked_pcs_batched(
            &[(*commitment, claim_expr.clone())],
            point,
            proof,
            context,
        )
    }

    /// Verifies a batched ZK stacked PCS proof for multiple evaluation claims at the same point.
    ///
    /// Each entry in `commitments_and_claims` is a `(commitment, claim_expr)` pair.
    /// All commitments must share the same `log_num_polys` and `mle_num_vars`.
    ///
    /// Returns the constraint data on success.
    /// The caller is responsible for adding constraints to the context.
    pub fn verify_zk_stacked_pcs_batched<C: ZkCnstrAndReadingCtxInner<GC>>(
        &self,
        commitments_and_claims: &[(GC::Digest, C::Expr)],
        point: &Point<GC::EF>,
        proof: ZkStackedPcsProof<GC>,
        context: &mut C,
    ) -> Result<ZkStackedPcsConstraintData<GC, C>, ZkStackedVerifierError> {
        let num_claims = commitments_and_claims.len();
        assert!(num_claims > 0, "must have at least one claim");

        let ZkStackedPcsProof {
            rlc_eval_proof,
            rlc_eval_claim,
            rlc_padding_vec,
            log_num_data_cols,
        } = proof;

        let verifier = &self.inner.basefold_verifier;
        let num_encoding_variables = self.inner.log_stacking_height as usize;
        let num_polys = (1 << log_num_data_cols) + GC::EF::D; // +deg(EF/F) for mask

        // Shape check: point must have the right dimension
        if log_num_data_cols + num_encoding_variables != point.dimension() {
            return Err(ZkStackedVerifierError::IncorrectShape("Inconsistent dimensions".into()));
        }

        // Shape check: one opening per commitment in the proof
        if rlc_eval_proof.component_polynomials_query_openings_and_proofs.len() != num_claims {
            return Err(ZkStackedVerifierError::IncorrectShape(
                "Number of openings doesn't match number of commitments".into(),
            ));
        }

        // Padding matches expected query count
        let query_count = verifier.fri_config.num_queries;
        if rlc_padding_vec.len() != query_count {
            return Err(ZkStackedVerifierError::IncorrectShape("padding length wrong".into()));
        }

        // Step 1: Read evals from context for each commitment.
        // Only commitment 0 includes mask column evaluations;
        // the others only have data column evaluations.
        let mut per_claim_evals = Vec::with_capacity(num_claims);
        for j in 0..num_claims {
            let num_to_read = if j == 0 { num_polys } else { 1 << log_num_data_cols };
            let evals = context.read_next(num_to_read).map_err(|_| {
                ZkStackedVerifierError::IncorrectShape("Failed to get evals".into())
            })?;
            per_claim_evals.push(evals);
        }

        // Step 2: Sample shared RLC point (dimension = log_num_data_cols)
        let rlc_point = {
            let mut challenger = context.challenger();
            let coords: Vec<GC::EF> =
                (0..log_num_data_cols).map(|_| challenger.sample_ext_element()).collect();
            Point::new(coords.into())
        };

        // Step 3: Sample batching challenge α
        let batching_challenge: GC::EF = {
            let mut challenger = context.challenger();
            challenger.sample_ext_element()
        };

        // Step 4: Observe combined padding and eval claim
        context.challenger().observe_ext_element_slice(&rlc_padding_vec);
        context.challenger().observe_ext_element(rlc_eval_claim);

        // Precompute α powers and eq evals
        let alpha_powers: Vec<GC::EF> = batching_challenge.powers().take(num_claims + 1).collect();

        let eq_evals = partial_lagrange_blocking(&rlc_point).into_buffer().into_vec();
        let num_original = 1 << log_num_data_cols;

        // Step 5: Compute expected combined evals from all commitments' query openings
        // For each query index q:
        //   combined_eval[q] = Σ_j α^j * data_rlc_j[q] + α^k * mask_0[q]
        let num_queries =
            rlc_eval_proof.component_polynomials_query_openings_and_proofs[0].values.sizes()[0];
        let expected_combined_eval: Vec<GC::EF> = (0..num_queries)
            .into_par_iter()
            .map(|q| {
                let mut combined = GC::EF::zero();
                for (j, opening_and_proof) in rlc_eval_proof
                    .component_polynomials_query_openings_and_proofs
                    .iter()
                    .enumerate()
                {
                    let opening_tensor = &opening_and_proof.values;
                    let row_width = opening_tensor.sizes()[1];
                    let row = &opening_tensor.as_slice()[q * row_width..(q + 1) * row_width];

                    let eq_sum: GC::EF = eq_evals
                        .iter()
                        .zip_eq(row[..num_original].iter())
                        .map(|(eq_val, &mle_val)| *eq_val * GC::EF::from(mle_val))
                        .sum();
                    combined += alpha_powers[j] * eq_sum;

                    // Only include the mask from commitment 0
                    if j == 0 {
                        combined += alpha_powers[num_claims]
                            * GC::EF::from_base_slice(&row[num_original..]);
                    }
                }
                combined
            })
            .collect();

        // Step 6: Define virtual oracle with combined padding correction
        let (eval_point, _) = point.split_at(point.dimension() - log_num_data_cols);
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
            expected_combined_eval
                .into_iter()
                .zip(corrections)
                .map(|(eval, correction)| eval - correction)
                .collect()
        };

        // Step 7: Verify basefold proof with all commitments
        let commitments: Vec<GC::Digest> = commitments_and_claims.iter().map(|(c, _)| *c).collect();
        if let Err(e) = self.verify_trusted_ext_mle_evaluation(
            &commitments,
            eval_point,
            rlc_eval_claim,
            &rlc_eval_proof,
            compute_batch_evals,
            &mut context.challenger(),
        ) {
            return Err(ZkStackedVerifierError::PcsError(e));
        }

        // Build constraint data
        let claim_datas: Vec<_> = commitments_and_claims
            .iter()
            .zip(per_claim_evals)
            .map(|((_, claim_expr), evals)| ZkStackedPcsClaimData {
                point: point.clone(),
                orig_eval_index: claim_expr.clone(),
                evals,
            })
            .collect();

        let constraint_data = ZkStackedPcsConstraintData {
            log_num_cols: log_num_data_cols,
            rlc_point,
            batching_challenge,
            combined_rlc_eval_claim: rlc_eval_claim,
            claims: claim_datas,
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
    /// Batching challenge α used to combine multiple claims
    pub batching_challenge: GC::EF,
    /// Combined RLC evaluation claim: Σ_j α^j * data_rlc_eval_j + Σ_j α^{k+j} * mask_eval_j
    pub combined_rlc_eval_claim: GC::EF,
    /// Per-commitment claim data
    pub claims: Vec<ZkStackedPcsClaimData<GC, C>>,
}

impl<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>> ZkProtocolProof<GC, C>
    for ZkStackedPcsConstraintData<GC, C>
{
    fn build_constraints(self) {
        let mut context = self.claims[0].evals[0].as_ref().clone();

        let num_original = 1 << self.log_num_cols;
        let num_claims = self.claims.len();

        let alpha_powers: Vec<GC::EF> =
            self.batching_challenge.powers().take(num_claims + 1).collect();

        // Combined RLC constraint:
        // Σ_j α^j * mle_eval(rlc_point, evals_j[0..2^p])
        //   + α^k * mask_sum_0 == combined_rlc_eval_claim
        //
        // Build data RLC terms and the single mask term.
        let mut terms: Vec<(GC::EF, C::Expr)> = Vec::with_capacity(num_claims + 1);
        for (j, claim) in self.claims.iter().enumerate() {
            terms.push((
                alpha_powers[j],
                C::mle_eval(self.rlc_point.clone(), &claim.evals[0..num_original]),
            ));
        }
        // Single mask from commitment 0
        let mask_sum_0 = (0..GC::EF::D)
            .map(|i| self.claims[0].evals[num_original + i].clone() * GC::EF::monomial(i))
            .reduce(|acc, term| acc + term)
            .unwrap();
        terms.push((alpha_powers[num_claims], mask_sum_0));

        let mut iter = terms.into_iter();
        let (first_alpha, first_term) = iter.next().unwrap();
        let combined_expr =
            iter.fold(first_term * first_alpha, |acc, (alpha, term)| acc + term * alpha);
        context.assert_zero(combined_expr - self.combined_rlc_eval_claim);

        // Per-claim MLE decomposition: mle_eval(stack_point, evals[0..2^p]) == y_q
        for claim in &self.claims {
            let (_, stack_point) =
                claim.point.split_at(claim.point.dimension() - self.log_num_cols);
            let mle_decomp_constraint = C::mle_eval(stack_point, &claim.evals[0..num_original])
                - claim.orig_eval_index.clone();
            context.assert_zero(mle_decomp_constraint);
        }
    }
}

// ============================================================================
// ZkPcsVerifier trait implementation
// ============================================================================

impl<GC: ZkIopCtx<PcsProof = ZkStackedPcsProof<GC>>> ZkPcsVerifier<GC> for ZkStackedPcsVerifier<GC>
where
    GC::F: TwoAdicField,
{
    type Proof = ZkStackedPcsProof<GC>;

    fn verify_multi_eval(
        &self,
        ctx: &mut ZkVerificationContext<GC>,
        claim: PcsMultiEvalClaim<GC::EF, VerifierValue<GC>>,
        proof: &Self::Proof,
    ) -> Result<(), ZkPcsVerificationError> {
        // Collect commitment digests and claim expressions
        let commitments_and_claims: Vec<_> = claim
            .commitment_indices
            .iter()
            .zip(claim.eval_exprs.iter())
            .map(|(idx, eval_expr)| {
                let entry = ctx.get_commitment_entry(*idx).ok_or_else(|| {
                    ZkPcsVerificationError::VerificationFailed(format!(
                        "invalid commitment index: {}",
                        idx.index()
                    ))
                })?;
                Ok((entry.digest, eval_expr.clone()))
            })
            .collect::<Result<Vec<_>, ZkPcsVerificationError>>()?;

        // Verify the batched stacked PCS proof
        let constraint_data = self
            .verify_zk_stacked_pcs_batched(
                &commitments_and_claims,
                &claim.point,
                proof.clone(),
                ctx,
            )
            .map_err(|e| ZkPcsVerificationError::VerificationFailed(e.to_string()))?;

        // Build constraints from the constraint data
        constraint_data.build_constraints();

        Ok(())
    }
}
