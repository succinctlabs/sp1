use crate::zk::inner::{
    ConstraintContextInnerExt, MleCommitmentIndex, VerifierValue, ZkCnstrAndReadingCtxInner,
    ZkIopCtx, ZkPcsVerificationError, ZkPcsVerifier, ZkVerificationContext,
};
use derive_where::derive_where;
use slop_algebra::{AbstractExtensionField, AbstractField, TwoAdicField};
use slop_challenger::{FieldChallenger, IopCtx};
use slop_commit::Rounds;
use slop_multilinear::{partial_lagrange_blocking, BatchPcsVerifier, Point};
use slop_stacked::stacking_combine;
use slop_utils::reverse_bits_len;
use std::marker::PhantomData;
use thiserror::Error;

use super::padding::VEIL_EXTRA_QUERIES;
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
    #[error("PCS error: {0}")]
    PcsError(String),
    #[error("Inconsistent RLC commitment")]
    RLCCommitmentInconsistency,
    #[error("Proof has incorrect shape")]
    IncorrectShape(String),
}

/// The verifier for the ZK stacked PCS: a thin wrapper around the base [`BatchPcsVerifier`] that
/// checks the batched evaluation proof.
///
/// This is the verifier-side analogue of the [`super::prover`] ZK commit/prove logic. The base PCS supplies
/// everything the ZK protocol needs (the opening check, the stacking height, the query count and
/// the blowup), so the wrapper carries no state of its own; its [`ZkPcsVerifier`] impl below is
/// the external API.
#[derive(Clone, Debug)]
pub struct ZkStackedVerifier<GC: ZkIopCtx, V: BatchPcsVerifier<GC>> {
    /// The base PCS verifier that checks the batched evaluation proof.
    pub base_verifier: V,
    _marker: PhantomData<GC>,
}

impl<GC: ZkIopCtx, V: BatchPcsVerifier<GC>> ZkStackedVerifier<GC, V> {
    /// Wraps a base PCS verifier into a ZK stacked PCS verifier.
    pub const fn new(base_verifier: V) -> Self {
        Self { base_verifier, _marker: PhantomData }
    }

    /// The query count of the ZK protocol: the base PCS's query count plus the
    /// [`VEIL_EXTRA_QUERIES`] rate-correction margin (the ZK padding slightly raises the
    /// committed code's rate — see [`super::padding`]). This is the number of hiding/padding rows
    /// the prover commits per polynomial, and every veil-side use of the base PCS query count
    /// goes through it. Mirrors the prover-side `num_zk_queries` in [`super::prover`].
    pub fn num_zk_queries(&self) -> usize {
        self.base_verifier.num_queries() + VEIL_EXTRA_QUERIES
    }

    /// Verifies a batched ZK stacked PCS opening of `commitments` at the shared `reduced_point`,
    /// where commitment `j` has `column_counts[j]` data columns.
    ///
    /// Commitments may have **different** column counts (`log_num_polys`) — the single union eq
    /// batches them regardless. What they *must* share is `mle_num_vars` (the encoding height):
    /// `reduced_point` is where the base PCS opens every commitment's columns, so it pins the
    /// per-column variable count. Equivalently, the callers' per-claim eval points may differ in
    /// their (variable-length) column-index prefix but must share their last `mle_num_vars` (reduced)
    /// coordinates.
    ///
    /// Returns the constraint data (column sub-evaluations + RLC consistency) on success. The
    /// caller asserts the decomposition and discharges the RLC constraint via the returned data.
    #[allow(clippy::type_complexity)]
    pub fn verify_zk_stacked_pcs_batched<C>(
        &self,
        commitments: &[GC::Digest],
        column_counts: &[usize],
        reduced_point: &Point<GC::EF>,
        proof: ZkStackedPcsProof<GC, V::Proof>,
        context: &mut C,
    ) -> Result<ZkStackedPcsConstraintData<GC, C>, ZkStackedVerifierError>
    where
        C: ZkCnstrAndReadingCtxInner<GC>,
    {
        let num_claims = commitments.len();
        assert!(num_claims > 0, "must have at least one claim");
        assert_eq!(column_counts.len(), num_claims, "one column count per commitment");

        let ZkStackedPcsProof { rlc_eval_proof, rlc_eval_claim, rlc_padding_vec } = proof;

        let num_encoding_variables = self.base_verifier.num_encoding_variables() as usize;

        // Shape check: the reduced point (where the base PCS opens) must have the encoding dimension.
        if reduced_point.dimension() != num_encoding_variables {
            return Err(ZkStackedVerifierError::IncorrectShape("Inconsistent dimensions".into()));
        }

        // Note: the base PCS verifier is responsible for checking that the proof contains exactly one
        // opening per commitment (Basefold does this against `commitments.len()`), so we don't
        // introspect the (now opaque) base proof here.

        // Padding matches expected query count
        let query_count = self.num_zk_queries();
        if rlc_padding_vec.len() != query_count {
            return Err(ZkStackedVerifierError::IncorrectShape("padding length wrong".into()));
        }

        // Step 1: Read evals from context for each commitment (its own `column_counts[j]` data
        // evals; commitment 0 also carries the shared `EF::D` mask evals).
        let mut per_claim_evals = Vec::with_capacity(num_claims);
        for (j, &count) in column_counts.iter().enumerate() {
            let num_to_read = if j == 0 { count + GC::EF::D } else { count };
            let evals = context.read_next(num_to_read).map_err(|_| {
                ZkStackedVerifierError::IncorrectShape("Failed to get evals".into())
            })?;
            per_claim_evals.push(evals);
        }

        // Step 2: Sample the RLC point — a single eq over every data column of every commitment
        // (dimension = log2 of the total data-column count, rounded up to a power of two). No
        // separate α batching challenge.
        let total_data_cols: usize = column_counts.iter().sum();
        let log_total_data_cols = total_data_cols.next_power_of_two().trailing_zeros() as usize;
        let rlc_point = context.with_challenger(|challenger| {
            let coords: Vec<GC::EF> =
                (0..log_total_data_cols).map(|_| challenger.sample_ext_element()).collect();
            Point::new(coords.into())
        });

        // Step 3: Observe combined padding and eval claim
        context.with_challenger(|c| {
            c.observe_ext_element_slice(&rlc_padding_vec);
            c.observe_ext_element(rlc_eval_claim);
        });

        let eq_evals = partial_lagrange_blocking(&rlc_point).into_buffer().into_vec();

        // Step 4: Define the virtual oracle. For a single query, this combines the opened values
        // (one round per commitment, in commitment order) into
        //     combined = Σ_c eq(rlc_point, c) * data_leaf_c + mask_0
        // — one eq over all commitments' data columns plus commitment 0's mask (coefficient 1) — and
        // subtracts the RLC padding correction to produce the value of the virtual oracle at the
        // corresponding FRI domain point. The Basefold verifier has already checked the Merkle
        // openings, so the evaluator only ever sees field values.
        let eval_point = reduced_point;
        let point_dim = eval_point.dimension();
        // The committed codewords live on an evaluation domain of size `2^(point_dim + log_blowup)`.
        let log_tensor_height = point_dim + self.base_verifier.log_blowup();
        let root = GC::EF::two_adic_generator(log_tensor_height);
        let to_virtual_oracle = |values: Rounds<&[GC::F]>, query_idx: usize| -> GC::EF {
            // Commitment `j` is committed with `column_counts[j]` data columns (and, for commitment
            // 0, an extra `EF::D` mask block). `values[j]` is its opened row for this query, in
            // commitment order; `global_col` walks the single eq weight vector across all rows.
            let mut combined = GC::EF::zero();
            let mut global_col = 0;
            for (j, (row, &count)) in values.iter().zip(column_counts).enumerate() {
                let weights = &eq_evals[global_col..global_col + count];
                combined += stacking_combine::<GC::F, GC::EF>(weights, &row[..count]);
                // Only include the mask from commitment 0 (coefficient 1); it follows its data cols.
                if j == 0 {
                    combined += GC::EF::from_base_slice(&row[count..]);
                }
                global_col += count;
            }

            let x = root.exp_u64(reverse_bits_len(query_idx, log_tensor_height) as u64);
            let padding_eval =
                rlc_padding_vec.iter().rev().fold(GC::EF::zero(), |acc, &coeff| acc * x + coeff);
            let correction = padding_eval * x.exp_u64(1 << point_dim);

            combined - correction
        };

        // Step 5: Verify the base-PCS evaluation proof over all commitments
        let pcs_result = context.with_challenger(|challenger| {
            self.base_verifier.verify(
                commitments,
                eval_point,
                rlc_eval_claim,
                to_virtual_oracle,
                &rlc_eval_proof,
                challenger,
            )
        });
        if let Err(e) = pcs_result {
            return Err(ZkStackedVerifierError::PcsError(e.to_string()));
        }

        // Build constraint data: the per-commitment column sub-evaluations + RLC consistency data.
        let constraint_data = ZkStackedPcsConstraintData {
            column_counts: column_counts.to_vec(),
            rlc_point,
            combined_rlc_eval_claim: rlc_eval_claim,
            claims: Rounds { rounds: per_claim_evals },
        };

        Ok(constraint_data)
    }
}

/// Self-contained constraint data for a ZK stacked PCS evaluation proof.
///
/// Holds the per-commitment column sub-evaluations (`claims`) and the data needed to assert the
/// RLC-consistency constraint. The *decomposition* (`orig_eval == combiner(column_evals)`) is
/// asserted by the caller at its own expression level, using [`Self::data_column_evals`].
/// Generic over the context type `C` which can be `ZkVerificationContext` or `ZkProverContext`.
#[derive(Clone)]
#[derive_where(Debug; C::Expr)]
pub struct ZkStackedPcsConstraintData<GC: IopCtx, C: ConstraintContextInnerExt<GC::EF>> {
    /// Per-commitment data-column counts (commitment-major). Commitments may differ in column count.
    pub column_counts: Vec<usize>,
    /// The single RLC point: one eq over *all* data columns of *all* commitments (dimension = log2
    /// of the total data-column count, rounded up to a power of two).
    pub rlc_point: Point<GC::EF>,
    /// Combined RLC evaluation claim: `Σ_c eq(rlc_point, c) * data_eval_c + mask_eval_0`, where `c`
    /// runs over every commitment's data columns and the mask is added with coefficient 1.
    pub combined_rlc_eval_claim: GC::EF,
    /// Per-commitment column sub-evaluations (`y_{q,ℓ}`), one [`Rounds`] entry per commitment: data
    /// columns, followed by the `EF::D` mask columns for commitment 0 only.
    pub claims: Rounds<Vec<C::Expr>>,
}

impl<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>> ZkStackedPcsConstraintData<GC, C> {
    /// The per-commitment **data** column sub-evaluations (excluding the mask columns), one
    /// [`Rounds`] entry per commitment. These are what the caller feeds to the decomposition
    /// combiner.
    pub fn data_column_evals(&self) -> Rounds<Vec<C::Expr>> {
        self.claims
            .iter()
            .zip(&self.column_counts)
            .map(|(evals, &count)| evals[0..count].to_vec())
            .collect()
    }
}

impl<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>> ZkStackedPcsConstraintData<GC, C> {
    /// Builds and asserts the linear constraints decomposing each commitment's claimed evaluation
    /// into its column sub-evaluations. Consumes `self` to drop the stored context references.
    pub fn build_constraints(self) {
        let mut context = self.claims[0][0].as_ref().clone();

        // RLC consistency constraint, mirroring the prover's combined eval claim:
        //   Σ_c eq(rlc_point, c) * data_eval_c + mask_sum_0 == combined_rlc_eval_claim
        // a single eq over every commitment's data column evals (commitment-major, per-commitment
        // counts), plus commitment 0's mask (coefficient 1, recombined via the monomial EF-over-F
        // basis after that commitment's data evals).
        let weights = partial_lagrange_blocking(&self.rlc_point).into_buffer().into_vec();
        let data_term = self
            .claims
            .iter()
            .zip(&self.column_counts)
            .flat_map(|(evals, &count)| evals[0..count].iter().cloned())
            .zip(weights.iter())
            .map(|(eval, &w)| eval * w)
            .reduce(|acc, term| acc + term)
            .expect("at least one data column");
        let count_0 = self.column_counts[0];
        let mask_sum_0 = (0..GC::EF::D)
            .map(|i| self.claims[0][count_0 + i].clone() * GC::EF::monomial(i))
            .reduce(|acc, term| acc + term)
            .unwrap();
        context.assert_zero(data_term + mask_sum_0 - self.combined_rlc_eval_claim);
    }
}

// ============================================================================
// External API: ZkPcsVerifier, generic over the base PCS verifier
// ============================================================================

impl<GC, V> ZkPcsVerifier<GC> for ZkStackedVerifier<GC, V>
where
    GC: ZkIopCtx,
    V: BatchPcsVerifier<GC>,
    <V as BatchPcsVerifier<GC>>::Proof: Clone,
{
    type Proof = ZkStackedPcsProof<GC, <V as BatchPcsVerifier<GC>>::Proof>;

    fn num_encoding_variables(&self) -> u32 {
        self.base_verifier.num_encoding_variables()
    }

    #[allow(clippy::type_complexity)]
    fn verify_multi_eval(
        &self,
        ctx: &mut ZkVerificationContext<GC, Self::Proof>,
        commitment_indices: Rounds<MleCommitmentIndex>,
        reduced_point: &Point<GC::EF>,
        proof: &Self::Proof,
    ) -> Result<Rounds<Vec<VerifierValue<GC, Self::Proof>>>, ZkPcsVerificationError> {
        // Collect each commitment's digest and data-column count (`2^log_num_polys`) from its
        // registered entry — the counts may differ across commitments.
        let (commitments, column_counts): (Vec<GC::Digest>, Vec<usize>) = commitment_indices
            .into_iter()
            .map(|idx| {
                ctx.get_commitment_entry(idx)
                    .map(|entry| (entry.digest, 1usize << entry.log_num_polys))
                    .ok_or_else(|| {
                        ZkPcsVerificationError::VerificationFailed(format!(
                            "invalid commitment index: {}",
                            idx.index()
                        ))
                    })
            })
            .collect::<Result<Vec<_>, ZkPcsVerificationError>>()?
            .into_iter()
            .unzip();

        // Verify the batched stacked PCS proof, delegating the evaluation-proof check to the
        // base PCS through the `BatchPcsVerifier` trait.
        let constraint_data = self
            .verify_zk_stacked_pcs_batched(
                &commitments,
                &column_counts,
                reduced_point,
                proof.clone(),
                ctx,
            )
            .map_err(|e| ZkPcsVerificationError::VerificationFailed(e.to_string()))?;

        // The per-commitment data-column sub-evaluations the caller combines into the original eval.
        let columns = constraint_data.data_column_evals();
        // Discharge only the RLC-consistency constraint here.
        constraint_data.build_constraints();

        Ok(columns)
    }
}
