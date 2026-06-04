// ZK Stacked PCS Prover implementation
use crate::zk::inner::{
    MerkleProverData, PcsMultiEvalClaim, ProverValue, ZkIopCtx, ZkMerkleizer, ZkPcsCommitmentError,
    ZkPcsProver, ZkProverContext,
};
use derive_where::derive_where;
use itertools::Itertools;
use rand::distributions::{Distribution, Standard};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField};
use slop_alloc::CpuBackend;
use slop_basefold::BasefoldProof;
use slop_basefold_prover::{BaseFoldConfigProverError, BasefoldProverData};
use slop_challenger::FieldChallenger;
use slop_commit::Message;
use slop_matrix::dense::RowMajorMatrix;
use slop_multilinear::{Mle, Point};
use slop_tensor::Tensor;
use std::{fmt::Debug, iter::repeat_with, marker::PhantomData, sync::Arc};
use thiserror::Error;

use rayon::prelude::*;

use super::{basefold_prover_wrapper::ZkBasefoldProver, ZkStackedPcsConstraintData};
use crate::zk::prover_ctx::{PcsProverConfig, ZkProverCtx};

/// Type alias for `ProverValue` when using the ZK PCS (stacked PCS).
///
/// This is the expression index type that should be used by downstream code
/// (e.g., zk-sumcheck) when working with the ZK PCS prover context.
#[allow(type_alias_bounds)]
pub type StackedPcsProverValue<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> =
    ProverValue<GC, MK, ZkStackedPcsProverData<GC, MK>>;

/// Type alias for `ZkProverContext` when using the ZK PCS (stacked PCS).
///
/// This is the prover context type that should be used by downstream code
/// (e.g., zk-sumcheck) when working with the ZK PCS.
#[allow(type_alias_bounds)]
pub type StackedPcsZkProverContext<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> =
    ZkProverContext<GC, MK, ZkStackedPcsProverData<GC, MK>>;

/// Configuration type that implements `PcsProverConfig` for the stacked PCS.
pub struct StackedPcsProverConfig<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> {
    _phantom: PhantomData<(GC, MK)>,
}

impl<GC: ZkIopCtx<PcsProof = ZkStackedPcsProof<GC>>, MK: ZkMerkleizer<GC>> PcsProverConfig<GC>
    for StackedPcsProverConfig<GC, MK>
{
    type Merkelizer = MK;
    type PcsProverData = ZkStackedPcsProverData<GC, MK>;
    type PcsProver = ZkBasefoldProver<GC, MK>;
}

/// Type alias for `ZkProverCtx` when using the stacked PCS.
#[allow(type_alias_bounds)]
pub type StackedPcsZkProverCtx<
    GC: ZkIopCtx<PcsProof = ZkStackedPcsProof<GC>>,
    MK: ZkMerkleizer<GC>,
> = ZkProverCtx<GC, StackedPcsProverConfig<GC, MK>>;

impl<GC: ZkIopCtx<PcsProof = ZkStackedPcsProof<GC>>, MK: ZkMerkleizer<GC>>
    ZkProverCtx<GC, StackedPcsProverConfig<GC, MK>>
{
    /// Initializes a prover context with stacked PCS support.
    pub fn initialize_with_pcs<RNG: CryptoRng + Rng>(
        mask_length: usize,
        pcs_prover: ZkBasefoldProver<GC, MK>,
        rng: &mut RNG,
    ) -> Result<Self, crate::zk::ZkProverCtxInitError<GC, StackedPcsProverConfig<GC, MK>>>
    where
        Standard: Distribution<GC::EF>,
    {
        Self::initialize(mask_length, rng, Some(pcs_prover))
    }

    /// Initializes a linear-only prover context with stacked PCS support.
    pub fn initialize_with_pcs_only_lin<RNG: CryptoRng + Rng>(
        mask_length: usize,
        pcs_prover: ZkBasefoldProver<GC, MK>,
        rng: &mut RNG,
    ) -> Result<Self, crate::zk::ZkProverCtxInitError<GC, StackedPcsProverConfig<GC, MK>>>
    where
        Standard: Distribution<GC::EF>,
    {
        Self::initialize_only_lin_constraints(mask_length, rng, Some(pcs_prover))
    }
}

#[derive(Debug)]
#[derive_where(Clone; MerkleProverData<GC, MK>: Clone)]
#[derive_where(Serialize, Deserialize; MerkleProverData<GC, MK>, Tensor<GC::F, CpuBackend>)]
pub struct ZkStackedPcsProverData<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> {
    pub full_pcs_data: BasefoldProverData<GC::F, MerkleProverData<GC, MK>>,
    pub mles: Message<Mle<GC::F, CpuBackend>>,
    pub mle_num_vars: usize,
}

#[derive(Error, Debug)]
pub enum ZkStackedPcsProverError<E> {
    #[error("Basefold prover error: {0}")]
    BasefoldError(E),
    /// `zk_commit_mles` was called with an empty message (nothing to commit).
    #[error("zk_commit_mles requires exactly one MLE")]
    MissingMle,
    /// A batched evaluation proof was requested with no claims.
    #[error("must have at least one claim")]
    NoClaims,
    /// Claims in a batch disagree on their number of variables.
    #[error("all MLEs must have the same number of variables: expected {expected}, got {actual}")]
    MismatchedNumVars { expected: usize, actual: usize },
    /// A claim's data tensor has an unexpected number of columns.
    #[error("data column count mismatch: expected {expected}, got {actual}")]
    DataColumnMismatch { expected: usize, actual: usize },
    /// A claim's mask tensor has an unexpected number of columns.
    #[error("mask column count mismatch: expected {expected}, got {actual}")]
    MaskColumnMismatch { expected: usize, actual: usize },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct ZkStackedPcsProof<GC: ZkIopCtx> {
    /// Basefold proof for the RLC polynomial evaluation
    pub rlc_eval_proof: BasefoldProof<GC>,
    /// RLC evaluation claim (a_q in the protocol)
    pub rlc_eval_claim: GC::EF,
    /// RLC padding vector
    pub rlc_padding_vec: Vec<GC::EF>,
    /// The number of MLEs stacked together without the masks
    pub log_num_data_cols: usize,
}

impl<GC: ZkIopCtx, MK: ZkMerkleizer<GC>> ZkBasefoldProver<GC, MK> {
    /// Takes in a (flat) MLE and commits to it in a zk-way.
    ///
    /// The MLE is passed as a [`Message`] so the caller does not need to clone or relinquish
    /// ownership of its data; the underlying buffer is only read, never consumed. The MLE's
    /// `2^log_num_polynomials * 2^mle_num_vars` entries are interpreted row-major as a matrix
    /// with `2^log_num_polynomials` data columns. The commitment is built from two separate
    /// tensors — the data columns and `EF::D` random mask columns — that are merkleized
    /// *jointly* rather than interleaved into one buffer. Because Reed–Solomon encoding is
    /// per-column and [`commit_tensors`](slop_merkle_tree::TensorCsProver::commit_tensors)
    /// concatenates same-index rows across tensors, this yields the exact same commitment as a
    /// single `[data | mask]` matrix while avoiding the large interleaved allocation.
    ///
    /// The `query_count` rate-padding rows must extend the data polynomial itself, so they are
    /// appended to the data buffer. When the caller hands over a uniquely-owned MLE whose buffer
    /// already has capacity for those rows, this commit performs **no reallocation of the data**.
    #[allow(clippy::type_complexity)]
    pub fn zk_commit_mles<RNG: CryptoRng + Rng>(
        &self,
        mle: Message<Mle<GC::F, CpuBackend>>,
        log_num_polynomials: usize,
        rng: &mut RNG,
    ) -> Result<
        (GC::Digest, ZkStackedPcsProverData<GC, MK>),
        ZkStackedPcsProverError<BaseFoldConfigProverError<GC, MK>>,
    >
    where
        Standard: Distribution<GC::F>,
    {
        let num_data_cols = 1usize << log_num_polynomials;
        let num_mask_cols = GC::EF::D;

        // The single committed MLE. Read its shape before taking ownership of the buffer.
        let data_mle = mle.into_iter().next().ok_or(ZkStackedPcsProverError::MissingMle)?;
        let mle_num_vars = data_mle.num_variables() as usize - log_num_polynomials;
        let num_data_rows = 1usize << mle_num_vars;

        // Get padding amount from FRI config. These extra rows extend every committed
        // polynomial to raise its effective rate.
        let query_count = self.inner.encoder.config().num_queries;
        let num_rows = num_data_rows + query_count;

        // Take ownership of the data buffer. When the MLE is uniquely held this is a move (and
        // appending the padding below reuses any spare capacity); otherwise we fall back to a
        // copy of the shared data.
        let mut data_vec = match Arc::try_unwrap(data_mle) {
            Ok(mle) => mle.into_guts().into_buffer().into_vec(),
            Err(shared) => shared.guts().as_slice().to_vec(),
        };

        // Append `query_count` random padding rows to the data polynomial. This reuses the
        // buffer's spare capacity when present, leaving the door open for a zero-copy commit.
        data_vec.extend(repeat_with(|| rng.gen()).take(query_count * num_data_cols));
        let data_mle = Mle::new(RowMajorMatrix::new(data_vec, num_data_cols).into());

        // The mask is a fresh set of `num_mask_cols` random columns spanning every row (data rows
        // plus padding rows). It lives in its own tensor and is merkleized jointly with the data,
        // so it is never interleaved into the data buffer.
        let mask_vec: Vec<GC::F> =
            repeat_with(|| rng.gen()).take(num_rows * num_mask_cols).collect();
        let mask_mle = Mle::new(RowMajorMatrix::new(mask_vec, num_mask_cols).into());

        // Commit the data and mask tensors jointly (see the doc comment for why this matches a
        // single interleaved commitment).
        let all_mle: Message<_> = Message::from(vec![data_mle, mask_mle]);
        let (commit, full_pcs_data) = self
            .commit_padded_multilinears(all_mle.clone())
            .map_err(ZkStackedPcsProverError::BasefoldError)?;

        let prover_data = ZkStackedPcsProverData { full_pcs_data, mles: all_mle, mle_num_vars };

        Ok((commit, prover_data))
    }

    /// Generate an evaluation proof for a single claim on one committed MLE.
    ///
    /// Thin wrapper around [`Self::zk_generate_eval_proof_for_mles`] for the single-MLE case.
    #[allow(clippy::type_complexity)]
    pub fn zk_generate_eval_proof_for_mle(
        &self,
        prover_data: ZkStackedPcsProverData<GC, MK>,
        eval_point: &Point<GC::EF>,
        eval_claim: &StackedPcsProverValue<GC, MK>,
        zkbuilder: &mut ZkProverContext<GC, MK, ZkStackedPcsProverData<GC, MK>>,
    ) -> Result<
        (
            ZkStackedPcsProof<GC>,
            ZkStackedPcsConstraintData<GC, ZkProverContext<GC, MK, ZkStackedPcsProverData<GC, MK>>>,
        ),
        ZkStackedPcsProverError<BaseFoldConfigProverError<GC, MK>>,
    > {
        self.zk_generate_eval_proof_for_mles(
            vec![(prover_data, eval_claim.clone())],
            eval_point,
            zkbuilder,
        )
    }

    /// Generate a batched evaluation proof for multiple committed MLEs at the same point.
    ///
    /// Each entry in `claims` is a `(prover_data, eval_claim)` pair. All MLEs must have the
    /// same shape (same `log_num_data_cols` and `mle_num_vars`).
    ///
    /// Returns a tuple of:
    /// - `ZkStackedPcsProof`: The proof data to send to verifier
    /// - `ZkStackedPcsConstraintData`: Constraint data which will be recomputed by verifier
    #[allow(clippy::type_complexity)]
    pub fn zk_generate_eval_proof_for_mles(
        &self,
        claims: Vec<(ZkStackedPcsProverData<GC, MK>, StackedPcsProverValue<GC, MK>)>,
        eval_point: &Point<GC::EF>,
        zkbuilder: &mut ZkProverContext<GC, MK, ZkStackedPcsProverData<GC, MK>>,
    ) -> Result<
        (
            ZkStackedPcsProof<GC>,
            ZkStackedPcsConstraintData<GC, ZkProverContext<GC, MK, ZkStackedPcsProverData<GC, MK>>>,
        ),
        ZkStackedPcsProverError<BaseFoldConfigProverError<GC, MK>>,
    > {
        let num_claims = claims.len();

        // Each commitment stores two tensors: `mles[0]` holds the `num_data_cols` data columns
        // and `mles[1]` holds the `EF::D` mask columns. The data column count is a power of 2
        // (set at commit time), so its log is recoverable from the first claim. All other claims
        // must match this shape.
        let first_claim = claims.first().ok_or(ZkStackedPcsProverError::NoClaims)?;
        let mle_num_vars = first_claim.0.mle_num_vars;
        let log_num_data_cols =
            first_claim.0.mles[0].num_polynomials().next_power_of_two().trailing_zeros() as usize;
        let num_data_cols = 1usize << log_num_data_cols;

        let mut full_pcs_datas = Vec::with_capacity(num_claims);
        let mut all_mles = Vec::with_capacity(num_claims);
        let mut eval_claims = Vec::with_capacity(num_claims);

        for (prover_data, eval_claim) in claims {
            let ZkStackedPcsProverData { full_pcs_data, mles, mle_num_vars: this_num_vars } =
                prover_data;
            if this_num_vars != mle_num_vars {
                return Err(ZkStackedPcsProverError::MismatchedNumVars {
                    expected: mle_num_vars,
                    actual: this_num_vars,
                });
            }
            if mles[0].num_polynomials() != num_data_cols {
                return Err(ZkStackedPcsProverError::DataColumnMismatch {
                    expected: num_data_cols,
                    actual: mles[0].num_polynomials(),
                });
            }
            if mles[1].num_polynomials() != GC::EF::D {
                return Err(ZkStackedPcsProverError::MaskColumnMismatch {
                    expected: GC::EF::D,
                    actual: mles[1].num_polynomials(),
                });
            }

            full_pcs_datas.push(full_pcs_data);
            all_mles.push(mles);
            eval_claims.push(eval_claim);
        }

        // Step 1: For each commitment, evaluate all rows at the inner point and add to transcript.
        // Only commitment 0 includes mask column evaluations in the transcript;
        // the others only send data column evaluations (since only one mask is used).
        let (eval_point_inner, _) = eval_point.split_at(eval_point.dimension() - log_num_data_cols);
        let mut per_claim_evals_elts = Vec::with_capacity(num_claims);
        let mut per_claim_evals_slice = Vec::with_capacity(num_claims);
        for (j, mles) in all_mles.iter().enumerate() {
            // Data column evaluations, followed (for commitment 0 only) by the mask column
            // evaluations. Only one mask is used across the batch, so the others omit it.
            let mut evals_slice =
                mles[0].eval_at(&eval_point_inner).into_evaluations().into_buffer().into_vec();
            if j == 0 {
                let mask_evals =
                    mles[1].eval_at(&eval_point_inner).into_evaluations().into_buffer().into_vec();
                evals_slice.extend(mask_evals);
            }
            let num_to_send = if j == 0 { num_data_cols + GC::EF::D } else { num_data_cols };
            let evals_elts = zkbuilder.add_values(&evals_slice[..num_to_send]);
            per_claim_evals_elts.push(evals_elts);
            per_claim_evals_slice.push(evals_slice);
        }

        // Step 2: Sample shared RLC point (dimension = log_num_data_cols)
        let rlc_point = zkbuilder.with_challenger(|challenger| {
            let coords: Vec<GC::EF> =
                (0..log_num_data_cols).map(|_| challenger.sample_ext_element()).collect();
            Point::new(coords.into())
        });

        // Step 3: Sample batching challenge α
        let batching_challenge: GC::EF = zkbuilder.with_challenger(|c| c.sample_ext_element());

        // Step 4: Compute per-commitment data RLC, then combine with powers of α
        //
        // For each commitment j:
        //   data_rlc_j[row] = Σ_i eq(rlc_point, i) * data_col_j_i[row]
        //
        // combined[row] = Σ_j α^j * data_rlc_j[row] + α^k * mask_0[row]
        //
        // Only one mask is included (from commitment 0) since a single random
        // polynomial suffices for zero-knowledge.
        let eq_evals = Mle::partial_lagrange(&rlc_point);
        let eq_evals_slice = eq_evals.guts().as_buffer().to_vec();

        let alpha_powers: Vec<GC::EF> = batching_challenge.powers().take(num_claims + 1).collect();

        // Total rows = 2^mle_num_vars + query_count (from padding)
        let total_rows = all_mles[0][0].guts().sizes()[0];
        let mut combined_mle_vec: Vec<GC::EF> = vec![GC::EF::zero(); total_rows];

        for (j, mles) in all_mles.iter().enumerate() {
            let data_tensor = mles[0].guts();
            let data_stride = data_tensor.strides()[0];
            let data_alpha = alpha_powers[j];

            // Per-row data RLC: Σ_i eq(rlc_point, i) * data_col_i[row].
            let data_rlc = |data_chunk: &[GC::F]| -> GC::EF {
                let eq_sum: GC::EF = eq_evals_slice
                    .iter()
                    .zip_eq(data_chunk.iter())
                    .map(|(eq, &b)| <GC::EF as core::ops::Mul<GC::F>>::mul(*eq, b))
                    .sum();
                data_alpha * eq_sum
            };

            // Only the mask from the first commitment is folded in (a single random
            // polynomial suffices for zero-knowledge); its columns live in `mles[1]`.
            let per_row: Vec<GC::EF> = if j == 0 {
                let mask_tensor = mles[1].guts();
                let mask_stride = mask_tensor.strides()[0];
                let mask_alpha = alpha_powers[num_claims];
                data_tensor
                    .as_buffer()
                    .par_chunks_exact(data_stride)
                    .zip(mask_tensor.as_buffer().par_chunks_exact(mask_stride))
                    .map(|(data_chunk, mask_chunk)| {
                        data_rlc(data_chunk) + mask_alpha * GC::EF::from_base_slice(mask_chunk)
                    })
                    .collect()
            } else {
                data_tensor.as_buffer().par_chunks_exact(data_stride).map(data_rlc).collect()
            };

            for (dst, src) in combined_mle_vec.iter_mut().zip(per_row.iter()) {
                *dst += *src;
            }
        }

        // Step 5: Split off padding from combined polynomial
        let unpadded_mle_length: usize = 1 << mle_num_vars;
        let rlc_padding_vec = combined_mle_vec.split_off(unpadded_mle_length);

        // Encode the combined polynomial
        let batch_mle_f =
            RowMajorMatrix::new(combined_mle_vec.clone(), 1).flatten_to_base::<GC::F>();
        let batch_mle_f = Tensor::from(batch_mle_f).reshape([1 << mle_num_vars, GC::EF::D]);
        let rlc_codeword =
            self.inner.encoder.encode_batch(Message::from(Mle::new(batch_mle_f))).unwrap();
        let rlc_codeword = (*rlc_codeword[0]).clone();

        // Step 6: Compute combined eval claim
        // combined_eval = Σ_j α^j * data_rlc_eval_j + α^k * mask_eval_0
        let mut rlc_eval_claim = GC::EF::zero();
        for (j, evals_slice) in per_claim_evals_slice.iter().enumerate() {
            let eq_sum: GC::EF = eq_evals_slice
                .iter()
                .zip_eq(evals_slice[..num_data_cols].iter())
                .map(|(eq_val, &eval)| *eq_val * eval)
                .sum();
            rlc_eval_claim += alpha_powers[j] * eq_sum;
        }
        // Add the single mask contribution from commitment 0
        let mask_sum_0: GC::EF = (0..GC::EF::D)
            .map(|i| GC::EF::monomial(i) * per_claim_evals_slice[0][num_data_cols + i])
            .sum();
        rlc_eval_claim += alpha_powers[num_claims] * mask_sum_0;

        // Step 7: Observe combined padding and eval claim
        zkbuilder.with_challenger(|challenger| {
            challenger.observe_ext_element_slice(&rlc_padding_vec[..]);
            challenger.observe_ext_element(rlc_eval_claim);
        });

        // Step 8: Prove basefold evaluation of the combined polynomial
        let rlc_mle_extension = Mle::new(RowMajorMatrix::new(combined_mle_vec, 1).into());
        let rlc_eval_proof = zkbuilder
            .with_challenger(|challenger| {
                self.prove_with_batched_ef_inputs(
                    eval_point_inner,
                    rlc_mle_extension,
                    rlc_codeword,
                    rlc_eval_claim,
                    full_pcs_datas,
                    challenger,
                )
            })
            .map_err(ZkStackedPcsProverError::BasefoldError)?;

        // Build constraint data (shared with verifier)
        let claim_datas: Vec<_> = eval_claims
            .into_iter()
            .zip(per_claim_evals_elts)
            .map(|(eval_claim, evals_elts)| super::ZkStackedPcsClaimData {
                point: eval_point.clone(),
                orig_eval_index: eval_claim,
                evals: evals_elts,
            })
            .collect();

        let constraint_data = ZkStackedPcsConstraintData {
            log_num_cols: log_num_data_cols,
            rlc_point,
            batching_challenge,
            combined_rlc_eval_claim: rlc_eval_claim,
            claims: claim_datas,
        };

        let proof = ZkStackedPcsProof {
            rlc_eval_proof,
            rlc_eval_claim,
            rlc_padding_vec,
            log_num_data_cols,
        };

        Ok((proof, constraint_data))
    }
}

// ============================================================================
// ZkPcsProver trait implementation
// ============================================================================

impl<GC: ZkIopCtx<PcsProof = ZkStackedPcsProof<GC>>, MK: ZkMerkleizer<GC>> ZkPcsProver<GC, MK>
    for ZkBasefoldProver<GC, MK>
{
    type ProverData = ZkStackedPcsProverData<GC, MK>;
    type ProveError = ZkStackedPcsProverError<BaseFoldConfigProverError<GC, MK>>;

    fn num_encoding_variables(&self) -> u32 {
        self.num_encoding_variables
    }

    fn commit_mle<RNG: CryptoRng + Rng>(
        &self,
        mle: Message<Mle<GC::F, CpuBackend>>,
        log_num_polynomials: usize,
        rng: &mut RNG,
    ) -> Result<(GC::Digest, Self::ProverData), ZkPcsCommitmentError>
    where
        Standard: Distribution<GC::F>,
    {
        // The flat MLE is interpreted as a `2^log_num_polynomials`-column matrix internally;
        // no separate stacking/copy step is needed.
        let (digest, prover_data) = self
            .zk_commit_mles(mle, log_num_polynomials, rng)
            .map_err(|e| ZkPcsCommitmentError::CommitmentFailed(e.to_string()))?;

        Ok((digest, prover_data))
    }

    fn prove_multi_eval(
        &self,
        ctx: &mut ZkProverContext<GC, MK, Self::ProverData>,
        claim: PcsMultiEvalClaim<GC::EF, ProverValue<GC, MK, Self::ProverData>>,
    ) -> Result<GC::PcsProof, Self::ProveError> {
        // Collect prover data and eval claims for each commitment
        let claims: Vec<_> = claim
            .commitment_indices
            .iter()
            .zip(claim.eval_exprs)
            .map(|(idx, eval_expr)| {
                let prover_data = ctx
                    .get_prover_data(*idx)
                    .expect("prove_multi_eval called with invalid commitment index");
                (prover_data, eval_expr)
            })
            .collect();

        // Generate the batched proof — propagate the real PCS error rather than panic.
        let (proof, constraint_data) =
            self.zk_generate_eval_proof_for_mles(claims, &claim.point, ctx)?;

        // Build the constraints from the constraint data
        constraint_data.build_constraints();

        Ok(proof)
    }
}
