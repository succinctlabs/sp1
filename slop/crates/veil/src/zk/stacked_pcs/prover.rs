//! Base-PCS-generic ZK stacked PCS prover: the ZK commit/prove logic (generic over any base
//! [`BatchPcsProver`]) and the data/proof types it produces, surfaced via the blanket
//! [`crate::zk::inner::ZkPcsProver`] impl at the bottom of the file. The Basefold instantiation
//! lives in [`super::basefold_zk_wrapper`].
use super::sealed::Sealed;
use crate::zk::inner::{
    ConstraintContextInnerExt, MleCommitmentIndex, ProverValue, ZkIopCtx, ZkMerkleizer,
    ZkPcsCommitmentError, ZkPcsProver, ZkProverContext,
};
use derive_where::derive_where;
use rand::distributions::{Distribution, Standard};
use rand::{CryptoRng, Rng};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField};
use slop_alloc::CpuBackend;
use slop_challenger::{FieldChallenger, IopCtx};
use slop_commit::{Message, Rounds};
use slop_matrix::dense::RowMajorMatrix;
use slop_multilinear::{BatchPcsProver, Mle, MleEncoder, Point};
use slop_stacked::stacking_combine;
use slop_tensor::Tensor;
use std::{iter::repeat_with, sync::Arc};
use thiserror::Error;

use super::padding::VEIL_EXTRA_QUERIES;
use super::ZkStackedPcsConstraintData;

/// The per-commitment prover data of the base PCS — produced by the [`BatchPcsProver`] commit and
/// fed (as a [`slop_commit::Rounds`]) into proving.
#[allow(type_alias_bounds)]
pub(in crate::zk::stacked_pcs) type PcsProverData<GC: ZkIopCtx, P: BatchPcsProver<GC>> =
    <P as BatchPcsProver<GC>>::ProverData;

#[derive(Debug)]
#[derive_where(Clone; D: Clone)]
#[derive_where(Serialize, Deserialize; D, Tensor<GC::F, CpuBackend>)]
pub struct ZkStackedPcsProverData<GC: IopCtx, D> {
    /// Per-commitment prover data from the base PCS commit (the base PCS's `CommitData`).
    pub full_pcs_data: D,
    /// The committed tensors: the data components `mles[..last]` (their columns concatenate into the
    /// commitment's data columns), followed by the single shared mask `mles[last]`.
    pub mles: Message<Mle<GC::F, CpuBackend>>,
    /// Encoding height (variables per column) shared by every component and the mask.
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
    /// A claim's mask tensor has an unexpected number of columns.
    #[error("mask column count mismatch: expected {expected}, got {actual}")]
    MaskColumnMismatch { expected: usize, actual: usize },
    /// An eval claim referenced a commitment index with no prover data: either the index is out
    /// of bounds or the commitment was already opened (its data was taken).
    #[error("no prover data for commitment index {0}: invalid or already-opened")]
    MissingProverData(usize),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "BP: Serialize", deserialize = "BP: Deserialize<'de>"))]
pub struct ZkStackedPcsProof<GC: IopCtx, BP> {
    /// Base-PCS proof for the RLC polynomial evaluation
    pub rlc_eval_proof: BP,
    /// RLC evaluation claim (a_q in the protocol)
    pub rlc_eval_claim: GC::EF,
    /// RLC padding vector
    pub rlc_padding_vec: Vec<GC::EF>,
}

// =========================================================================================
// ZK stacked PCS proving over any base [`BatchPcsProver`]
//
// The ZK commit/prove logic below is generic over the base PCS purely through [`BatchPcsProver`]:
// it runs the opening protocol, supplies the [`MleEncoder`] used to encode the mid-proof
// random-linear-combination polynomial, and exposes the reduced-rate commit
// ([`BatchPcsProver::commit_mles_with_log_blowup`]) the ZK commit phase needs. A base PCS opts into
// the ZK stacked PCS by implementing [`super::sealed::Sealed`], which gates the blanket
// [`crate::zk::inner::ZkPcsProver`] impl at the bottom of this file.
//
// **Soundness-critical encoder constraint**: the base PCS's [`Encoder`](BatchPcsProver::Encoder) is
// more constrained here than in the transparent backend. Beyond the general [`MleEncoder`]
// consistency requirements, the ZK *verifier* hard-codes a **coefficient-basis Reed–Solomon**
// rate-padding correction (`padding_eval · x^{2^point_dim}` in `to_virtual_oracle`, the
// coefficient-form split `enc([data|pad])(x) = enc(data)(x) + x^{|data|}·enc(pad)(x)`). So the base
// PCS must commit via a coefficient-to-evaluation RS encoder (e.g.
// [`CpuDftEncoder`](slop_basefold_prover::CpuDftEncoder)); an evaluation-basis encoder would
// type-check but make that correction wrong.
// =========================================================================================

/// The query count of the ZK protocol: the base PCS's query count
/// ([`BatchPcsProver::num_queries`]) plus the [`VEIL_EXTRA_QUERIES`] rate-correction margin (the ZK
/// padding slightly raises the committed code's rate — see [`super::padding`]). This is the number
/// of random hiding rows the ZK commit appends to each polynomial, and every veil-side use of the
/// base PCS query count goes through it.
fn num_zk_queries<GC: ZkIopCtx, P: BatchPcsProver<GC>>(prover: &P) -> usize {
    prover.num_queries() + VEIL_EXTRA_QUERIES
}

/// Commits one or more **pre-stacked** data MLEs under a single commitment, in a zk way.
///
/// `data_mles` are the block-column tensors `[2^mle_num_vars, cols_i]` (column `ℓ` is the paper's
/// `f_ℓ` — a consecutive block of the flat evaluation vector); they all share the encoding height
/// `2^mle_num_vars` and their columns concatenate (in order) into the commitment's full column
/// set. A single commitment may hold many such components (e.g. jagged's `LongMle` components) —
/// the simplest case is exactly one. Producers build the components via
/// [`slop_stacked::stack_multilinear`] (or already hold them); the PCS itself no longer
/// transposes.
///
/// The commitment is built from the data components **plus one shared `EF::D`-column random
/// mask**, committed *jointly* through the base PCS at a reduced rate (see
/// [`BatchPcsProver::commit_mles_with_log_blowup`]). The `num_zk_queries` hiding rows extend
/// every committed column with fresh random values, appended as the trailing rows of each data
/// component (a contiguous extend, no transpose).
#[allow(clippy::type_complexity)]
fn zk_commit_mles<GC, P, RNG>(
    prover: &P,
    data_mles: Message<Mle<GC::F, CpuBackend>>,
    rng: &mut RNG,
) -> Result<
    (P::Commitment, ZkStackedPcsProverData<GC, PcsProverData<GC, P>>),
    ZkStackedPcsProverError<P::ProverError>,
>
where
    GC: ZkIopCtx,
    P: BatchPcsProver<GC>,
    RNG: CryptoRng + Rng,
    Standard: Distribution<GC::F>,
{
    let num_mask_cols = GC::EF::D;

    // The encoding height is shared by every data component (and the mask).
    let mle_num_vars =
        data_mles.first().ok_or(ZkStackedPcsProverError::MissingMle)?.num_variables() as usize;
    let num_data_rows = 1usize << mle_num_vars;

    // Number of random hiding rows to append. These extra rows extend every committed
    // polynomial to raise its effective rate.
    let query_count = num_zk_queries(prover);
    let num_rows = num_data_rows + query_count;

    // Pad each data component's columns with `query_count` random hiding rows. This is a
    // contiguous extend per component (no transpose) — it reuses spare capacity when the
    // component is uniquely held, otherwise it copies that component's data once.
    let mut all_mle: Vec<Mle<GC::F>> = Vec::with_capacity(data_mles.len() + 1);
    for data in data_mles {
        if data.num_variables() as usize != mle_num_vars {
            return Err(ZkStackedPcsProverError::MismatchedNumVars {
                expected: mle_num_vars,
                actual: data.num_variables() as usize,
            });
        }
        let cols = data.num_polynomials();
        let mut data_vec = match Arc::try_unwrap(data) {
            Ok(mle) => mle.into_guts().into_buffer().into_vec(),
            Err(shared) => shared.guts().as_slice().to_vec(),
        };
        data_vec.extend(repeat_with(|| rng.gen()).take(query_count * cols));
        all_mle.push(Mle::new(RowMajorMatrix::new(data_vec, cols).into()));
    }

    // A single random mask spanning every row (data rows plus hiding rows), committed jointly
    // with the data components. One mask suffices for zero-knowledge across the whole commitment.
    let mask_vec: Vec<GC::F> = repeat_with(|| rng.gen()).take(num_rows * num_mask_cols).collect();
    all_mle.push(Mle::new(RowMajorMatrix::new(mask_vec, num_mask_cols).into()));

    let all_mle: Message<_> = Message::from(all_mle);

    // Commit the data components and mask jointly at a blowup reduced by one. The ZK hiding rows
    // push each component just past the power-of-two `num_data_rows` to `num_data_rows +
    // query_count` rows; the base encoder zero-extends that back up to the next power of two
    // internally (no padded copy here), and the reduced rate keeps the committed tensor the same
    // size as a standard unpadded commitment. The `clone` is a cheap `Arc`-vec clone — the stored
    // `all_mle` is reused unpadded for opening, no bulk data is copied.
    let reduced_log_blowup = prover.encoder().log_blowup().saturating_sub(1);
    let (commit, full_pcs_data) = prover
        .commit_mles_with_log_blowup(all_mle.clone(), reduced_log_blowup)
        .map_err(ZkStackedPcsProverError::BasefoldError)?;

    let prover_data = ZkStackedPcsProverData { full_pcs_data, mles: all_mle, mle_num_vars };

    Ok((commit, prover_data))
}

/// Generate a batched evaluation proof for multiple committed MLEs at the same point.
///
/// The base-PCS opening and the RLC encoding both go through the base PCS, so the proving
/// logic itself holds no base-PCS-specific types.
///
/// `prover_datas` are the per-commitment prover datas to open at the shared `reduced_point`. The
/// commitments may have **different** data-column counts; only the encoding height
/// (`mle_num_vars` = `reduced_point.dimension()`) must match across the batch. Returns the proof
/// to send to the verifier together with the constraint data (column sub-evaluations + RLC
/// consistency); the *decomposition* (`orig_eval == combiner(column_evals)`) is asserted by the
/// caller, not here.
///
/// TODO: Grinding functionality
#[allow(clippy::type_complexity)]
fn zk_generate_eval_proof_for_mles<GC, MK, P>(
    prover: &P,
    prover_datas: Vec<ZkStackedPcsProverData<GC, PcsProverData<GC, P>>>,
    reduced_point: &Point<GC::EF>,
    zkbuilder: &mut ZkProverContext<
        GC,
        MK,
        ZkStackedPcsProverData<GC, PcsProverData<GC, P>>,
        ZkStackedPcsProof<GC, P::Proof>,
    >,
) -> Result<
    (
        ZkStackedPcsProof<GC, P::Proof>,
        ZkStackedPcsConstraintData<
            GC,
            ZkProverContext<
                GC,
                MK,
                ZkStackedPcsProverData<GC, PcsProverData<GC, P>>,
                ZkStackedPcsProof<GC, P::Proof>,
            >,
        >,
    ),
    ZkStackedPcsProverError<P::ProverError>,
>
where
    GC: ZkIopCtx,
    MK: ZkMerkleizer<GC>,
    P: BatchPcsProver<GC>,
{
    let num_claims = prover_datas.len();

    // Each commitment stores its data components in `mles[..last]` (their columns concatenate
    // into that commitment's data columns) and the shared `EF::D` mask in `mles[last]`. The
    // commitments may have *different* data-column counts (e.g. different-size polynomials opened
    // at points that share their encoding coordinates); only the encoding height `mle_num_vars`
    // — the dimension of the shared `reduced_point` where the base PCS opens — must match.
    let first = prover_datas.first().ok_or(ZkStackedPcsProverError::NoClaims)?;
    let mle_num_vars = first.mle_num_vars;

    let mut full_pcs_datas = Vec::with_capacity(num_claims);
    let mut all_mles = Vec::with_capacity(num_claims);
    // Per-commitment data-column counts (commitment-major); they index the single union eq.
    let mut column_counts = Vec::with_capacity(num_claims);

    for prover_data in prover_datas {
        let ZkStackedPcsProverData { full_pcs_data, mles, mle_num_vars: this_num_vars } =
            prover_data;
        if this_num_vars != mle_num_vars {
            return Err(ZkStackedPcsProverError::MismatchedNumVars {
                expected: mle_num_vars,
                actual: this_num_vars,
            });
        }
        if mles.last().expect("commitment has a mask").num_polynomials() != GC::EF::D {
            return Err(ZkStackedPcsProverError::MaskColumnMismatch {
                expected: GC::EF::D,
                actual: mles.last().expect("commitment has a mask").num_polynomials(),
            });
        }
        column_counts.push(mles[..mles.len() - 1].iter().map(|m| m.num_polynomials()).sum());
        full_pcs_datas.push(full_pcs_data);
        all_mles.push(mles);
    }

    // Step 1: For each commitment, evaluate all rows at the inner point and add to transcript.
    // Only commitment 0 includes mask column evaluations in the transcript;
    // the others only send data column evaluations (since only one mask is used).
    // The reduced point is supplied concretely by the caller (stacked default or custom). It
    // must have the encoding dimension, since the base PCS opens the committed columns there.
    if reduced_point.dimension() != mle_num_vars {
        return Err(ZkStackedPcsProverError::MismatchedNumVars {
            expected: mle_num_vars,
            actual: reduced_point.dimension(),
        });
    }
    let eval_point_inner = reduced_point;
    let mut per_claim_evals_elts = Vec::with_capacity(num_claims);
    let mut per_claim_evals_slice = Vec::with_capacity(num_claims);
    for (j, mles) in all_mles.iter().enumerate() {
        let mask_idx = mles.len() - 1;
        // Data column evaluations (this commitment's components concatenated in order), followed
        // — for commitment 0 only — by the mask column evaluations. Only one mask is used across
        // the batch, so the others omit it.
        let mut evals_slice: Vec<GC::EF> = Vec::with_capacity(column_counts[j] + GC::EF::D);
        for component in &mles[..mask_idx] {
            evals_slice.extend(
                component.eval_at(eval_point_inner).into_evaluations().into_buffer().into_vec(),
            );
        }
        if j == 0 {
            evals_slice.extend(
                mles[mask_idx]
                    .eval_at(eval_point_inner)
                    .into_evaluations()
                    .into_buffer()
                    .into_vec(),
            );
        }
        let num_to_send = if j == 0 { column_counts[j] + GC::EF::D } else { column_counts[j] };
        let evals_elts = zkbuilder.add_values(&evals_slice[..num_to_send]);
        per_claim_evals_elts.push(evals_elts);
        per_claim_evals_slice.push(evals_slice);
    }

    // Step 2: Sample the RLC point — a *single* eq over every data column of every commitment
    // (dimension = log2 of the total data-column count, rounded up to a power of two). This one
    // eq batches the whole request; there is no separate α batching challenge.
    let total_data_cols: usize = column_counts.iter().sum();
    let log_total_data_cols = total_data_cols.next_power_of_two().trailing_zeros() as usize;
    let rlc_point = zkbuilder.with_challenger(|challenger| {
        let coords: Vec<GC::EF> =
            (0..log_total_data_cols).map(|_| challenger.sample_ext_element()).collect();
        Point::new(coords.into())
    });

    // Step 3: Combine all data columns of all commitments under the single eq, plus commitment
    // 0's mask with coefficient 1:
    //   combined[row] = Σ_c eq(rlc_point, c) · data_col_c[row] + mask_0[row]
    // where `c` runs over every commitment's data columns in commitment order. The mask's
    // `EF::D` base columns are recombined into one random EF value via the monomial (EF-over-F)
    // basis (`from_base_slice`); added with coefficient 1, that random EF value hides the
    // combination.
    let eq_evals = Mle::partial_lagrange(&rlc_point);
    let eq_evals_slice = eq_evals.guts().as_buffer().to_vec();

    // Total rows = 2^mle_num_vars + query_count (from padding)
    let total_rows = all_mles[0][0].guts().sizes()[0];
    let mut combined_mle_vec: Vec<GC::EF> = vec![GC::EF::zero(); total_rows];

    // `global_col` runs continuously over all data columns of all commitments (commitment-major),
    // indexing the single eq weight vector.
    let mut global_col = 0;
    for (j, mles) in all_mles.iter().enumerate() {
        let mask_idx = mles.len() - 1;
        for component in &mles[..mask_idx] {
            let tensor = component.guts();
            let stride = tensor.strides()[0];
            let cols = component.num_polynomials();
            let weights = &eq_evals_slice[global_col..global_col + cols];
            let per_row: Vec<GC::EF> = tensor
                .as_buffer()
                .par_chunks_exact(stride)
                .map(|data_chunk| stacking_combine::<GC::F, GC::EF>(weights, data_chunk))
                .collect();
            for (dst, src) in combined_mle_vec.iter_mut().zip(per_row.iter()) {
                *dst += *src;
            }
            global_col += cols;
        }

        // Only commitment 0's mask is folded in (coefficient 1); it is the trailing component.
        if j == 0 {
            let mask_tensor = mles[mask_idx].guts();
            let mask_stride = mask_tensor.strides()[0];
            let per_row: Vec<GC::EF> = mask_tensor
                .as_buffer()
                .par_chunks_exact(mask_stride)
                .map(GC::EF::from_base_slice)
                .collect();
            for (dst, src) in combined_mle_vec.iter_mut().zip(per_row.iter()) {
                *dst += *src;
            }
        }
    }

    // Step 5: Split off padding from combined polynomial
    let unpadded_mle_length: usize = 1 << mle_num_vars;
    let rlc_padding_vec = combined_mle_vec.split_off(unpadded_mle_length);

    // Encode the combined polynomial into a base-PCS codeword via the backend's encoder.
    let batch_mle_f = RowMajorMatrix::new(combined_mle_vec.clone(), 1).flatten_to_base::<GC::F>();
    let batch_mle_f = Tensor::from(batch_mle_f).reshape([1 << mle_num_vars, GC::EF::D]);
    let rlc_codeword = prover.encoder().encode(Mle::new(batch_mle_f));

    // Step 6: Compute the combined eval claim — the same single eq over all commitments' data
    // column evals, plus commitment 0's mask eval (coefficient 1):
    //   combined_eval = Σ_c eq(rlc_point, c) · data_eval_c + mask_eval_0
    let flat_data_evals = per_claim_evals_slice
        .iter()
        .zip(&column_counts)
        .flat_map(|(evals_slice, &count)| evals_slice[..count].iter().copied());
    let mut rlc_eval_claim: GC::EF =
        eq_evals_slice.iter().zip(flat_data_evals).map(|(w, eval)| *w * eval).sum();
    // The single mask contribution from commitment 0 (coefficient 1), recombined via the
    // monomial EF-over-F basis. It follows commitment 0's `column_counts[0]` data evals.
    let mask_sum_0: GC::EF = (0..GC::EF::D)
        .map(|i| GC::EF::monomial(i) * per_claim_evals_slice[0][column_counts[0] + i])
        .sum();
    rlc_eval_claim += mask_sum_0;

    // Step 7: Observe combined padding and eval claim
    zkbuilder.with_challenger(|challenger| {
        challenger.observe_ext_element_slice(&rlc_padding_vec[..]);
        challenger.observe_ext_element(rlc_eval_claim);
    });

    // Step 8: Prove the base-PCS evaluation of the combined polynomial
    let rlc_mle_extension = Mle::new(RowMajorMatrix::new(combined_mle_vec, 1).into());
    let rlc_eval_proof = zkbuilder
        .with_challenger(|challenger| {
            prover.prove(
                eval_point_inner,
                rlc_eval_claim,
                rlc_mle_extension,
                rlc_codeword,
                full_pcs_datas.into_iter().collect(),
                challenger,
            )
        })
        .map_err(ZkStackedPcsProverError::BasefoldError)?;

    // Build constraint data (shared with verifier): the per-commitment column sub-evaluations
    // plus the RLC consistency data. The decomposition is handled by the caller.
    let constraint_data = ZkStackedPcsConstraintData {
        column_counts,
        rlc_point,
        combined_rlc_eval_claim: rlc_eval_claim,
        claims: Rounds { rounds: per_claim_evals_elts },
    };

    let proof = ZkStackedPcsProof { rlc_eval_proof, rlc_eval_claim, rlc_padding_vec };

    Ok((proof, constraint_data))
}

// ============================================================================
// External API: ZkPcsProver, generic over the base PCS prover
// ============================================================================

/// Any base [`BatchPcsProver`] that opts in via [`Sealed`] is a [`ZkPcsProver`]: committing and
/// proving are the free functions above, so this blanket impl just adapts the associated types and
/// error mapping. (It coexists with the `NoPcsProver` impl because `NoPcsProver` does not implement
/// [`Sealed`].)
impl<GC, MK, P> ZkPcsProver<GC, MK> for P
where
    GC: ZkIopCtx,
    MK: ZkMerkleizer<GC>,
    P: BatchPcsProver<GC> + Sealed,
    P::Proof: Clone + Serialize + serde::de::DeserializeOwned,
    P::ProverData: Clone,
{
    type Proof = ZkStackedPcsProof<GC, P::Proof>;
    type ProverData = ZkStackedPcsProverData<GC, PcsProverData<GC, P>>;
    type ProveError = ZkStackedPcsProverError<P::ProverError>;

    fn num_encoding_variables(&self) -> u32 {
        <P as BatchPcsProver<GC>>::num_encoding_variables(self)
    }

    fn commit_mle<RNG: CryptoRng + Rng>(
        &self,
        mle: Message<Mle<GC::F, CpuBackend>>,
        rng: &mut RNG,
    ) -> Result<(GC::Digest, Self::ProverData), ZkPcsCommitmentError>
    where
        Standard: Distribution<GC::F>,
    {
        let (commit, prover_data) = zk_commit_mles(self, mle, rng)
            .map_err(|e| ZkPcsCommitmentError::CommitmentFailed(e.to_string()))?;
        Ok((commit.into(), prover_data))
    }

    #[allow(clippy::type_complexity)]
    fn prove_multi_eval(
        &self,
        ctx: &mut ZkProverContext<GC, MK, Self::ProverData, Self::Proof>,
        commitment_indices: Rounds<MleCommitmentIndex>,
        reduced_point: &Point<GC::EF>,
    ) -> Result<
        (Self::Proof, Rounds<Vec<ProverValue<GC, MK, Self::ProverData, Self::Proof>>>),
        Self::ProveError,
    > {
        // Move out each commitment's prover data.
        let prover_datas: Vec<_> = commitment_indices
            .into_iter()
            .map(|idx| {
                ctx.take_prover_data(idx)
                    .ok_or(ZkStackedPcsProverError::MissingProverData(idx.index()))
            })
            .collect::<Result<_, Self::ProveError>>()?;

        let (proof, constraint_data) =
            zk_generate_eval_proof_for_mles(self, prover_datas, reduced_point, ctx)?;

        // The per-commitment data-column sub-evaluations the caller combines into the original eval.
        let columns = constraint_data.data_column_evals();
        // Discharge only the RLC-consistency constraint here.
        constraint_data.build_constraints();

        Ok((proof, columns))
    }
}
