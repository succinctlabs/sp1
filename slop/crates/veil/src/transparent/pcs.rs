//! A minimal stacked multilinear PCS for the transparent backend, built directly on the abstract
//! [`BatchPcsProver`] / [`BatchPcsVerifier`] / [`MleEncoder`] traits — the *same* base layer the ZK
//! stacked PCS rides on, but with **no** zero-knowledge machinery (no mask columns, no rate
//! padding, no padding correction). Everything here is generic in the base PCS; basefold is plugged
//! in via a type alias (see [`super::BasefoldTransparentProver`]). Because both backends use the
//! same base PCS and the same column decomposition, their column conventions agree, so the
//! `OracleEval` combiners are portable across the two backends.
//!
//! Stacking convention (block — matching `slop_stacked::stacked_reduced_point` /
//! `stacked_oracle_eval`, the jagged layer, and basefold's fixed encoding width): a flat MLE is
//! carved into **consecutive blocks** of height `2^log_stacking_height`, one block per committed
//! column. An evaluation point splits as
//! `point = (batch_point ∈ first dim - log_stacking_height coords, stack_point ∈ last
//! log_stacking_height coords)`; each column is opened at `stack_point`, and
//! `f(point) = Σ_c eq(batch_point, c) · col_c(stack_point)`.

use rayon::prelude::*;
use slop_algebra::{AbstractExtensionField, AbstractField, TwoAdicField};
use slop_challenger::{FieldChallenger, IopCtx};
use slop_commit::{Message, Rounds};
use slop_matrix::dense::RowMajorMatrix;
use slop_multilinear::{partial_lagrange_blocking, Mle, Point};
use slop_multilinear::{BatchPcsProver, BatchPcsVerifier, MleEncoder};
use slop_stacked::{stacked_batched_oracle_eval, stacked_reduced_point, stacking_combine};
use slop_tensor::Tensor;

/// Per-commitment prover data: the committed data components (kept so the opening can rebuild the
/// virtual oracle) plus the base-PCS prover data (used to open them).
pub struct TransparentCommitData<GC: IopCtx, Inner: BatchPcsProver<GC>> {
    /// The committed data components, each a `[2^log_stacking_height, cols_i]` block-column tensor;
    /// their columns concatenate (in order) into the commitment's full column set.
    pub columns: Message<Mle<GC::F>>,
    /// The base PCS prover data for this commitment.
    pub base_data: Inner::ProverData,
}

/// The result of [`commit`]: the commitment digest paired with its per-commitment prover data.
#[allow(type_alias_bounds)]
pub type CommitResult<GC: IopCtx, Inner: BatchPcsProver<GC>> =
    Result<(GC::Digest, TransparentCommitData<GC, Inner>), Inner::ProverError>;

/// `(reduced_point, union combiner coeffs over all commitments' columns, per-commitment eq-batch
/// weights)` — the shared per-opening derived data.
type OpeningParams<EF> = (Point<EF>, Vec<EF>, Vec<EF>);

/// Commit one or more **pre-stacked** block-column components under a single commitment through the
/// base PCS at the standard rate (no mask, no padding). Each `columns[i]` is a
/// `[2^log_stacking_height, cols_i]` tensor (column `ℓ` = a block `f_ℓ`); their columns concatenate
/// into the commitment's full column set. The decomposition (Fig 8 step 1) is the producer's job —
/// see [`slop_stacked::stack_multilinear`].
pub fn commit<GC, Inner>(prover: &Inner, columns: Message<Mle<GC::F>>) -> CommitResult<GC, Inner>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    Inner: BatchPcsProver<GC>,
{
    let (commitment, base_data) = prover.commit_mles(columns.clone())?;
    Ok((commitment.into(), TransparentCommitData { columns, base_data }))
}

/// Derives the shared opening data. Returns `(reduced_point, union_coeffs, eq_selector)`.
///
/// The `num_commitments` commitments (all opened at the same `point`) are eq-batched: a selector
/// point of `⌈log₂ num_commitments⌉` Fiat-Shamir coords gives the cross-commitment weight
/// `eq(selector, j)` (the eq analogue of `α^j`). The `union_coeffs` are the single
/// [`stacked_batched_oracle_eval`] over every `(commitment, column)` pair, and `eq_selector` holds
/// the per-commitment weights used to combine the claimed evaluations.
fn opening_params<GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>>(
    point: &Point<GC::EF>,
    log_stacking_height: usize,
    num_commitments: usize,
    challenger: &mut GC::Challenger,
) -> OpeningParams<GC::EF> {
    // Reduced opening point: the last `log_stacking_height` coords (shared by all commitments).
    let reduced_point = stacked_reduced_point(point, log_stacking_height);
    // Eq-batch the commitments: sample a selector point of `⌈log₂ N⌉` coords. The cross-commitment
    // weight is then `eq(selector, j)` instead of `α^j`, and the whole batched stacking combiner is
    // a single eq over the union of all columns: `coeffs[(j,c)] = eq(selector, j)·eq(batch_point, c)`.
    let log_num_commitments = num_commitments.next_power_of_two().trailing_zeros() as usize;
    let selector_coords: Vec<GC::EF> =
        (0..log_num_commitments).map(|_| challenger.sample_ext_element()).collect();
    let selector_point = Point::new(selector_coords.into());
    let eq_selector = partial_lagrange_blocking(&selector_point).into_buffer().into_vec();
    let union_coeffs =
        stacked_batched_oracle_eval(&selector_point, point, log_stacking_height).coeffs;
    (reduced_point, union_coeffs, eq_selector)
}

/// Open a batch of commitments (all at the same `point`) proving that the eq-batched, stacking-
/// combined virtual oracle evaluates to the eq-batched claimed evals. Mirrors the ZK opening minus
/// the mask / rate-padding / RLC-point machinery — the stacking combiner *is* the virtual oracle.
///
/// The virtual-oracle MLE is encoded via [`BatchPcsProver::encoder`], which the base PCS impl
/// guarantees to be consistent with how it encoded the committed columns (see [`MleEncoder`]).
pub fn open<GC, Inner>(
    prover: &Inner,
    commit_datas: &[&TransparentCommitData<GC, Inner>],
    point: &Point<GC::EF>,
    claimed_evals: &[GC::EF],
    log_stacking_height: usize,
    challenger: &mut GC::Challenger,
) -> Result<Inner::Proof, Inner::ProverError>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    Inner: BatchPcsProver<GC>,
    Inner::ProverData: Clone,
{
    // The virtual oracle is a polynomial over the `log_stacking_height` within-column coords (rows
    // of the committed columns), opened at the reduced point.
    let num_rows = 1usize << log_stacking_height;
    let num_cols = 1usize << (point.dimension() - log_stacking_height);
    let (reduced_point, union_coeffs, eq_selector) =
        opening_params::<GC>(point, log_stacking_height, commit_datas.len(), challenger);

    // Virtual oracle: virt[row] = Σ_j Σ_c eq(selector,j)·eq(batch_point,c) · col_j_c[row]. The union
    // coeffs are flattened commitment-major, so commitment `j`'s column weights are the contiguous
    // slice `union_coeffs[j·num_cols .. (j+1)·num_cols]`; within that, each data component reads the
    // sub-slice at its running column offset.
    let mut virtual_evals = vec![GC::EF::zero(); num_rows];
    for (j, cd) in commit_datas.iter().enumerate() {
        let commit_weights = &union_coeffs[j * num_cols..(j + 1) * num_cols];
        let mut col_offset = 0;
        for component in cd.columns.iter() {
            let comp_cols = component.num_polynomials();
            let weights = &commit_weights[col_offset..col_offset + comp_cols];
            virtual_evals
                .par_iter_mut()
                .zip_eq(component.hypercube_par_iter())
                .for_each(|(acc, cols)| *acc += stacking_combine::<GC::F, GC::EF>(weights, cols));
            col_offset += comp_cols;
        }
    }

    let reduced_eval: GC::EF = claimed_evals.iter().zip(&eq_selector).map(|(&e, &w)| w * e).sum();

    // Encode the virtual oracle into the base PCS codeword (flatten EF → base field, then encode).
    let virtual_f = RowMajorMatrix::new(virtual_evals.clone(), 1).flatten_to_base::<GC::F>();
    let virtual_f = Tensor::from(virtual_f).reshape([num_rows, GC::EF::D]);
    let codeword = prover.encoder().encode(Mle::new(virtual_f));
    let virtual_mle = Mle::new(RowMajorMatrix::new(virtual_evals, 1).into());

    let base_datas: Rounds<_> = commit_datas.iter().map(|cd| cd.base_data.clone()).collect();
    prover.prove(&reduced_point, reduced_eval, virtual_mle, codeword, base_datas, challenger)
}

/// Verify a batched opening produced by [`open`]: the single union stacking combiner (one big eq
/// over all commitments' columns) is handed to the base PCS as the virtual oracle's per-query
/// evaluator, against the eq-batched claimed evals.
pub fn verify<GC, Verifier>(
    verifier: &Verifier,
    commits: &[GC::Digest],
    point: &Point<GC::EF>,
    claimed_evals: &[GC::EF],
    log_stacking_height: usize,
    proof: &Verifier::Proof,
    challenger: &mut GC::Challenger,
) -> Result<(), Verifier::VerifierError>
where
    GC: IopCtx<F: TwoAdicField, EF: TwoAdicField>,
    Verifier: BatchPcsVerifier<GC, Commitment = GC::Digest>,
{
    let (reduced_point, union_coeffs, eq_selector) =
        opening_params::<GC>(point, log_stacking_height, commits.len(), challenger);

    let reduced_eval: GC::EF = claimed_evals.iter().zip(&eq_selector).map(|(&e, &w)| w * e).sum();

    // One big eq over the union of all commitments' columns: flatten the per-commitment opened
    // leaves (one round each, commitment-major) and dot with the union coefficients. (This mirrors
    // `LinearOracleEval`, but written as a closure so the base-field leaf is lifted into `EF` for the
    // multiply — `LinearOracleEval`'s own impl can't be reused here, see the module note.)
    let oracle_evaluator = |leaves: Rounds<&[GC::F]>, _index: usize| -> GC::EF {
        union_coeffs
            .iter()
            .zip(leaves.iter().flat_map(|round| round.iter()))
            .map(|(&c, &v)| c * GC::EF::from(v))
            .sum()
    };

    verifier.verify(commits, &reduced_point, reduced_eval, oracle_evaluator, proof, challenger)
}
