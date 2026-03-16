use serde::{Deserialize, Serialize};

use slop_utils::log2_ceil_usize;
use std::{fmt::Debug, iter::once, sync::Arc};

use slop_algebra::AbstractField;
use slop_alloc::{mem::CopyError, Buffer, CpuBackend, HasBackend};
use slop_challenger::{FieldChallenger, IopCtx};
use slop_commit::{Message, Rounds};
use slop_multilinear::{
    Evaluations, Mle, MultilinearPcsProver, MultilinearPcsVerifier, PaddedMle, Point, ToMle,
};
use slop_sumcheck::reduce_sumcheck_to_evaluation;
use slop_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use thiserror::Error;

use crate::{
    sumcheck::jagged_sumcheck_poly, JaggedAssistSumAsPolyCPUImpl, JaggedEvalProver,
    JaggedEvalSumcheckProver, JaggedLittlePolynomialProverParams, JaggedPcsProof,
    JaggedPcsVerifier,
};

pub type JaggedAssistProver<GC> = JaggedEvalSumcheckProver<
    <GC as IopCtx>::F,
    JaggedAssistSumAsPolyCPUImpl<<GC as IopCtx>::F, <GC as IopCtx>::EF, <GC as IopCtx>::Challenger>,
    CpuBackend,
    <GC as IopCtx>::Challenger,
>;

/// Result type for `commit_multilinears`.
pub type CommitMultilinearsResult<GC, C, Proof> = Result<
    (
        <GC as IopCtx>::Digest,
        JaggedProverData<GC, <C as MultilinearPcsProver<GC, Proof>>::ProverData>,
    ),
    JaggedProverError<<C as MultilinearPcsProver<GC, Proof>>::ProverError>,
>;

/// Result type for `prove_trusted_evaluations`.
pub type ProveTrustedEvaluationsResult<GC, C, Proof> = Result<
    JaggedPcsProof<GC, Proof>,
    JaggedProverError<<C as MultilinearPcsProver<GC, Proof>>::ProverError>,
>;

#[derive(Clone)]
pub struct JaggedProver<GC: IopCtx, Proof, C: MultilinearPcsProver<GC, Proof>> {
    pub pcs_prover: C,
    jagged_eval_prover: JaggedAssistProver<GC>,
    pub max_log_row_count: usize,
    _marker: std::marker::PhantomData<Proof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JaggedProverData<GC: IopCtx, ProverData> {
    pub pcs_prover_data: ProverData,
    pub row_counts: Arc<Vec<usize>>,
    pub column_counts: Arc<Vec<usize>>,
    /// The number of columns added as a result of padding in the undedrlying stacked PCS.
    pub padding_column_count: usize,
    pub original_commitment: GC::Digest,
}

#[derive(Debug, Error)]
pub enum JaggedProverError<Error> {
    #[error("batch pcs prover error: {0}")]
    BatchPcsProverError(Error),
    #[error("copy error: {0}")]
    CopyError(#[from] CopyError),
}

pub trait DefaultJaggedProver<GC: IopCtx, Verifier: MultilinearPcsVerifier<GC>>:
    MultilinearPcsProver<GC, Verifier::Proof> + Sized
{
    fn prover_from_verifier(
        verifier: &JaggedPcsVerifier<GC, Verifier>,
    ) -> JaggedProver<GC, Verifier::Proof, Self>;
}

impl<GC: IopCtx, Proof, C: MultilinearPcsProver<GC, Proof>> JaggedProver<GC, Proof, C> {
    pub const fn new(
        max_log_row_count: usize,
        pcs_prover: C,
        jagged_eval_prover: JaggedAssistProver<GC>,
    ) -> Self {
        Self {
            pcs_prover,
            jagged_eval_prover,
            max_log_row_count,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn from_verifier<Verifier>(verifier: &JaggedPcsVerifier<GC, Verifier>) -> Self
    where
        Verifier: MultilinearPcsVerifier<GC, Proof = Proof>,
        C: DefaultJaggedProver<GC, Verifier>,
    {
        C::prover_from_verifier(verifier)
    }

    /// Commit to a batch of padded multilinears.
    ///
    /// The jagged polyniomial commitments scheme is able to commit to sparse polynomials having
    /// very few or no real rows.
    /// **Note** the padding values will be ignored and treated as though they are zero.
    pub fn commit_multilinears(
        &self,
        multilinears: Vec<PaddedMle<GC::F>>,
    ) -> CommitMultilinearsResult<GC, C, Proof> {
        let mut row_counts = multilinears.iter().map(|x| x.num_real_entries()).collect::<Vec<_>>();
        let mut column_counts =
            multilinears.iter().map(|x| x.num_polynomials()).collect::<Vec<_>>();

        // Check the validity of the input multilinears.
        for padded_mle in multilinears.iter() {
            // Check that the number of variables matches what the prover expects.
            assert_eq!(padded_mle.num_variables(), self.max_log_row_count as u32);
        }

        // Because of the padding in the stacked PCS, it's necessary to add a "dummy columns" in the
        // jagged commitment scheme to pad the area to the next multiple of the stacking height.
        // We do this in the form of two dummy tables, one with the maximum number of rows and
        // possibly multiple columns, and one with a single column and the remaining number
        // of "leftover" values.

        // Collect all the multilinears that have at least one non-zero entry into a commit message
        // for the dense PCS.
        let message =
            multilinears.into_iter().filter_map(|mle| mle.into_inner()).collect::<Message<_>>();

        let (commitment, data, num_added_vals) =
            self.pcs_prover.commit_multilinear(message).unwrap();

        let num_added_cols = num_added_vals.div_ceil(1 << self.max_log_row_count).max(1);

        row_counts.push(1 << self.max_log_row_count);
        row_counts.push(num_added_vals - (num_added_cols - 1) * (1 << self.max_log_row_count));
        column_counts.push(num_added_cols - 1);
        column_counts.push(1);

        let (hasher, compressor) = GC::default_hasher_and_compressor();

        let hash = hasher.hash_iter(
            once(GC::F::from_canonical_usize(row_counts.len()))
                .chain(row_counts.clone().into_iter().map(GC::F::from_canonical_usize))
                .chain(column_counts.clone().into_iter().map(GC::F::from_canonical_usize)),
        );

        let final_commitment = compressor.compress([commitment, hash]);

        let jagged_prover_data = JaggedProverData::<GC, _> {
            pcs_prover_data: data,
            row_counts: Arc::new(row_counts),
            column_counts: Arc::new(column_counts),
            padding_column_count: num_added_cols,
            original_commitment: commitment,
        };

        Ok((final_commitment, jagged_prover_data))
    }

    pub fn prove_trusted_evaluations(
        &self,
        eval_point: Point<GC::EF>,
        evaluation_claims: Rounds<Evaluations<GC::EF>>,
        prover_data: Rounds<
            JaggedProverData<GC, <C as MultilinearPcsProver<GC, Proof>>::ProverData>,
        >,
        challenger: &mut GC::Challenger,
    ) -> ProveTrustedEvaluationsResult<GC, C, Proof> {
        let num_col_variables = prover_data
            .iter()
            .map(|data| data.column_counts.iter().sum::<usize>())
            .sum::<usize>()
            .next_power_of_two()
            .ilog2();
        let z_col = (0..num_col_variables)
            .map(|_| challenger.sample_ext_element::<GC::EF>())
            .collect::<Point<_>>();

        let z_row = eval_point;

        let backend = *evaluation_claims[0][0].backend();

        // First, allocate a buffer for all of the column claims on device.
        let total_column_claims = evaluation_claims
            .iter()
            .map(|evals| evals.iter().map(|evals| evals.num_polynomials()).sum::<usize>())
            .sum::<usize>();

        let total_len = total_column_claims
        // Add in the dummy padding columns added during the stacked PCS commitment.
            + prover_data.iter().map(|data| data.padding_column_count).sum::<usize>();

        let mut column_claims: Buffer<GC::EF> = Buffer::with_capacity_in(total_len, backend);

        // Then, copy the column claims from the evaluation claims into the buffer, inserting extra
        // zeros for the dummy columns.
        for (column_claim_round, data) in evaluation_claims.into_iter().zip(prover_data.iter()) {
            for column_claim in column_claim_round.into_iter() {
                column_claims
                    .extend_from_device_slice(column_claim.into_evaluations().as_buffer())?;
            }
            column_claims.extend_from_host_slice(
                vec![GC::EF::zero(); data.padding_column_count].as_slice(),
            )?;
        }

        assert!(prover_data
            .iter()
            .flat_map(|data| data.row_counts.iter())
            .all(|x| *x <= 1 << self.max_log_row_count));

        let row_data =
            prover_data.iter().map(|data| data.row_counts.clone()).collect::<Rounds<_>>();
        let column_data =
            prover_data.iter().map(|data| data.column_counts.clone()).collect::<Rounds<_>>();

        // Collect the jagged polynomial parameters.
        let params = JaggedLittlePolynomialProverParams::new(
            prover_data
                .iter()
                .flat_map(|data| {
                    data.row_counts
                        .iter()
                        .copied()
                        .zip(data.column_counts.iter().copied())
                        .flat_map(|(row_count, column_count)| {
                            std::iter::repeat_n(row_count, column_count)
                        })
                })
                .collect(),
            self.max_log_row_count,
        );

        // Generate the jagged sumcheck proof.
        let z_row_backend = z_row.copy_into(&backend);
        let z_col_backend = z_col.copy_into(&backend);

        let all_mles = prover_data
            .iter()
            .map(|data| data.pcs_prover_data.interleaved_mles().clone())
            .collect::<Rounds<_>>();

        let sumcheck_poly = {
            let _span = tracing::debug_span!("create jagged sumcheck poly").entered();
            jagged_sumcheck_poly(
                all_mles.clone(),
                &params,
                row_data,
                column_data,
                self.pcs_prover.log_max_padding_amount(),
                &z_row_backend,
                &z_col_backend,
            )
        };

        // The overall evaluation claim of the sparse polynomial is inferred from the individual
        // table claims.

        let column_claims: Mle<GC::EF> = Mle::from_buffer(column_claims);

        let sumcheck_claims = column_claims.eval_at(&z_col_backend);
        let sumcheck_claim = sumcheck_claims[0];

        let (sumcheck_proof, component_poly_evals) = reduce_sumcheck_to_evaluation(
            vec![sumcheck_poly],
            challenger,
            vec![sumcheck_claim],
            1,
            GC::EF::one(),
        );

        let final_eval_point = sumcheck_proof.point_and_eval.0.clone();

        let jagged_eval_proof = {
            let _span = tracing::debug_span!("jagged evaluation proof").entered();
            self.jagged_eval_prover.prove_jagged_evaluation(
                &params,
                &z_row,
                &z_col,
                &final_eval_point,
                challenger,
                backend,
            )
        };
        let (row_counts, column_counts): (Rounds<_>, Rounds<_>) = prover_data
            .iter()
            .map(|data| {
                (Clone::clone(data.row_counts.as_ref()), Clone::clone(data.column_counts.as_ref()))
            })
            .unzip();

        let original_commitments: Rounds<_> =
            prover_data.iter().map(|data| data.original_commitment).collect();

        let stacked_prover_data =
            prover_data.into_iter().map(|data| data.pcs_prover_data).collect::<Rounds<_>>();

        let pcs_proof = {
            let _span = tracing::debug_span!("Dense PCS evaluation proof").entered();
            self.pcs_prover
                .prove_untrusted_evaluation(
                    final_eval_point,
                    component_poly_evals[0][0],
                    stacked_prover_data,
                    challenger,
                )
                .unwrap()
        };

        let row_counts_and_column_counts: Rounds<Vec<(usize, usize)>> = row_counts
            .into_iter()
            .zip(column_counts)
            .map(|(r, c)| r.into_iter().zip(c).collect())
            .collect();

        Ok(JaggedPcsProof {
            pcs_proof,
            sumcheck_proof,
            jagged_eval_proof,
            row_counts_and_column_counts,
            merkle_tree_commitments: original_commitments,
            expected_eval: component_poly_evals[0][0],
            max_log_row_count: self.max_log_row_count,
            log_m: log2_ceil_usize(*params.col_prefix_sums_usize.last().unwrap()),
        })
    }
}
