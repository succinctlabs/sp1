use crate::{
    JaggedEvalSumcheckConfig, JaggedLittlePolynomialVerifierParams, JaggedSumcheckEvalProof,
};
use itertools::{izip, Itertools};
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractField, PrimeField32};
use slop_challenger::{FieldChallenger, IopCtx};
use slop_commit::Rounds;
use slop_multilinear::{full_geq, Mle, MleEval, MultilinearPcsVerifier, Point};
use slop_sumcheck::{partially_verify_sumcheck_proof, PartialSumcheckProof, SumcheckError};
use slop_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use slop_utils::log2_ceil_usize;
use std::{fmt::Debug, iter::once};
use thiserror::Error;

#[derive(Clone, Serialize, Deserialize)]
pub struct JaggedPcsProof<GC: IopCtx, Proof> {
    pub pcs_proof: Proof,
    pub sumcheck_proof: PartialSumcheckProof<GC::EF>,
    pub jagged_eval_proof: JaggedSumcheckEvalProof<GC::EF>,
    pub row_counts_and_column_counts: Rounds<Vec<(usize, usize)>>,
    pub merkle_tree_commitments: Rounds<GC::Digest>,
    pub expected_eval: GC::EF,
    pub max_log_row_count: usize,
    pub log_m: usize,
}

#[derive(Debug, Clone)]
pub struct JaggedPcsVerifier<GC, C> {
    pub pcs_verifier: C,
    pub max_log_row_count: usize,
    _marker: std::marker::PhantomData<GC>,
}

impl<GC, C> JaggedPcsVerifier<GC, C> {
    pub fn new(pcs_verifier: C, max_log_row_count: usize) -> Self {
        Self { pcs_verifier, max_log_row_count, _marker: std::marker::PhantomData }
    }
}

#[derive(Debug, Error)]
pub enum JaggedPcsVerifierError<EF, PcsError> {
    #[error("sumcheck claim mismatch: {0} != {1}")]
    SumcheckClaimMismatch(EF, EF),
    #[error("sumcheck proof verification failed: {0}")]
    SumcheckError(SumcheckError),
    #[error("jagged evaluation proof verification failed")]
    JaggedEvalProofVerificationFailed,
    #[error("dense pcs verification failed: {0}")]
    DensePcsVerificationFailed(#[from] PcsError),
    #[error("booleanity check failed")]
    BooleanityCheckFailed,
    #[error("montonicity check failed")]
    MonotonicityCheckFailed,
    #[error("proof has incorrect shape")]
    IncorrectShape,
    #[error("invalid prefix sums")]
    InvalidPrefixSums,
    #[error("incorrect table sizes")]
    IncorrectTableSizes,
    #[error("round area out of bounds (must be non-zero and less than 2^30)")]
    AreaOutOfBounds,
    #[error("base field overflow")]
    BaseFieldOverflow,
}

pub struct PrefixSumsMaxLogRowCount {
    pub row_counts: Vec<Vec<usize>>,
    pub column_counts: Vec<Vec<usize>>,
    pub usize_prefix_sums: Vec<usize>,
    pub log_m: usize,
}

pub fn unzip_and_prefix_sums(
    row_counts_and_column_counts: &Rounds<Vec<(usize, usize)>>,
) -> PrefixSumsMaxLogRowCount {
    let (row_counts, column_counts): (Vec<Vec<usize>>, Vec<Vec<usize>>) =
        row_counts_and_column_counts.iter().map(|r_c| r_c.clone().into_iter().unzip()).unzip();

    let usize_column_heights: Vec<usize> = row_counts
        .iter()
        .zip_eq(column_counts.iter())
        .flat_map(|(rc, cc)| {
            rc.iter().zip_eq(cc.iter()).flat_map(|(r, c)| std::iter::repeat_n(*r, *c))
        })
        .collect();

    let mut usize_prefix_sums: Vec<usize> = usize_column_heights
        .iter()
        .scan(0usize, |state, &x| {
            let result = *state;
            *state += x;
            Some(result)
        })
        .collect();

    usize_prefix_sums
        .push(*usize_prefix_sums.last().unwrap() + *usize_column_heights.last().unwrap());

    let log_trace = log2_ceil_usize(usize_prefix_sums.last().copied().unwrap());
    PrefixSumsMaxLogRowCount { row_counts, column_counts, usize_prefix_sums, log_m: log_trace }
}

impl<GC: IopCtx, Verifier: MultilinearPcsVerifier<GC>> JaggedPcsVerifier<GC, Verifier> {
    pub fn challenger(&self) -> GC::Challenger {
        GC::default_challenger()
    }

    pub fn verify_trusted_evaluations(
        &self,
        commitments: &[GC::Digest],
        point: Point<GC::EF>,
        evaluation_claims: &[MleEval<GC::EF>],
        proof: &JaggedPcsProof<GC, Verifier::Proof>,
        challenger: &mut GC::Challenger,
    ) -> Result<(), JaggedPcsVerifierError<GC::EF, Verifier::VerifierError>> {
        let JaggedPcsProof {
            pcs_proof,
            sumcheck_proof,
            jagged_eval_proof,
            row_counts_and_column_counts,
            merkle_tree_commitments: original_commitments,
            expected_eval,
            max_log_row_count,
            log_m,
        } = proof;

        // Each round must have at least one table committed to.
        if row_counts_and_column_counts.iter().any(|rc_cc| rc_cc.is_empty()) {
            return Err(JaggedPcsVerifierError::IncorrectShape);
        }

        let PrefixSumsMaxLogRowCount {
            row_counts,
            column_counts,
            usize_prefix_sums,
            log_m: purported_log_m,
        } = unzip_and_prefix_sums(row_counts_and_column_counts);

        if usize_prefix_sums.is_empty()
            || *max_log_row_count != self.max_log_row_count
            || *log_m != purported_log_m
        {
            return Err(JaggedPcsVerifierError::IncorrectShape);
        }

        let num_col_variables = (usize_prefix_sums.len() - 1).next_power_of_two().ilog2();
        let z_col = (0..num_col_variables)
            .map(|_| challenger.sample_ext_element::<GC::EF>())
            .collect::<Point<_>>();

        let z_row = point;

        if z_row.dimension() != self.max_log_row_count {
            return Err(JaggedPcsVerifierError::IncorrectShape);
        }

        // Collect the claims for the different polynomials.
        let mut column_claims = evaluation_claims.iter().flatten().copied().collect::<Vec<_>>();

        if commitments.len() != self.pcs_verifier.num_expected_commitments()
            || evaluation_claims.len() != self.pcs_verifier.num_expected_commitments()
            || row_counts.len() != self.pcs_verifier.num_expected_commitments()
            || column_counts.len() != self.pcs_verifier.num_expected_commitments()
            || original_commitments.len() != self.pcs_verifier.num_expected_commitments()
        {
            return Err(JaggedPcsVerifierError::IncorrectShape);
        }

        if !row_counts.iter().all(|rc| rc.len() >= 2)
            || !column_counts.iter().all(|cc| cc.len() >= 2)
        {
            return Err(JaggedPcsVerifierError::IncorrectShape);
        }

        // Check
        for (round_column_counts, round_evaluation) in
            izip!(column_counts.iter(), evaluation_claims.iter())
        {
            let expected_len: usize =
                round_column_counts.iter().take(round_column_counts.len() - 2).sum();
            if round_evaluation.num_polynomials() != expected_len {
                return Err(JaggedPcsVerifierError::IncorrectShape);
            }
        }

        for (round_column_counts, round_row_counts, modified_commitment, original_commitment) in izip!(
            column_counts.iter(),
            row_counts.iter(),
            commitments.iter(),
            original_commitments.iter()
        ) {
            let (hasher, compressor) = GC::default_hasher_and_compressor();

            if round_column_counts.len() >= GC::F::ORDER_U32 as usize {
                return Err(JaggedPcsVerifierError::BaseFieldOverflow);
            }
            if round_row_counts
                .iter()
                .chain(round_column_counts.iter())
                .any(|&count| count >= GC::F::ORDER_U32 as usize)
            {
                return Err(JaggedPcsVerifierError::BaseFieldOverflow);
            }

            let hash = hasher.hash_iter(
                once(GC::F::from_canonical_usize(round_column_counts.len())).chain(
                    round_row_counts.clone().into_iter().map(GC::F::from_canonical_usize).chain(
                        round_column_counts.clone().into_iter().map(GC::F::from_canonical_usize),
                    ),
                ),
            );
            let expected_commitment = compressor.compress([*original_commitment, hash]);

            if expected_commitment != *modified_commitment {
                return Err(JaggedPcsVerifierError::IncorrectTableSizes);
            }
        }

        let round_areas: Vec<usize> = row_counts
            .iter()
            .zip(column_counts.iter())
            .map(|(rc, cc)| {
                // The counts have been checked above to be at least length 2, so it's safe to
                // subtract 2.
                let rc_len = rc.len() - 2;
                let cc_len = cc.len() - 2;
                rc.iter()
                    .take(rc_len)
                    .zip_eq(cc.iter().take(cc_len))
                    .map(|(r, c)| r.saturating_mul(*c))
                    .fold(0usize, |a, b| a.saturating_add(b))
            })
            .collect();

        // Each round is checked to have a non-zero area. This check may not be strictly necessary.
        // The area must also be less than 2^30 to avoid overflow in field arithmetic.
        if round_areas.iter().any(|&area| area == 0 || area >= (1 << 30)) {
            return Err(JaggedPcsVerifierError::AreaOutOfBounds);
        }

        // Check that the padding column and row counts are computed from the total areas correctly.
        let expected_added_vals_and_cols: Vec<(usize, usize)> = round_areas
            .iter()
            .map(|area| {
                let next_multiple = area.next_multiple_of(
                    1 << Verifier::log_stacking_height(&self.pcs_verifier) as usize,
                );
                // No underflow because `next_multiple>=area`.
                let added_vals = next_multiple - area;
                (added_vals, added_vals.div_ceil(1 << self.max_log_row_count).max(1))
            })
            .collect();

        let proof_added_columns: Vec<usize> =
            column_counts.iter().map(|cc| cc[cc.len() - 2] + 1).collect();

        let (added_rows_uniform, added_rows_final): (Vec<usize>, Vec<usize>) =
            row_counts.iter().map(|rc| (rc[rc.len() - 2], rc[rc.len() - 1])).unzip();

        let last_cols = column_counts.iter().map(|cc| cc[cc.len() - 1]).collect::<Vec<_>>();

        // The last two column counts in each round should be `[num_added_columns, 1]`, and the
        // last two row counts in each round should be of the form `[1<<self.max_log_row_count, x]`.
        if proof_added_columns
            != expected_added_vals_and_cols.iter().map(|(_, cols)| *cols).collect::<Vec<_>>()
            || last_cols.iter().any(|&x| x != 1)
            || added_rows_uniform.iter().any(|&x| x != 1 << self.max_log_row_count)
            || added_rows_final.iter().zip_eq(expected_added_vals_and_cols.iter()).any(
                |(&x, &expected)| {
                    x != expected.0 - (expected.1 - 1) * (1 << self.max_log_row_count)
                },
            )
            || row_counts.iter().any(|rc| rc.iter().any(|&r| r > 1 << self.max_log_row_count))
        {
            return Err(JaggedPcsVerifierError::IncorrectShape);
        }

        if *log_m >= 30 {
            return Err(JaggedPcsVerifierError::AreaOutOfBounds);
        }

        let point_prefix_sums: Vec<Point<GC::F>> =
            usize_prefix_sums.iter().map(|&x| Point::from_usize(x, *log_m + 1)).collect();

        let insertion_points: Vec<usize> = column_counts
            .iter()
            .scan(0, |state, y| {
                // Remove the the last two counts, which are the added columns for padding to the
                // next multiple of `log_stacking_height`.
                let y_len = y.len() - 2;
                *state += y.iter().take(y_len).sum::<usize>();
                Some(*state)
            })
            .collect();

        // For each commit, the stacked PCS needed a commitment to a vector of length a multiple of
        // 1 << self.pcs.log_stackiinng_height, and this is achieved by adding columns of zeroes
        // after the "real" columns. We insert these "artificial" zeroes into the evaluation
        // claims on the verifier side.
        for (insertion_point, num_added_columns) in
            insertion_points.iter().rev().zip_eq(proof_added_columns.iter().rev())
        {
            for _ in 0..*num_added_columns {
                column_claims.insert(*insertion_point, GC::EF::zero());
            }
        }

        if point_prefix_sums.len() != column_claims.len() + 1 {
            return Err(JaggedPcsVerifierError::IncorrectShape);
        }

        // Pad the column claims to the next power of two.
        column_claims.resize(column_claims.len().next_power_of_two(), GC::EF::zero());

        if (1 << z_col.len()) != column_claims.len() {
            return Err(JaggedPcsVerifierError::IncorrectShape);
        }

        let column_mle = Mle::from(column_claims);
        let sumcheck_claim = column_mle.blocking_eval_at(&z_col)[0];

        if sumcheck_claim != sumcheck_proof.claimed_sum {
            return Err(JaggedPcsVerifierError::SumcheckClaimMismatch(
                sumcheck_claim,
                sumcheck_proof.claimed_sum,
            ));
        }

        let log_trace = log2_ceil_usize(usize_prefix_sums.last().copied().unwrap());
        partially_verify_sumcheck_proof(sumcheck_proof, challenger, log_trace, 2)
            .map_err(JaggedPcsVerifierError::SumcheckError)?;

        for (t_col, next_t_col) in point_prefix_sums.iter().zip(point_prefix_sums.iter().skip(1)) {
            // We bound the prefix sums to be < 2^30. While this function is implemented with
            // `C::F` being any field, this function is intended for use with primes larger than
            // `2^30`. We recommend using this function for Mersenne31, BabyBear, KoalaBear.
            if t_col.len() != next_t_col.len() || t_col.len() >= 31 || t_col.is_empty() {
                return Err(JaggedPcsVerifierError::IncorrectShape);
            }
            // Check monotonicity of the column prefix sums.
            if full_geq(t_col, next_t_col) != GC::F::one() {
                return Err(JaggedPcsVerifierError::MonotonicityCheckFailed);
            }
        }

        let params = JaggedLittlePolynomialVerifierParams { col_prefix_sums: point_prefix_sums };

        let jagged_eval = JaggedEvalSumcheckConfig::jagged_evaluation(
            &params,
            &z_row,
            &z_col,
            &sumcheck_proof.point_and_eval.0,
            jagged_eval_proof,
            challenger,
        )
        .map_err(|_| JaggedPcsVerifierError::JaggedEvalProofVerificationFailed)?;

        // Check the expected evaluation of the dense trace polynomial.
        if *expected_eval * jagged_eval != sumcheck_proof.point_and_eval.1 {
            return Err(JaggedPcsVerifierError::JaggedEvalProofVerificationFailed);
        }

        let mut total_areas = round_areas.clone();
        for (prev_area, (num_added_evals, _)) in
            total_areas.iter_mut().zip_eq(expected_added_vals_and_cols.iter())
        {
            *prev_area += *num_added_evals;
        }

        // Verify the evaluation proof using the (dense) stacked PCS verifier.
        let evaluation_point = sumcheck_proof.point_and_eval.0.clone();
        self.pcs_verifier
            .verify_untrusted_evaluation(
                proof.merkle_tree_commitments.as_slice(),
                &total_areas,
                evaluation_point,
                *expected_eval,
                pcs_proof,
                challenger,
            )
            .map_err(JaggedPcsVerifierError::DensePcsVerificationFailed)
    }
}
