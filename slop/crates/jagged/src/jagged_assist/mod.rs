mod assist_prover;
mod assist_verifier;
mod boolean_batched_prover;
mod boolean_batched_verifier;
mod geq;
mod two_stage_jagged;

pub use assist_prover::JaggedEvalSumcheckProver;
pub use assist_prover::*;
pub use assist_verifier::*;
pub use boolean_batched_verifier::*;
pub use geq::*;
pub use two_stage_jagged::*;

#[cfg(test)]
mod tests {

    use crate::{
        deinterleave_prefix_sums, interleave_prefix_sums,
        jagged_assist::assist_prover::JaggedEvalSumcheckPoly,
        jagged_assist::geq::{sum_z_first_n_via_geq, GeqBranchingProgram},
        BranchingProgram, JaggedLittlePolynomialProverParams, JaggedLittlePolynomialVerifierParams,
    };
    use itertools::Itertools;
    use rand::{thread_rng, Rng};
    use slop_algebra::{extension::BinomialExtensionField, AbstractField};
    use slop_alloc::Buffer;
    use slop_baby_bear::{
        baby_bear_poseidon2::{my_bb_16_perm, Perm},
        BabyBear,
    };
    use slop_challenger::DuplexChallenger;
    use slop_multilinear::{Mle, Point};
    use slop_sumcheck::partially_verify_sumcheck_proof;
    use slop_tensor::Tensor;
    use slop_utils::log2_ceil_usize;

    use super::*;

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Challenger = DuplexChallenger<BabyBear, Perm, 16, 8>;

    #[test]
    fn test_jagged_eval_sumcheck() {
        let row_counts = [12, 1, 0, 0, 17, 0];

        let mut rng = thread_rng();

        let mut prefix_sums = row_counts
            .iter()
            .scan(0, |state, row_count| {
                let result = *state;
                *state += row_count;
                Some(result)
            })
            .collect::<Vec<_>>();

        prefix_sums.push(*prefix_sums.last().unwrap() + row_counts.last().unwrap());
        let log_m = log2_ceil_usize(*prefix_sums.last().unwrap());

        let log_max_row_count = 7;

        let z_row: Point<EF> = (0..log_max_row_count).map(|_| rng.gen::<EF>()).collect();
        let z_col: Point<EF> =
            (0..log2_ceil_usize(row_counts.len())).map(|_| rng.gen::<EF>()).collect();
        let z_index: Point<EF> = (0..log_m + 1).map(|_| rng.gen::<EF>()).collect();

        let merged_prefix_sums = prefix_sums
            .windows(2)
            .map(|x| {
                let curr: Point<F> = Point::from_usize(x[0], log_m + 1);
                let next: Point<F> = Point::from_usize(x[1], log_m + 1);
                interleave_prefix_sums(&curr, &next)
            })
            .collect::<Vec<_>>();

        let z_col_eq_vals = (0..row_counts.len())
            .map(|c| {
                let c_point: Point<EF> = Point::from_usize(c, z_col.dimension());
                Mle::full_lagrange_eval(&c_point, &z_col)
            })
            .collect_vec();
        let h_poly = BranchingProgram::new(z_row.clone(), z_index.clone());
        let geq_poly = GeqBranchingProgram::new(log_m + 1);

        let prover_params =
            JaggedLittlePolynomialProverParams::new(row_counts.to_vec(), log_max_row_count);
        let verifier_params: JaggedLittlePolynomialVerifierParams<F> =
            prover_params.clone().into_verifier_params();
        let expected_assist_sum =
            verifier_params.full_jagged_little_polynomial_evaluation(&z_row, &z_col, &z_index);

        // Sample alpha (the assist/geq combining scalar) from a fresh challenger,
        // mirroring the verifier-side flow: observe the assist claim first, then sample.
        let default_perm = my_bb_16_perm();
        let mut alpha_challenger = Challenger::new(default_perm.clone());
        slop_challenger::FieldChallenger::observe_ext_element(
            &mut alpha_challenger,
            expected_assist_sum,
        );
        let alpha: EF = slop_challenger::FieldChallenger::sample_ext_element(&mut alpha_challenger);

        // The geq BP evaluates to 1 on every monotone (curr, next) pair. The
        // prover's z_col_eq factor is supported only on the real column pairs
        // (not the full 2^log_num_cols hypercube), so the geq contribution to
        // the sum is `Σ_{col in real} z_col_lagrange[col]`, computed via the
        // closed-form `sum_z_first_n_via_geq` (handles the n == 2^d edge case).
        let num_real_pairs = prefix_sums.len() - 1;
        let sum_z_first_n: EF = sum_z_first_n_via_geq::<F, EF>(num_real_pairs, &z_col);
        let expected_fused_sum = expected_assist_sum + alpha * sum_z_first_n;

        let batch_eval_poly = JaggedEvalSumcheckPoly::<F, EF>::new_from_jagged_params(
            z_row.clone(),
            z_col.clone(),
            z_index.clone(),
            prefix_sums.clone(),
            alpha,
        );

        let mut challenger = Challenger::new(default_perm.clone());
        slop_challenger::FieldChallenger::observe_ext_element(&mut challenger, expected_assist_sum);
        let _: EF = slop_challenger::FieldChallenger::sample_ext_element(&mut challenger);

        let mut sum_values = Buffer::from(vec![EF::zero(); 6 * (log_m + 1)]);

        let sc_proof = prove_jagged_eval_sumcheck(
            batch_eval_poly,
            &mut challenger,
            expected_fused_sum,
            1,
            &mut sum_values,
        );

        assert_eq!(sc_proof.claimed_sum, expected_fused_sum);

        let mut verify_challenger = DuplexChallenger::<BabyBear, Perm, 16, 8>::new(default_perm);
        slop_challenger::FieldChallenger::observe_ext_element(
            &mut verify_challenger,
            expected_assist_sum,
        );
        let _: EF = slop_challenger::FieldChallenger::sample_ext_element(&mut verify_challenger);
        partially_verify_sumcheck_proof(&sc_proof, &mut verify_challenger, 2 * (log_m + 1), 2)
            .unwrap();

        let out_of_domain_point = sc_proof.point_and_eval.0;

        let (curr, next) = deinterleave_prefix_sums(&out_of_domain_point);
        let h_eval = h_poly.eval(&curr, &next);
        let geq_eval = geq_poly.eval(&curr, &next);
        let prefix_factor: EF = merged_prefix_sums
            .iter()
            .zip(z_col_eq_vals.iter())
            .map(|(merged_prefix_sum, z_col_eq_val)| {
                *z_col_eq_val * Mle::full_lagrange_eval(merged_prefix_sum, &out_of_domain_point)
            })
            .sum();
        let expected_eval = prefix_factor * (h_eval + alpha * geq_eval);

        assert_eq!(expected_eval, sc_proof.point_and_eval.1);
    }

    /// End-to-end: the high-level prover + verifier should accept honest proofs.
    #[test]
    fn test_fused_jagged_eval_roundtrip_accepts() {
        use slop_challenger::FieldChallenger;
        let row_counts = vec![12usize, 1, 0, 0, 17, 0];
        let log_max_row_count = 7;

        let mut rng = thread_rng();
        let prover_params =
            JaggedLittlePolynomialProverParams::new(row_counts.clone(), log_max_row_count);
        let verifier_params: JaggedLittlePolynomialVerifierParams<F> =
            prover_params.clone().into_verifier_params();
        let log_m = log2_ceil_usize(*prover_params.col_prefix_sums_usize.last().unwrap());

        let z_row: Point<EF> = (0..log_max_row_count).map(|_| rng.gen::<EF>()).collect();
        let z_col: Point<EF> =
            (0..log2_ceil_usize(row_counts.len())).map(|_| rng.gen::<EF>()).collect();
        let z_trace: Point<EF> = (0..log_m + 1).map(|_| rng.gen::<EF>()).collect();

        let default_perm = my_bb_16_perm();
        let mut prover_challenger = Challenger::new(default_perm.clone());
        let prover = JaggedEvalSumcheckProver::<F, EF, Challenger>::default();
        let proof = prover.prove_jagged_evaluation(
            &prover_params,
            &z_row,
            &z_col,
            &z_trace,
            &mut prover_challenger,
        );

        let mut verifier_challenger = Challenger::new(default_perm);
        let result = JaggedEvalSumcheckConfig::<F>::jagged_evaluation(
            &verifier_params,
            &z_row,
            &z_col,
            &z_trace,
            &proof,
            &mut verifier_challenger,
        );
        assert!(result.is_ok(), "honest proof rejected: {:?}", result.err());

        // Drain the verifier challenger by sampling once to confirm FS states match
        // (prover stops after the sumcheck univariates; the verifier should be at
        // the same FS state).
        let prover_alpha: EF = prover_challenger.sample_ext_element();
        let verifier_alpha: EF = verifier_challenger.sample_ext_element();
        assert_eq!(prover_alpha, verifier_alpha, "FS states diverge post-fused-proof");

        let interleaved_prefix_sums_buffer = verifier_params
            .col_prefix_sums
            .iter()
            .zip(verifier_params.col_prefix_sums.iter().skip(1))
            .flat_map(|(curr, next)| {
                interleave_prefix_sums(curr, next).iter().copied().collect::<Vec<_>>()
            })
            .collect::<Buffer<_>>();

        let interleaved_prefix_sums_mle = Mle::new(
            Tensor::from(interleaved_prefix_sums_buffer)
                .reshape([(verifier_params.col_prefix_sums.len() - 1), 2 * (log_m + 1)]),
        );

        let eval =
            interleaved_prefix_sums_mle.eval_at(&proof.two_stage_proof.stage2.point_and_eval.0);

        // The final evaluations are computed always assuming the number of bits for `curr` and `next` is NUM_BITS; in the case at hand,
        // we know the number of bits is `log_m+1`, so we check that the other bits are 0.
        for i in 0..2 * (NUM_BITS - log_m - 1) {
            assert_eq!(proof.two_stage_proof.final_evals[i], EF::zero(), "failure at index {}", i);
        }

        // The remaining evaluation claims must match those produced by actually evaluating the
        // interleaved prefix sums MLE at the random sumcheck point.
        for (i, (e1, e2)) in eval
            .into_iter()
            .skip(2 * (NUM_BITS - log_m - 1))
            .zip(proof.two_stage_proof.final_evals)
            .enumerate()
        {
            assert_eq!(e1, e2, "eval mismatch at index {}", i);
        }
    }

    /// Non-monotonicity rejection now comes from the sumcheck rather than the
    /// explicit `full_geq` loop: if the verifier's `col_prefix_sums` are
    /// non-monotone, the geq BP eval at the random sumcheck point disagrees
    /// with the prover's claim (which assumed all monotone), so reconciliation
    /// fails.
    #[test]
    fn test_fused_jagged_eval_rejects_non_monotone() {
        let row_counts = vec![12usize, 1, 0, 0, 17, 0];
        let log_max_row_count = 7;

        let mut rng = thread_rng();
        let prover_params =
            JaggedLittlePolynomialProverParams::new(row_counts.clone(), log_max_row_count);
        let mut bad_prefix_sums = prover_params.col_prefix_sums_usize.clone();
        bad_prefix_sums.swap(1, 2);
        let bad_prover_params = JaggedLittlePolynomialProverParams {
            col_prefix_sums_usize: bad_prefix_sums,
            max_log_row_count: log_max_row_count,
        };
        let log_m = log2_ceil_usize(*bad_prover_params.col_prefix_sums_usize.last().unwrap());

        let z_row: Point<EF> = (0..log_max_row_count).map(|_| rng.gen::<EF>()).collect();
        let z_col: Point<EF> =
            (0..log2_ceil_usize(row_counts.len())).map(|_| rng.gen::<EF>()).collect();
        let z_trace: Point<EF> = (0..log_m + 1).map(|_| rng.gen::<EF>()).collect();

        let default_perm = my_bb_16_perm();
        let mut prover_challenger = Challenger::new(default_perm.clone());
        let prover = JaggedEvalSumcheckProver::<F, EF, Challenger>::default();
        let proof = prover.prove_jagged_evaluation(
            &bad_prover_params,
            &z_row,
            &z_col,
            &z_trace,
            &mut prover_challenger,
        );

        let mut verifier_challenger = Challenger::new(default_perm);

        let bad_verifier_params = bad_prover_params.into_verifier_params();

        // The jagged evaluation should fail, since the prover sumcheck claim is not satisfied by the
        // non-monotonic data.
        assert!(JaggedEvalSumcheckConfig::<F>::jagged_evaluation(
            &bad_verifier_params,
            &z_row,
            &z_col,
            &z_trace,
            &proof,
            &mut verifier_challenger,
        )
        .is_err());
    }
}
