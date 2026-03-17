mod eval_sumcheck_prover;
mod sumcheck_eval;
mod sumcheck_poly;
mod sumcheck_sum_as_poly;

pub use eval_sumcheck_prover::*;
use slop_alloc::{Buffer, CanCopyFrom, CpuBackend};
pub use sumcheck_eval::*;
pub use sumcheck_poly::*;
pub use sumcheck_sum_as_poly::*;

use slop_algebra::{ExtensionField, Field};
use slop_multilinear::{Point, PointBackend};

use crate::JaggedLittlePolynomialProverParams;

pub trait JaggedEvalProver<F: Field, EF: ExtensionField<F>, Challenger>:
    'static + Send + Sync + Clone
{
    type A: PointBackend<EF> + CanCopyFrom<Buffer<EF>, CpuBackend, Output = Buffer<EF, Self::A>>;

    fn prove_jagged_evaluation(
        &self,
        params: &JaggedLittlePolynomialProverParams,
        z_row: &Point<EF>,
        z_col: &Point<EF>,
        z_trace: &Point<EF>,
        challenger: &mut Challenger,
        backend: Self::A,
    ) -> JaggedSumcheckEvalProof<EF>;
}

#[cfg(test)]
mod tests {

    use crate::{
        interleave_prefix_sums, jagged_assist::sumcheck_poly::JaggedEvalSumcheckPoly,
        BranchingProgram, JaggedLittlePolynomialProverParams, JaggedLittlePolynomialVerifierParams,
    };
    use itertools::Itertools;
    use rand::{thread_rng, Rng};
    use slop_algebra::{extension::BinomialExtensionField, AbstractField};
    use slop_alloc::CpuBackend;
    use slop_baby_bear::{
        baby_bear_poseidon2::{my_bb_16_perm, Perm},
        BabyBear,
    };
    use slop_challenger::DuplexChallenger;
    use slop_multilinear::Mle;
    use slop_sumcheck::partially_verify_sumcheck_proof;
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

        let prover_params =
            JaggedLittlePolynomialProverParams::new(row_counts.to_vec(), log_max_row_count);
        let verifier_params: JaggedLittlePolynomialVerifierParams<F> =
            prover_params.clone().into_verifier_params();
        let expected_sum =
            verifier_params.full_jagged_little_polynomial_evaluation(&z_row, &z_col, &z_index);

        let batch_eval_poly = JaggedEvalSumcheckPoly::<
            F,
            EF,
            Challenger,
            Challenger,
            JaggedAssistSumAsPolyCPUImpl<F, EF, Challenger>,
            CpuBackend,
        >::new_from_jagged_params(
            z_row.clone(),
            z_col.clone(),
            z_index.clone(),
            prefix_sums.clone(),
            CpuBackend,
        );

        let default_perm = my_bb_16_perm();
        let mut challenger = Challenger::new(default_perm.clone());

        let mut sum_values = Buffer::from(vec![EF::zero(); 6 * (log_m + 1)]);

        let sc_proof = prove_jagged_eval_sumcheck(
            batch_eval_poly,
            &mut challenger,
            expected_sum,
            1,
            &mut sum_values,
        );

        assert!(sc_proof.claimed_sum == expected_sum);

        let mut challenger = DuplexChallenger::<BabyBear, Perm, 16, 8>::new(default_perm);
        partially_verify_sumcheck_proof(&sc_proof, &mut challenger, 2 * (log_m + 1), 2).unwrap();

        let out_of_domain_point = sc_proof.point_and_eval.0;

        let expected_eval = merged_prefix_sums
            .iter()
            .zip(z_col_eq_vals.iter())
            .map(|(merged_prefix_sum, z_col_eq_val)| {
                let h_eval = h_poly.eval_interleaved(&out_of_domain_point);
                *z_col_eq_val
                    * Mle::full_lagrange_eval(merged_prefix_sum, &out_of_domain_point)
                    * h_eval
            })
            .sum::<EF>();

        assert!(expected_eval == sc_proof.point_and_eval.1);
    }
}
