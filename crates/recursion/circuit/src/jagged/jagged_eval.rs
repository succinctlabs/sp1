use std::marker::PhantomData;

use rayon::ThreadPoolBuilder;
use slop_algebra::AbstractField;
use slop_jagged::{
    deinterleave_prefix_sums, BranchingProgram, JaggedLittlePolynomialVerifierParams,
    JaggedSumcheckEvalProof, K, K1, K2,
};
use slop_multilinear::{full_geq, partial_lagrange_blocking, Mle, Point};

use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Ext, Felt, SymbolicExt, SymbolicFelt},
};

use crate::{
    challenger::FieldChallengerVariable, sumcheck::verify_sumcheck, symbolic::IntoSymbolic,
    CircuitConfig, SP1FieldConfigVariable,
};

impl<C: CircuitConfig> IntoSymbolic<C> for JaggedLittlePolynomialVerifierParams<Felt<SP1Field>> {
    type Output = JaggedLittlePolynomialVerifierParams<SymbolicFelt<SP1Field>>;

    fn as_symbolic(&self) -> Self::Output {
        JaggedLittlePolynomialVerifierParams {
            col_prefix_sums: self
                .col_prefix_sums
                .iter()
                .map(|x| <Point<Felt<SP1Field>> as IntoSymbolic<C>>::as_symbolic(x))
                .collect::<Vec<_>>(),
        }
    }
}

/// The three jagged-evaluation points passed to [`RecursiveJaggedEvalConfig::jagged_evaluation`].
pub struct JaggedEvalPoints {
    pub z_row: Point<Ext<SP1Field, SP1ExtensionField>>,
    pub z_col: Point<Ext<SP1Field, SP1ExtensionField>>,
    pub z_trace: Point<Ext<SP1Field, SP1ExtensionField>>,
}

#[allow(clippy::type_complexity)]
pub trait RecursiveJaggedEvalConfig<C: CircuitConfig, Chal>: Sized {
    type JaggedEvalProof;

    fn jagged_evaluation(
        &self,
        builder: &mut Builder<C>,
        params: &JaggedLittlePolynomialVerifierParams<Felt<SP1Field>>,
        points: JaggedEvalPoints,
        proof: &Self::JaggedEvalProof,
        challenger: &mut Chal,
    ) -> (SymbolicExt<SP1Field, SP1ExtensionField>, Vec<Felt<SP1Field>>);
}

pub struct RecursiveTrivialJaggedEvalConfig;

impl<C: CircuitConfig> RecursiveJaggedEvalConfig<C, ()> for RecursiveTrivialJaggedEvalConfig {
    type JaggedEvalProof = ();

    fn jagged_evaluation(
        &self,
        _builder: &mut Builder<C>,
        params: &JaggedLittlePolynomialVerifierParams<Felt<SP1Field>>,
        points: JaggedEvalPoints,
        _proof: &Self::JaggedEvalProof,
        _challenger: &mut (),
    ) -> (SymbolicExt<SP1Field, SP1ExtensionField>, Vec<Felt<SP1Field>>) {
        let JaggedEvalPoints { z_row, z_col, z_trace } = points;
        let params_ef = JaggedLittlePolynomialVerifierParams {
            col_prefix_sums: params
                .col_prefix_sums
                .iter()
                .map(|x| x.iter().map(|y| SymbolicExt::from(*y)).collect())
                .collect::<Vec<_>>(),
        };
        let z_row =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(&z_row);
        let z_col =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(&z_col);
        let z_trace =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(&z_trace);

        // Need to use a single threaded rayon pool.
        let pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
        let result = pool.install(|| {
            params_ef.full_jagged_little_polynomial_evaluation(&z_row, &z_col, &z_trace)
        });
        (result, vec![])
    }
}

#[derive(Debug, Clone)]
pub struct RecursiveJaggedEvalSumcheckConfig<SC>(pub PhantomData<SC>);

impl<C: CircuitConfig, SC: SP1FieldConfigVariable<C>>
    RecursiveJaggedEvalConfig<C, SC::FriChallengerVariable>
    for RecursiveJaggedEvalSumcheckConfig<SC>
{
    type JaggedEvalProof = JaggedSumcheckEvalProof<Ext<SP1Field, SP1ExtensionField>>;

    fn jagged_evaluation(
        &self,
        builder: &mut Builder<C>,
        params: &JaggedLittlePolynomialVerifierParams<Felt<SP1Field>>,
        points: JaggedEvalPoints,
        proof: &Self::JaggedEvalProof,
        challenger: &mut SC::FriChallengerVariable,
    ) -> (SymbolicExt<SP1Field, SP1ExtensionField>, Vec<Felt<SP1Field>>) {
        let JaggedEvalPoints { z_row, z_col, z_trace } = points;
        // Mirror `slop_jagged::JaggedEvalSumcheckConfig::jagged_evaluation`.
        // Flow (CPU and circuit must match step-for-step in FS order):
        //   1. Sample α (combines assist + α·geq).
        //   2. Observe partial_sumcheck.claimed_sum (the fused claim).
        //   3. Verify the inner sumcheck.
        //   4. Two-stage GKR (verify stage1, transition via ζ''', verify stage2).
        //   5. Recover real_sum, reconcile via BP + geq evals at (curr, next).

        let z_row_sym =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(&z_row);
        let z_col_sym =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(&z_col);
        let z_trace_sym =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(&z_trace);

        let JaggedSumcheckEvalProof { partial_sumcheck_proof, two_stage_proof } = proof;

        // Static shape constants — `col_prefix_sums.len() - 1` is the number
        // of (curr, next) pairs the prover summed over, equal to the number
        // of "real" columns.  `log_num_cols = z_col.dimension()`.
        let num_real_pairs = params.col_prefix_sums.len() - 1;
        let log_num_cols = z_col_sym.dimension();
        let two_c = 1usize << log_num_cols;
        // `log_m + 1` = the per-prefix-sum bit width (== col_prefix_sums[0].dimension()).
        let prefix_sum_dim = params.col_prefix_sums[0].dimension();

        // ----- 1. Sample α. -----
        let alpha_ext = challenger.sample_ext(builder);
        let alpha: SymbolicExt<SP1Field, SP1ExtensionField> = alpha_ext.into();

        // ----- 2. Observe fused claim. -----
        let fused_claim_ext: Ext<SP1Field, SP1ExtensionField> =
            builder.eval(partial_sumcheck_proof.claimed_sum);
        challenger.observe_ext_element(builder, fused_claim_ext);

        // ----- 3. Verify the inner (assist + α·geq) sumcheck. -----
        builder.cycle_tracker_v2_enter("jagged eval - verify inner sumcheck");
        verify_sumcheck::<C, SC>(builder, challenger, partial_sumcheck_proof);
        builder.cycle_tracker_v2_exit();

        // `ζ_sumcheck` = the point inner sumcheck reduces to.  Length `2·(log_m+1)`.
        let zeta_sumcheck: Vec<SymbolicExt<SP1Field, SP1ExtensionField>> =
            partial_sumcheck_proof.point_and_eval.0.iter().map(|x| (*x).into()).collect();
        assert_eq!(zeta_sumcheck.len(), 2 * prefix_sum_dim);

        // ----- 4. Two-stage GKR verification (mirrors CPU lines 100–203). -----
        // λ1 is sampled but not actually used by the verifier — just drives FS.
        let _lambda1 = challenger.sample_ext(builder);

        builder.cycle_tracker_v2_enter("jagged eval - verify stage1 sumcheck");
        verify_sumcheck::<C, SC>(builder, challenger, &two_stage_proof.stage1);
        builder.cycle_tracker_v2_exit();
        challenger.observe_ext_element_slice(builder, &two_stage_proof.v);

        // Stage-1 consistency: `point_and_eval.1 == eq(z_col, stage1.point) · ∏ v_j`.
        let stage1_point: Point<SymbolicExt<SP1Field, SP1ExtensionField>> =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(
                &two_stage_proof.stage1.point_and_eval.0,
            );
        let v_sym: Vec<SymbolicExt<SP1Field, SP1ExtensionField>> =
            two_stage_proof.v.iter().map(|x| (*x).into()).collect();
        assert_eq!(v_sym.len(), K2);
        let eq_zcol_stage1 = Mle::<_>::full_lagrange_eval(&z_col_sym, &stage1_point);
        let prod_v = v_sym
            .iter()
            .cloned()
            .fold(SymbolicExt::<SP1Field, SP1ExtensionField>::one(), |acc, vj| acc * vj);
        let stage1_point_eval_sym: SymbolicExt<SP1Field, SP1ExtensionField> =
            two_stage_proof.stage1.point_and_eval.1.into();
        builder.assert_ext_eq(eq_zcol_stage1 * prod_v, stage1_point_eval_sym);

        // ζ''' challenge (log K_2 = 3 ext elements).
        let log_k2 = K2.trailing_zeros() as usize;
        let zeta_ppp: Point<SymbolicExt<SP1Field, SP1ExtensionField>> =
            (0..log_k2).map(|_| challenger.sample_ext(builder).into()).collect();
        // w = partial_lagrange(ζ'''), length K_2.
        let w = partial_lagrange_blocking(&zeta_ppp);
        let w_slice: &[SymbolicExt<SP1Field, SP1ExtensionField>] = w.as_buffer().as_slice();

        // Stage-1 → stage-2 claim transition: stage2.claimed_sum == Σ w_j · v_j.
        let stage2_claim_expected = w_slice
            .iter()
            .zip(v_sym.iter())
            .fold(SymbolicExt::<SP1Field, SP1ExtensionField>::zero(), |acc, (wj, vj)| {
                acc + *wj * *vj
            });
        let stage2_claimed_sum_sym: SymbolicExt<SP1Field, SP1ExtensionField> =
            two_stage_proof.stage2.claimed_sum.into();
        builder.assert_ext_eq(stage2_claim_expected, stage2_claimed_sum_sym);

        // λ2 sampled but unused (drives FS only).
        let _lambda2 = challenger.sample_ext(builder);

        builder.cycle_tracker_v2_enter("jagged eval - verify stage2 sumcheck");
        verify_sumcheck::<C, SC>(builder, challenger, &two_stage_proof.stage2);
        builder.cycle_tracker_v2_exit();

        challenger.observe_ext_element_slice(builder, &two_stage_proof.final_evals);

        // Stage-2 final consistency:
        //   stage2.point_and_eval.1 == eq(stage1.point, η) · Σ_j w_j · ∏_{j'} eq(z_padded[k], final_evals[k])
        // where k = j·K1 + j', and z_padded = `zeta_sumcheck` left-padded with zeros to length K.
        let eta_point: Point<SymbolicExt<SP1Field, SP1ExtensionField>> =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(
                &two_stage_proof.stage2.point_and_eval.0,
            );
        let eq_stage1_eta = Mle::<_>::full_lagrange_eval(&stage1_point, &eta_point);

        // z_padded[K - 2·(log_m+1) .. K] = zeta_sumcheck; first slots are zero.
        let k_actual = zeta_sumcheck.len();
        assert!(k_actual <= K);
        let mut z_padded: Vec<SymbolicExt<SP1Field, SP1ExtensionField>> =
            vec![SymbolicExt::<SP1Field, SP1ExtensionField>::zero(); K];
        z_padded[K - k_actual..].clone_from_slice(&zeta_sumcheck);

        let final_evals_sym: Vec<SymbolicExt<SP1Field, SP1ExtensionField>> =
            two_stage_proof.final_evals.iter().map(|x| (*x).into()).collect();
        assert_eq!(final_evals_sym.len(), K);

        let one_sym = SymbolicExt::<SP1Field, SP1ExtensionField>::one();
        let mut inner_sum = SymbolicExt::<SP1Field, SP1ExtensionField>::zero();
        for (j, &wj) in w_slice.iter().enumerate().take(K2) {
            let mut prod = one_sym;
            for jp in 0..K1 {
                let kk = j * K1 + jp;
                let zk = z_padded[kk];
                let pk = final_evals_sym[kk];
                // eq(zk, pk) = (1 - zk)(1 - pk) + zk · pk.
                prod *= (one_sym - zk) * (one_sym - pk) + zk * pk;
            }
            inner_sum += wj * prod;
        }
        let stage2_point_eval_sym: SymbolicExt<SP1Field, SP1ExtensionField> =
            two_stage_proof.stage2.point_and_eval.1.into();
        builder.assert_ext_eq(eq_stage1_eta * inner_sum, stage2_point_eval_sym);

        // ----- 5. Recover assist (real_sum) and reconcile via BP + geq. -----

        // sum_z_first_n = sum_z_first_n_via_geq(num_real_pairs, z_col).
        // n is a codegen-time constant; edges (n==0 or n>=2^c) collapse cleanly.
        let sum_z_first_n: SymbolicExt<SP1Field, SP1ExtensionField> = if num_real_pairs == 0 {
            SymbolicExt::<SP1Field, SP1ExtensionField>::zero()
        } else if num_real_pairs >= two_c {
            SymbolicExt::<SP1Field, SP1ExtensionField>::one()
        } else {
            let threshold_pt: Point<SymbolicExt<SP1Field, SP1ExtensionField>> = (0..log_num_cols)
                .rev()
                .map(|b| {
                    let bit = ((num_real_pairs >> b) & 1) as u32;
                    SymbolicExt::<SP1Field, SP1ExtensionField>::from_canonical_u32(bit)
                })
                .collect();
            one_sym - full_geq(&threshold_pt, &z_col_sym)
        };

        // jagged_eval is what `jagged_evaluation` returns to the caller —
        // the value of the dense MLE at the rotated point.
        let fused_claim_sym: SymbolicExt<SP1Field, SP1ExtensionField> =
            partial_sumcheck_proof.claimed_sum.into();
        let jagged_eval = fused_claim_sym - alpha * sum_z_first_n;

        // real_sum = stage1.claimed_sum − L(0, ζ_sumcheck) · (1 − sum_z_first_n).
        let l_zero: SymbolicExt<SP1Field, SP1ExtensionField> =
            zeta_sumcheck.iter().fold(one_sym, |acc, z| acc * (one_sym - *z));
        let padded_contribution = l_zero * (one_sym - sum_z_first_n);
        let stage1_claimed_sum_sym: SymbolicExt<SP1Field, SP1ExtensionField> =
            two_stage_proof.stage1.claimed_sum.into();
        let real_sum = stage1_claimed_sum_sym - padded_contribution;

        // De-interleave the inner-sumcheck point into (curr, next) pieces.
        let proof_point_sym =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(
                &partial_sumcheck_proof.point_and_eval.0,
            );
        let (curr, next) = deinterleave_prefix_sums(&proof_point_sym);

        let assist_bp = BranchingProgram::new(z_row_sym.clone(), z_trace_sym.clone());
        let assist_eval = assist_bp.eval(&curr, &next);

        // `full_geq` over the deinterleaved halves (each of dim `log_m+1`).
        let geq_eval = full_geq(&curr, &next);

        let expected = real_sum * (assist_eval + alpha * geq_eval);
        let partial_pe1_sym: SymbolicExt<SP1Field, SP1ExtensionField> =
            partial_sumcheck_proof.point_and_eval.1.into();
        builder.assert_ext_eq(expected, partial_pe1_sym);

        // ----- prefix_sum_felts: one Felt per *real* column (i.e. the
        //       first `num_real_cols == col_prefix_sums.len() - 1` entries
        //       of `col_prefix_sums`).  The trailing prefix sum (total
        //       area) is verified separately by the outer caller against
        //       `final_area`; including it here would tip
        //       `verify_trusted_evaluations`'s `zip_eq` against
        //       `repeated_flattened_row_counts` (which has length
        //       `num_real_cols`) off by one. -----

        let num_real_cols = params.col_prefix_sums.len().saturating_sub(1);
        let prefix_sum_felts: Vec<Felt<SP1Field>> = params
            .col_prefix_sums
            .iter()
            .take(num_real_cols)
            .map(|prefix_sum| {
                // bits2num: high-bit first (mirrors prefix_sum_checks order).
                let mut acc: Felt<_> = builder.constant(SP1Field::zero());
                for bit in prefix_sum.iter() {
                    acc = builder.eval(*bit + acc * SymbolicFelt::from_canonical_u32(2));
                }
                acc
            })
            .collect();

        (jagged_eval, prefix_sum_felts)
    }
}

#[cfg(test)]
mod tests {
    use std::{marker::PhantomData, sync::Arc};

    use rand::{thread_rng, Rng};
    use slop_algebra::{extension::BinomialExtensionField, AbstractField};
    use slop_challenger::{DuplexChallenger, IopCtx};
    use slop_jagged::{
        JaggedEvalSumcheckProver, JaggedLittlePolynomialProverParams,
        JaggedLittlePolynomialVerifierParams,
    };
    use slop_multilinear::Point;
    use sp1_core_machine::utils::setup_logger;
    use sp1_hypercube::{inner_perm, log2_ceil_usize};
    use sp1_primitives::{SP1DiffusionMatrix, SP1GlobalContext};
    use sp1_recursion_compiler::{
        circuit::{AsmBuilder, AsmCompiler, AsmConfig, CircuitV2Builder},
        ir::{Ext, Felt},
    };
    use sp1_recursion_executor::Executor;

    use crate::{
        challenger::DuplexChallengerVariable,
        jagged::jagged_eval::{
            JaggedEvalPoints, RecursiveJaggedEvalConfig, RecursiveJaggedEvalSumcheckConfig,
            RecursiveTrivialJaggedEvalConfig,
        },
        witness::Witnessable,
        SP1FieldConfigVariable,
    };

    use sp1_primitives::{SP1Field, SP1Perm};
    type F = SP1Field;
    type EF = BinomialExtensionField<SP1Field, 4>;
    type C = AsmConfig;
    type SC = SP1GlobalContext;

    fn trivial_jagged_eval(
        verifier_params: &JaggedLittlePolynomialVerifierParams<F>,
        z_row: &Point<EF>,
        z_col: &Point<EF>,
        z_trace: &Point<EF>,
        expected_result: EF,
        should_succeed: bool,
    ) {
        let mut builder = AsmBuilder::default();
        builder.cycle_tracker_v2_enter("trivial-jagged-eval");
        let verifier_params_variable = verifier_params.read(&mut builder);
        let z_row_variable = z_row.read(&mut builder);
        let z_col_variable = z_col.read(&mut builder);
        let z_trace_variable = z_trace.read(&mut builder);
        let recursive_jagged_evaluator = RecursiveTrivialJaggedEvalConfig {};
        let (recursive_jagged_evaluation, _) = <RecursiveTrivialJaggedEvalConfig as RecursiveJaggedEvalConfig<C, ()>>::jagged_evaluation(
            &recursive_jagged_evaluator,
            &mut builder,
            &verifier_params_variable,
            JaggedEvalPoints {
                z_row: z_row_variable,
                z_col: z_col_variable,
                z_trace: z_trace_variable,
            },
            &(),
            &mut (),
        );
        let recursive_jagged_evaluation: Ext<F, EF> = builder.eval(recursive_jagged_evaluation);
        let expected_result: Ext<F, EF> = builder.constant(expected_result);
        builder.assert_ext_eq(recursive_jagged_evaluation, expected_result);
        builder.cycle_tracker_v2_exit();

        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();
        let program = compiler.compile_inner(block).validate().unwrap();

        let mut witness_stream = Vec::new();
        Witnessable::<AsmConfig>::write(&verifier_params, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&z_row, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&z_col, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&z_trace, &mut witness_stream);

        let mut executor =
            Executor::<F, EF, SP1DiffusionMatrix>::new(Arc::new(program), inner_perm());
        executor.witness_stream = witness_stream.into();
        if should_succeed {
            executor.run().unwrap();
        } else {
            executor.run().expect_err("invalid proof should not be verified");
        }
    }

    fn sumcheck_jagged_eval(
        prover_params: &JaggedLittlePolynomialProverParams,
        verifier_params: &JaggedLittlePolynomialVerifierParams<F>,
        z_row: &Point<EF>,
        z_col: &Point<EF>,
        z_trace: &Point<EF>,
        expected_result: EF,
        should_succeed: bool,
    ) -> Vec<Felt<F>> {
        let prover =
            JaggedEvalSumcheckProver::<F, EF, <SP1GlobalContext as IopCtx>::Challenger>::default();
        let default_perm = inner_perm();
        let mut challenger =
            DuplexChallenger::<SP1Field, SP1Perm, 16, 8>::new(default_perm.clone());
        let jagged_eval_proof =
            prover.prove_jagged_evaluation(prover_params, z_row, z_col, z_trace, &mut challenger);

        let mut builder = AsmBuilder::default();
        builder.cycle_tracker_v2_enter("sumcheck-jagged-eval");
        let verifier_params_variable = verifier_params.read(&mut builder);
        let z_row_variable = z_row.read(&mut builder);
        let z_col_variable = z_col.read(&mut builder);
        let z_trace_variable = z_trace.read(&mut builder);
        let jagged_eval_proof_variable = jagged_eval_proof.read(&mut builder);
        let recursive_jagged_evaluator = RecursiveJaggedEvalSumcheckConfig::<SC>(PhantomData);
        let mut challenger_variable = DuplexChallengerVariable::new(&mut builder);
        let (recursive_jagged_evaluation, prefix_sum_felts) =
            <RecursiveJaggedEvalSumcheckConfig<SC> as RecursiveJaggedEvalConfig<
                C,
                <SC as SP1FieldConfigVariable<C>>::FriChallengerVariable,
            >>::jagged_evaluation(
                &recursive_jagged_evaluator,
                &mut builder,
                &verifier_params_variable,
                JaggedEvalPoints {
                    z_row: z_row_variable,
                    z_col: z_col_variable,
                    z_trace: z_trace_variable,
                },
                &jagged_eval_proof_variable,
                &mut challenger_variable,
            );
        let recursive_jagged_evaluation: Ext<F, EF> = builder.eval(recursive_jagged_evaluation);
        let expected_result: Ext<F, EF> = builder.constant(expected_result);
        builder.assert_ext_eq(recursive_jagged_evaluation, expected_result);
        builder.cycle_tracker_v2_exit();

        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();
        let program = compiler.compile_inner(block).validate().unwrap();

        let mut witness_stream = Vec::new();
        Witnessable::<AsmConfig>::write(&verifier_params, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&z_row, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&z_col, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&z_trace, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&jagged_eval_proof, &mut witness_stream);
        let mut executor =
            Executor::<F, EF, SP1DiffusionMatrix>::new(Arc::new(program), inner_perm());
        executor.witness_stream = witness_stream.into();
        if should_succeed {
            executor.run().unwrap();
        } else {
            executor.run().expect_err("invalid proof should not be verified");
        }
        prefix_sum_felts
    }

    #[test]
    fn test_jagged_eval_proof() {
        setup_logger();
        let row_counts = [12, 1, 2, 1, 17, 0];

        let mut prefix_sums = row_counts
            .iter()
            .scan(0, |state, row_count| {
                let result = *state;
                *state += row_count;
                Some(result)
            })
            .collect::<Vec<_>>();
        prefix_sums.push(*prefix_sums.last().unwrap() + row_counts.last().unwrap());

        let mut rng = thread_rng();

        let log_m = log2_ceil_usize(*prefix_sums.last().unwrap());

        let log_max_row_count = 7;

        let prover_params =
            JaggedLittlePolynomialProverParams::new(row_counts.to_vec(), log_max_row_count);

        let verifier_params: JaggedLittlePolynomialVerifierParams<F> =
            prover_params.clone().into_verifier_params();

        let z_row: Point<EF> = (0..log_max_row_count).map(|_| rng.gen::<EF>()).collect();
        let z_col: Point<EF> =
            (0..log2_ceil_usize(row_counts.len())).map(|_| rng.gen::<EF>()).collect();
        let z_trace: Point<EF> = (0..log_m + 1).map(|_| rng.gen::<EF>()).collect();

        let expected_result =
            verifier_params.full_jagged_little_polynomial_evaluation(&z_row, &z_col, &z_trace);

        trivial_jagged_eval(&verifier_params, &z_row, &z_col, &z_trace, expected_result, true);
        sumcheck_jagged_eval(
            &prover_params,
            &verifier_params,
            &z_row,
            &z_col,
            &z_trace,
            expected_result,
            true,
        );

        // Test the invalid cases.
        let mut z_row_invalid = z_row.clone();
        let first_element = z_row_invalid.get_mut(0).unwrap();
        *first_element += EF::one();
        trivial_jagged_eval(
            &verifier_params,
            &z_row_invalid,
            &z_col,
            &z_trace,
            expected_result,
            false,
        );
        sumcheck_jagged_eval(
            &prover_params,
            &verifier_params,
            &z_row_invalid,
            &z_col,
            &z_trace,
            expected_result,
            false,
        );
    }
}
