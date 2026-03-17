use std::marker::PhantomData;

use rayon::ThreadPoolBuilder;
use slop_jagged::{
    interleave_prefix_sums, BranchingProgram, JaggedLittlePolynomialVerifierParams,
    JaggedSumcheckEvalProof,
};
use slop_multilinear::{Mle, Point};
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

pub trait RecursiveJaggedEvalConfig<C: CircuitConfig, Chal>: Sized {
    type JaggedEvalProof;

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn jagged_evaluation(
        &self,
        builder: &mut Builder<C>,
        params: &JaggedLittlePolynomialVerifierParams<Felt<SP1Field>>,
        z_row: Point<Ext<SP1Field, SP1ExtensionField>>,
        z_col: Point<Ext<SP1Field, SP1ExtensionField>>,
        z_trace: Point<Ext<SP1Field, SP1ExtensionField>>,
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
        z_row: Point<Ext<SP1Field, SP1ExtensionField>>,
        z_col: Point<Ext<SP1Field, SP1ExtensionField>>,
        z_trace: Point<Ext<SP1Field, SP1ExtensionField>>,
        _proof: &Self::JaggedEvalProof,
        _challenger: &mut (),
    ) -> (SymbolicExt<SP1Field, SP1ExtensionField>, Vec<Felt<SP1Field>>) {
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
        z_row: Point<Ext<SP1Field, SP1ExtensionField>>,
        z_col: Point<Ext<SP1Field, SP1ExtensionField>>,
        z_trace: Point<Ext<SP1Field, SP1ExtensionField>>,
        proof: &Self::JaggedEvalProof,
        challenger: &mut SC::FriChallengerVariable,
    ) -> (SymbolicExt<SP1Field, SP1ExtensionField>, Vec<Felt<SP1Field>>) {
        let z_row =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(&z_row);
        let z_col =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(&z_col);
        let z_trace =
            <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(&z_trace);

        let JaggedSumcheckEvalProof { partial_sumcheck_proof } = proof;
        // Calculate the partial lagrange from z_col point.
        let z_col_partial_lagrange = Mle::blocking_partial_lagrange(&z_col);
        let z_col_partial_lagrange = z_col_partial_lagrange.guts().as_slice();

        // Calculate the jagged eval from the branching program eval claims.
        let jagged_eval = partial_sumcheck_proof.claimed_sum;

        challenger.observe_ext_element(builder, jagged_eval);

        builder.assert_ext_eq(jagged_eval, partial_sumcheck_proof.claimed_sum);

        // Verify the jagged eval proof.
        builder.cycle_tracker_v2_enter("jagged eval - verify sumcheck");
        verify_sumcheck::<C, SC>(builder, challenger, partial_sumcheck_proof);
        builder.cycle_tracker_v2_exit();
        let proof_point = <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(
            &partial_sumcheck_proof.point_and_eval.0,
        );

        // Compute the jagged eval sc expected eval and assert it matches the proof's eval.
        let current_column_prefix_sums = params.col_prefix_sums.iter();
        let next_column_prefix_sums = params.col_prefix_sums.iter().skip(1);
        let mut prefix_sum_felts = Vec::new();
        builder.cycle_tracker_v2_enter("jagged eval - calculate expected eval");
        let mut jagged_eval_sc_expected_eval = current_column_prefix_sums
            .zip(next_column_prefix_sums)
            .zip(z_col_partial_lagrange.iter())
            .map(|((current_column_prefix_sum, next_column_prefix_sum), z_col_eq_val)| {
                assert!(current_column_prefix_sum.dimension() <= 30);
                assert!(next_column_prefix_sum.dimension() <= 30);

                let merged_prefix_sum =
                    interleave_prefix_sums(current_column_prefix_sum, next_column_prefix_sum);

                let (full_lagrange_eval, felt) = C::prefix_sum_checks(
                    builder,
                    merged_prefix_sum.to_vec(),
                    partial_sumcheck_proof.point_and_eval.0.to_vec(),
                );
                prefix_sum_felts.push(felt);
                *z_col_eq_val * full_lagrange_eval
            })
            .sum::<SymbolicExt<SP1Field, SP1ExtensionField>>();
        builder.cycle_tracker_v2_exit();
        let branching_program = BranchingProgram::new(z_row.clone(), z_trace.clone());
        jagged_eval_sc_expected_eval *= branching_program.eval_interleaved(&proof_point);

        builder
            .assert_ext_eq(jagged_eval_sc_expected_eval, partial_sumcheck_proof.point_and_eval.1);

        (jagged_eval.into(), prefix_sum_felts)
    }
}

#[cfg(test)]
mod tests {
    use std::{marker::PhantomData, sync::Arc};

    use rand::{thread_rng, Rng};
    use slop_algebra::{extension::BinomialExtensionField, AbstractField};
    use slop_alloc::CpuBackend;
    use slop_challenger::{DuplexChallenger, IopCtx};
    use slop_jagged::{
        JaggedAssistSumAsPolyCPUImpl, JaggedEvalProver, JaggedEvalSumcheckProver,
        JaggedLittlePolynomialProverParams, JaggedLittlePolynomialVerifierParams,
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
            RecursiveJaggedEvalConfig, RecursiveJaggedEvalSumcheckConfig,
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
            z_row_variable,
            z_col_variable,
            z_trace_variable,
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
        let prover = JaggedEvalSumcheckProver::<
            F,
            JaggedAssistSumAsPolyCPUImpl<_, _, _>,
            CpuBackend,
            <SP1GlobalContext as IopCtx>::Challenger,
        >::default();
        let default_perm = inner_perm();
        let mut challenger =
            DuplexChallenger::<SP1Field, SP1Perm, 16, 8>::new(default_perm.clone());
        let jagged_eval_proof = prover.prove_jagged_evaluation(
            prover_params,
            z_row,
            z_col,
            z_trace,
            &mut challenger,
            CpuBackend,
        );

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
                z_row_variable,
                z_col_variable,
                z_trace_variable,
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
