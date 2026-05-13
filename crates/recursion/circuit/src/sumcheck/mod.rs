pub mod witness;

use crate::{
    challenger::{CanObserveVariable, FieldChallengerVariable},
    symbolic::IntoSymbolic,
    CircuitConfig, SP1FieldConfigVariable,
};
use slop_algebra::{AbstractField, UnivariatePolynomial};
use slop_alloc::{buffer, Buffer};
use slop_multilinear::{partial_lagrange_blocking, Mle, MleEval, Point};
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::{Dimensions, Tensor};
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::{
    ir::Felt,
    prelude::{Builder, Ext, SymbolicExt},
};

pub fn evaluate_mle_ext_batch<C: CircuitConfig>(
    builder: &mut Builder<C>,
    mles: Vec<Mle<Ext<SP1Field, SP1ExtensionField>>>,
    point: Point<Ext<SP1Field, SP1ExtensionField>>,
) -> Vec<MleEval<Ext<SP1Field, SP1ExtensionField>>> {
    let point_symbolic =
        <Point<Ext<SP1Field, SP1ExtensionField>> as IntoSymbolic<C>>::as_symbolic(&point);
    let partial_lagrange = partial_lagrange_blocking(&point_symbolic);
    let mut result = Vec::new();
    // TODO: use builder par iter collect.
    for mle in &mles {
        let mle = mle.guts();
        let mut sizes = mle.sizes().to_vec();
        sizes.remove(0);
        let dimensions = Dimensions::try_from(sizes).unwrap();
        let mut dst = Tensor { storage: buffer![], dimensions };
        let total_len = dst.total_len();
        let dot_products = mle
            .as_buffer()
            .chunks_exact(mle.strides()[0])
            .zip(partial_lagrange.as_buffer().iter())
            .map(|(chunk, scalar)| chunk.iter().map(|a| *scalar * *a).collect())
            .fold(
                vec![SymbolicExt::<SP1Field, SP1ExtensionField>::zero(); total_len],
                |mut a, b: Vec<SymbolicExt<_, _>>| {
                    a.iter_mut().zip(b.iter()).for_each(|(a, b)| *a += *b);
                    a
                },
            );
        let dot_products = dot_products.into_iter().map(|x| builder.eval(x)).collect::<Buffer<_>>();
        dst.storage = dot_products;
        result.push(MleEval::new(dst));
    }

    result
}

pub fn evaluate_mle_ext<C: CircuitConfig>(
    builder: &mut Builder<C>,
    mle: Mle<Ext<SP1Field, SP1ExtensionField>>,
    point: Point<Ext<SP1Field, SP1ExtensionField>>,
) -> MleEval<Ext<SP1Field, SP1ExtensionField>> {
    evaluate_mle_ext_batch(builder, vec![mle], point).pop().unwrap()
}

pub fn verify_sumcheck<C: CircuitConfig, SC: SP1FieldConfigVariable<C>>(
    builder: &mut Builder<C>,
    challenger: &mut SC::FriChallengerVariable,
    proof: &PartialSumcheckProof<Ext<SP1Field, SP1ExtensionField>>,
) {
    let num_variables = proof.univariate_polys.len();
    let mut alpha_point: Point<SymbolicExt<SP1Field, SP1ExtensionField>> = Point::default();

    assert_eq!(num_variables, proof.point_and_eval.0.dimension());

    let first_poly = proof.univariate_polys[0].clone();
    let first_poly_symbolic: UnivariatePolynomial<SymbolicExt<SP1Field, SP1ExtensionField>> =
        UnivariatePolynomial {
            coefficients: first_poly
                .coefficients
                .clone()
                .into_iter()
                .map(|c| c.into())
                .collect::<Vec<_>>(),
        };
    builder.assert_ext_eq(first_poly_symbolic.eval_one_plus_eval_zero(), proof.claimed_sum);

    let coeffs: Vec<Felt<SP1Field>> =
        first_poly.coefficients.iter().flat_map(|x| C::ext2felt(builder, *x)).collect::<Vec<_>>();

    challenger.observe_slice(builder, coeffs);

    let mut previous_poly = first_poly_symbolic;
    for poly in proof.univariate_polys.iter().skip(1) {
        let alpha = challenger.sample_ext(builder);
        alpha_point.add_dimension(alpha.into());
        let poly_symbolic: UnivariatePolynomial<SymbolicExt<SP1Field, SP1ExtensionField>> =
            UnivariatePolynomial {
                coefficients: poly
                    .coefficients
                    .clone()
                    .into_iter()
                    .map(|c| c.into())
                    .collect::<Vec<_>>(),
            };
        let expected_eval = previous_poly.eval_at_point(alpha.into());
        builder.assert_ext_eq(expected_eval, poly_symbolic.eval_one_plus_eval_zero());

        let coeffs: Vec<Felt<SP1Field>> =
            poly.coefficients.iter().flat_map(|x| C::ext2felt(builder, *x)).collect::<Vec<_>>();
        challenger.observe_slice(builder, coeffs);
        previous_poly = poly_symbolic;
    }

    let alpha = challenger.sample_ext(builder);
    alpha_point.add_dimension(alpha.into());

    alpha_point.iter().zip(proof.point_and_eval.0.iter()).for_each(|(d, p)| {
        builder.assert_ext_eq(*d, *p);
    });

    builder.assert_ext_eq(previous_poly.eval_at_point(alpha.into()), proof.point_and_eval.1);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{challenger::DuplexChallengerVariable, witness::Witnessable};
    use rand::{rngs::OsRng, thread_rng};
    use slop_algebra::{extension::BinomialExtensionField, AbstractExtensionField, AbstractField};
    use slop_challenger::DuplexChallenger;
    use slop_multilinear::{full_geq, Mle};
    use slop_sumcheck::reduce_sumcheck_to_evaluation;
    use sp1_hypercube::inner_perm;
    use sp1_primitives::{SP1DiffusionMatrix, SP1GlobalContext};
    use sp1_recursion_compiler::{
        circuit::{AsmBuilder, AsmCompiler, AsmConfig, CircuitV2Builder},
        config::InnerConfig,
        ir::{Builder, Ext, SymbolicExt},
    };
    use sp1_recursion_executor::Executor;

    use sp1_primitives::{SP1Field, SP1Perm};
    type F = SP1Field;
    type SC = SP1GlobalContext;
    type C = InnerConfig;
    type EF = BinomialExtensionField<SP1Field, 4>;

    #[test]
    fn test_sumcheck() {
        let mut rng = thread_rng();

        let mle = Mle::<SP1Field>::rand(&mut rng, 1, 10);

        let default_perm = inner_perm();
        let mut challenger =
            DuplexChallenger::<SP1Field, SP1Perm, 16, 8>::new(default_perm.clone());

        let claim = EF::from_base(mle.guts().as_slice().iter().copied().sum::<SP1Field>());

        let (sumcheck_proof, _) = reduce_sumcheck_to_evaluation::<SP1Field, EF, _>(
            vec![mle.clone()],
            &mut challenger,
            vec![claim],
            1,
            EF::one(),
        );

        let (point, eval_claim) = sumcheck_proof.point_and_eval.clone();
        let evaluation = mle.eval_at(&point)[0];
        assert_eq!(evaluation, eval_claim);

        let mut builder = Builder::<C>::default();

        let sumcheck_proof_variable = sumcheck_proof.read(&mut builder);

        let mut challenger_variable = DuplexChallengerVariable::new(&mut builder);
        verify_sumcheck::<C, SC>(&mut builder, &mut challenger_variable, &sumcheck_proof_variable);

        let mut witness_stream = Vec::new();
        Witnessable::<AsmConfig>::write(&sumcheck_proof, &mut witness_stream);

        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
        let mut executor = Executor::<F, EF, SP1DiffusionMatrix>::new(program, inner_perm());
        executor.witness_stream = witness_stream.into();
        executor.run().unwrap();
    }

    #[test]
    fn test_sumcheck_failure() {
        let mut rng = thread_rng();

        let mle = Mle::<SP1Field>::rand(&mut rng, 1, 10);

        let default_perm = inner_perm();
        let mut challenger =
            DuplexChallenger::<SP1Field, SP1Perm, 16, 8>::new(default_perm.clone());

        let claim = EF::from_base(mle.guts().as_slice().iter().copied().sum::<SP1Field>());

        let (mut sumcheck_proof, _) = reduce_sumcheck_to_evaluation::<SP1Field, EF, _>(
            vec![mle.clone()],
            &mut challenger,
            vec![claim],
            1,
            EF::one(),
        );

        let (point, eval_claim) = sumcheck_proof.point_and_eval.clone();
        let evaluation = mle.eval_at(&point)[0];
        assert_eq!(evaluation, eval_claim);

        // modify the first polynomial to make the sumcheck fail
        sumcheck_proof.univariate_polys[0].coefficients[0] = EF::one();

        let mut builder = Builder::<C>::default();

        let sumcheck_proof_variable = sumcheck_proof.read(&mut builder);

        let mut challenger_variable = DuplexChallengerVariable::new(&mut builder);
        verify_sumcheck::<C, SC>(&mut builder, &mut challenger_variable, &sumcheck_proof_variable);

        let mut witness_stream = Vec::new();
        Witnessable::<AsmConfig>::write(&sumcheck_proof, &mut witness_stream);

        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
        let mut executor = Executor::<F, EF, SP1DiffusionMatrix>::new(program, inner_perm());
        executor.witness_stream = witness_stream.into();
        executor.run().expect_err("Sumcheck should fail");
    }

    #[test]
    fn test_eval_at_point() {
        let mut rng = OsRng;
        let mut builder = AsmBuilder::default();
        let exts = builder.hint_exts_v2(3);
        let point = builder.hint_ext_v2();
        let univariate_poly =
            UnivariatePolynomial { coefficients: vec![exts[0], exts[1], exts[2]] };
        let univariate_poly_symbolic: UnivariatePolynomial<SymbolicExt<F, EF>> =
            UnivariatePolynomial {
                coefficients: univariate_poly.coefficients.iter().map(|c| (*c).into()).collect(),
            };
        let expected_eval = univariate_poly_symbolic.eval_at_point(point.into());
        builder.assert_ext_eq(expected_eval, exts[0] + exts[1] * point + exts[2] * point * point);

        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
        let mut executor = Executor::<F, EF, SP1DiffusionMatrix>::new(program, inner_perm());
        let coeffs = (0..3).map(|_| rand::Rng::gen::<F>(&mut rng)).collect::<Vec<_>>();
        let point: F = rand::Rng::gen(&mut rng);
        executor.witness_stream =
            [vec![coeffs[0].into(), coeffs[1].into(), coeffs[2].into()], vec![point.into()]]
                .concat()
                .into();
        executor.run().unwrap();
    }

    #[test]
    fn test_eq_eval() {
        let mut builder = AsmBuilder::default();
        let vec_1: Vec<SymbolicExt<F, EF>> =
            builder.hint_exts_v2(2).iter().copied().map(|x| x.into()).collect::<Vec<_>>();
        let vec_2: Vec<SymbolicExt<F, EF>> =
            builder.hint_exts_v2(2).iter().copied().map(|x| x.into()).collect::<Vec<_>>();
        let point_1 = Point::from(vec_1);
        let point_2 = Point::from(vec_2);
        let eq_eval = Mle::full_lagrange_eval(&point_1, &point_2);
        let one: Ext<F, EF> = builder.constant(EF::one());
        builder.assert_ext_eq(eq_eval, one);

        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
        let mut executor = Executor::<F, EF, SP1DiffusionMatrix>::new(program, inner_perm());
        executor.witness_stream =
            [vec![F::zero().into(), F::one().into()], vec![F::zero().into(), F::one().into()]]
                .concat()
                .into();
        executor.run().unwrap();
    }

    #[test]
    fn test_full_geq() {
        let mut builder = AsmBuilder::default();
        let vec_1: Vec<SymbolicExt<F, EF>> =
            builder.hint_exts_v2(2).iter().copied().map(|x| x.into()).collect::<Vec<_>>();
        let vec_2: Vec<SymbolicExt<F, EF>> =
            builder.hint_exts_v2(2).iter().copied().map(|x| x.into()).collect::<Vec<_>>();
        let point_1 = Point::from(vec_1);
        let point_2 = Point::from(vec_2);
        let geq_eval = full_geq(&point_1, &point_2);
        let one: Ext<F, EF> = builder.constant(EF::one());
        builder.assert_ext_eq(geq_eval, one);

        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
        let mut executor = Executor::<F, EF, SP1DiffusionMatrix>::new(program, inner_perm());
        executor.witness_stream =
            [vec![F::zero().into(), F::one().into()], vec![F::one().into(), F::zero().into()]]
                .concat()
                .into();
        executor.run().unwrap();
    }
}
