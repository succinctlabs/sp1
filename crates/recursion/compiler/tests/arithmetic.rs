use rand::{thread_rng, Rng};

use p3_field::AbstractField;
use sp1_recursion_compiler::{
    asm::AsmBuilder,
    ir::{Ext, ExtConst, Felt, SymbolicExt, Var},
};
use sp1_recursion_core::runtime::Runtime;
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

#[test]
fn test_compiler_arithmetic() {
    let num_tests = 3;
    let mut rng = thread_rng();
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    let mut builder = AsmBuilder::<F, EF>::default();

    let zero: Felt<_> = builder.eval(F::zero());
    let one: Felt<_> = builder.eval(F::one());

    builder.assert_felt_eq(zero * one, F::zero());
    builder.assert_felt_eq(one * one, F::one());
    builder.assert_felt_eq(one + one, F::two());

    let zero_ext: Ext<_, _> = builder.eval(EF::zero().cons());
    let one_ext: Ext<_, _> = builder.eval(EF::one().cons());

    builder.assert_ext_eq(zero_ext * one_ext, EF::zero().cons());
    builder.assert_ext_eq(one_ext * one_ext, EF::one().cons());
    builder.assert_ext_eq(one_ext + one_ext, EF::two().cons());
    builder.assert_ext_eq(one_ext - one_ext, EF::zero().cons());

    for _ in 0..num_tests {
        let a_var_val = rng.gen::<F>();
        let b_var_val = rng.gen::<F>();
        let a_var: Var<_> = builder.eval(a_var_val);
        let b_var: Var<_> = builder.eval(b_var_val);
        builder.assert_var_eq(a_var + b_var, a_var_val + b_var_val);
        builder.assert_var_eq(a_var * b_var, a_var_val * b_var_val);
        builder.assert_var_eq(a_var - b_var, a_var_val - b_var_val);
        builder.assert_var_eq(-a_var, -a_var_val);

        let a_felt_val = rng.gen::<F>();
        let b_felt_val = rng.gen::<F>();
        let a: Felt<_> = builder.eval(a_felt_val);
        let b: Felt<_> = builder.eval(b_felt_val);
        builder.assert_felt_eq(a + b, a_felt_val + b_felt_val);
        builder.assert_felt_eq(a + b, a + b_felt_val);
        builder.assert_felt_eq(a * b, a_felt_val * b_felt_val);
        builder.assert_felt_eq(a - b, a_felt_val - b_felt_val);
        builder.assert_felt_eq(a / b, a_felt_val / b_felt_val);
        builder.assert_felt_eq(-a, -a_felt_val);

        let a_ext_val = rng.gen::<EF>();
        let b_ext_val = rng.gen::<EF>();
        let a_ext: Ext<_, _> = builder.eval(a_ext_val.cons());
        let b_ext: Ext<_, _> = builder.eval(b_ext_val.cons());
        builder.assert_ext_eq(a_ext + b_ext, (a_ext_val + b_ext_val).cons());
        builder.assert_ext_eq(
            -a_ext / b_ext + (a_ext * b_ext) * (a_ext * b_ext),
            (-a_ext_val / b_ext_val + (a_ext_val * b_ext_val) * (a_ext_val * b_ext_val)).cons(),
        );
        let mut a_expr = SymbolicExt::from(a_ext);
        let mut a_val = a_ext_val;
        for _ in 0..10 {
            a_expr += b_ext * a_val + EF::one();
            a_val += b_ext_val * a_val + EF::one();
            builder.assert_ext_eq(a_expr.clone(), a_val.cons())
        }
        builder.assert_ext_eq(a_ext * b_ext, (a_ext_val * b_ext_val).cons());
        builder.assert_ext_eq(a_ext - b_ext, (a_ext_val - b_ext_val).cons());
        builder.assert_ext_eq(a_ext / b_ext, (a_ext_val / b_ext_val).cons());
        builder.assert_ext_eq(-a_ext, (-a_ext_val).cons());
    }

    let program = builder.compile_program();

    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run().unwrap();
    runtime.print_stats();
}
