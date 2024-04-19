use rand::{thread_rng, Rng};

use p3_field::AbstractField;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::AsmBuilder;
use sp1_recursion_compiler::ir::ExtConst;
use sp1_recursion_compiler::ir::{Ext, Felt};
use sp1_recursion_core::runtime::Runtime;

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
        let a_val = rng.gen::<F>();
        let b_val = rng.gen::<F>();
        let a: Felt<_> = builder.eval(a_val);
        let b: Felt<_> = builder.eval(b_val);
        builder.assert_felt_eq(a + b, a_val + b_val);
        builder.assert_felt_eq(a + b, a + b_val);
        builder.assert_felt_eq(a * b, a_val * b_val);
        builder.assert_felt_eq(a - b, a_val - b_val);
        builder.assert_felt_eq(a / b, a_val / b_val);

        let a_ext_val = rng.gen::<EF>();
        let b_ext_val = rng.gen::<EF>();
        let a_ext: Ext<_, _> = builder.eval(a_ext_val.cons());
        let b_ext: Ext<_, _> = builder.eval(b_ext_val.cons());
        builder.assert_ext_eq(a_ext + b_ext, (a_ext_val + b_ext_val).cons());
        builder.assert_ext_eq(a_ext * b_ext, (a_ext_val * b_ext_val).cons());
        builder.assert_ext_eq(a_ext - b_ext, (a_ext_val - b_ext_val).cons());
        builder.assert_ext_eq(a_ext / b_ext, (a_ext_val / b_ext_val).cons());
    }

    let program = builder.compile_program();

    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run();
    runtime.print_stats();
}
