use p3_field::AbstractField;
use rand::{thread_rng, Rng};
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::runtime::Runtime;

#[test]
fn test_compiler_arithmetic() {
    let num_tests = 3;
    let mut rng = thread_rng();
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    let mut builder = VmBuilder::<F>::default();

    let zero: Felt<_> = builder.eval(F::zero());
    let one: Felt<_> = builder.eval(F::one());

    builder.assert_felt_eq(zero * one, F::zero());
    builder.assert_felt_eq(one * one, F::one());
    builder.assert_felt_eq(one + one, F::two());

    let zero_ext: Ext<_> = builder.eval(EF::zero());
    let one_ext: Ext<_> = builder.eval(EF::one());

    builder.assert_ext_eq(zero_ext * one_ext, EF::zero());
    builder.assert_ext_eq(one_ext * one_ext, EF::one());
    builder.assert_ext_eq(one_ext + one_ext, EF::two());
    builder.assert_ext_eq(one_ext - one_ext, EF::zero());

    for _ in 0..num_tests {
        let a_val = rng.gen::<F>();
        let b_val = rng.gen::<F>();
        let a: Felt<_> = builder.eval(a_val);
        let b: Felt<_> = builder.eval(b_val);
        builder.assert_felt_eq(a + b, a_val + b_val);
        builder.assert_felt_eq(a * b, a_val * b_val);
        builder.assert_felt_eq(a - b, a_val - b_val);
        builder.assert_felt_eq(a / b, a_val / b_val);

        let a_ext_val = rng.gen::<EF>();
        let b_ext_val = rng.gen::<EF>();
        let a_ext: Ext<_> = builder.eval(a_ext_val);
        let b_ext: Ext<_> = builder.eval(b_ext_val);
        builder.assert_ext_eq(a_ext + b_ext, a_ext_val + b_ext_val);
        builder.assert_ext_eq(a_ext * b_ext, a_ext_val * b_ext_val);
        builder.assert_ext_eq(a_ext - b_ext, a_ext_val - b_ext_val);
        builder.assert_ext_eq(a_ext / b_ext, a_ext_val / b_ext_val);
    }

    let program = builder.compile();

    let mut runtime = Runtime::<F, EF>::new(&program);
    runtime.run();
}
