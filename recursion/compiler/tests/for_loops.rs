use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::runtime::Runtime;

#[test]
fn test_compiler_for_loops() {
    let mut builder = VmBuilder::<BabyBear>::default();

    let n_val = BabyBear::from_canonical_u32(10);
    let m_val = BabyBear::from_canonical_u32(5);

    let zero: Var<_> = builder.eval(BabyBear::zero());
    let n: Var<_> = builder.eval(n_val);
    let m: Var<_> = builder.eval(m_val);

    let i_counter: Var<_> = builder.eval(BabyBear::zero());
    let total_counter: Var<_> = builder.eval(BabyBear::zero());
    builder.range(zero, n).for_each(|_, builder| {
        builder.assign(i_counter, i_counter + BabyBear::one());

        let j_counter: Var<_> = builder.eval(BabyBear::zero());
        builder.range(zero, m).for_each(|_, builder| {
            builder.assign(total_counter, total_counter + BabyBear::one());
            builder.assign(j_counter, j_counter + BabyBear::one());
        });
        // Assert that the inner loop ran m times, in two different ways.
        builder.assert_var_eq(j_counter, m_val);
        builder.assert_var_eq(j_counter, m);
    });
    // Assert that the outer loop ran n times, in two different ways.
    builder.assert_var_eq(i_counter, n_val);
    builder.assert_var_eq(i_counter, n);
    // Assert that the total counter is equal to n * m, in two ways.
    builder.assert_var_eq(total_counter, n_val * m_val);
    builder.assert_var_eq(total_counter, n * m);

    let program = builder.compile();

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    let mut runtime = Runtime::<F, EF>::new(&program);
    runtime.run();
}
