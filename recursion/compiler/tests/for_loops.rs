use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::runtime::Runtime;

#[test]
fn test_compiler_for_loops() {
    let mut builder = AsmBuilder::<BabyBear>::new();

    let n_val = BabyBear::from_canonical_u32(10);
    let m_val = BabyBear::from_canonical_u32(5);

    let zero: Felt<_> = builder.constant(BabyBear::zero());
    let n: Felt<_> = builder.constant(n_val);
    let m: Felt<_> = builder.constant(m_val);

    let i_counter: Felt<_> = builder.constant(BabyBear::zero());
    let total_counter: Felt<_> = builder.constant(BabyBear::zero());
    builder.iter(zero..n).for_each(|_, builder| {
        builder.assign(i_counter, i_counter + BabyBear::one());

        let j_counter: Felt<_> = builder.constant(BabyBear::zero());
        builder.iter(zero..m).for_each(|_, builder| {
            builder.assign(total_counter, total_counter + BabyBear::one());
            builder.assign(j_counter, j_counter + BabyBear::one());
        });
        // Assert that the inner loop ran m times, in two different ways.
        builder.assert_eq(j_counter, m_val);
        builder.assert_eq(j_counter, m);
    });
    // Assert that the outer loop ran n times, in two different ways.
    builder.assert_eq(i_counter, n_val);
    builder.assert_eq(i_counter, n);
    // Assert that the total counter is equal to n * m, in two ways.
    builder.assert_eq(total_counter, n_val * m_val);
    builder.assert_eq(total_counter, n * m);

    let program = builder.compile();

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;

    let mut runtime = Runtime::<F>::new(&program);
    runtime.run();
}
