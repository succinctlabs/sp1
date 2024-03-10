use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::runtime::Runtime;

#[test]
fn test_compiler_basic_types() {
    let mut builder = AsmBuilder::<BabyBear>::new();
    let p: Bool = builder.constant(true);
    let q: Bool = builder.constant(false);

    let a: Felt<_> = builder.constant(BabyBear::zero());
    let b: Felt<_> = builder.constant(BabyBear::one());

    let i: Int = builder.constant(0);
    let j: Int = builder.constant(1);
    let k: Int = builder.constant(2);

    builder.assert(p);
    builder.assert_not(q);

    builder.assert(p & p);
    builder.assert_not(p & q);
    builder.assert(p | q);
    builder.assert_not(q | q);
    builder.assert(p ^ q);

    builder.assert_eq(a, BabyBear::zero());
    builder.assert_eq(b, BabyBear::one());
    builder.assert_ne(a, b);
    builder.assert_eq(b, a + b);

    builder.assert_ne(i, j);
    builder.assert_eq(j, i + j);
    builder.assert_eq(j + j, k);

    let program = builder.compile();

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;

    let mut runtime = Runtime::<F>::new(&program);
    runtime.run();
}
