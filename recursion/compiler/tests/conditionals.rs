use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::runtime::Runtime;

#[test]
fn test_compiler_conditionals() {
    let mut builder = AsmBuilder::<BabyBear>::new();
    let p: Bool = builder.constant(true);
    let q: Bool = builder.constant(false);

    let a: Felt<_> = builder.constant(BabyBear::zero());
    let b: Felt<_> = builder.constant(BabyBear::one());

    builder.assert(p);
    builder.assert_not(q);

    builder.assert(p & p);
    builder.assert_not(p & q);
    builder.assert(p | q);
    builder.assert_not(q | q);
    builder.assert(p ^ q);

    builder.assert_ne(a, b);
    builder.assert_eq(b, a + b);

    let code = builder.code();
    println!("{}", code);

    let program = code.machine_code();

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;

    let mut runtime = Runtime::<F>::new(&program);
    runtime.run();
}
