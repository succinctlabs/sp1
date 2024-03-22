use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;
use p3_field::AbstractField;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::runtime::Runtime;

#[test]
fn test_compiler_conditionals() {
    type SC = BabyBearPoseidon2;
    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
    let mut builder = VmBuilder::<F, EF>::default();

    let a: Var<_> = builder.eval(F::zero());
    let b: Var<_> = builder.eval(F::one());
    let c: Var<_> = builder.eval(F::zero());
    let d: Var<_> = builder.eval(F::zero());

    builder
        .if_ne(a, b)
        .then(|builder| builder.assign(c, F::two()));
    builder.assert_var_eq(c, F::two());

    builder.if_ne(a, d).then_or_else(
        |builder| builder.assign(c, F::two() + F::two()),
        |builder| builder.assign(c, F::one()),
    );
    builder.assert_var_eq(c, F::one());

    // Test nested if statements.
    builder.if_ne(a, b).then(|builder| {
        builder.if_ne(a, b).then(|builder| {
            builder.assign(c, F::from_canonical_u32(20));
        });
    });
    builder.assert_var_eq(c, F::from_canonical_u32(20));

    let code = builder.compile_to_asm();
    println!("{}", code);
    // let program = builder.compile();
    let program = code.machine_code();

    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run();
}
