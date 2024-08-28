use p3_baby_bear::BabyBear;
use p3_field::{extension::BinomialExtensionField, AbstractField};
use sp1_recursion_compiler::{asm::AsmBuilder, ir::Var};
use sp1_recursion_core::runtime::Runtime;
use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;

#[test]
fn test_compiler_conditionals() {
    type SC = BabyBearPoseidon2;
    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
    let mut builder = AsmBuilder::<F, EF>::default();

    let zero: Var<_> = builder.eval(F::zero());
    let one: Var<_> = builder.eval(F::one());
    let two: Var<_> = builder.eval(F::two());
    let three: Var<_> = builder.eval(F::from_canonical_u32(3));
    let four: Var<_> = builder.eval(F::from_canonical_u32(4));

    let c: Var<_> = builder.eval(F::zero());
    builder.if_eq(zero, zero).then(|builder| {
        builder.if_eq(one, one).then(|builder| {
            builder.if_eq(two, two).then(|builder| {
                builder.if_eq(three, three).then(|builder| {
                    builder.if_eq(four, four).then(|builder| builder.assign(c, F::one()))
                })
            })
        })
    });
    builder.assert_var_eq(c, F::one());

    let c: Var<_> = builder.eval(F::zero());
    builder.if_eq(zero, one).then_or_else(
        |builder| {
            builder
                .if_eq(one, one)
                .then(|builder| builder.if_eq(two, two).then(|builder| builder.assign(c, F::one())))
        },
        |builder| {
            builder.if_ne(three, four).then_or_else(|_| {}, |builder| builder.assign(c, F::zero()))
        },
    );
    builder.assert_var_eq(c, F::zero());

    let code = builder.compile_asm();
    println!("{}", code);
    // let program = builder.compile();
    let program = code.machine_code();

    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run().unwrap();
}

#[test]
fn test_compiler_conditionals_v2() {
    type SC = BabyBearPoseidon2;
    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
    let mut builder = AsmBuilder::<F, EF>::default();

    let zero: Var<_> = builder.eval(F::zero());
    let one: Var<_> = builder.eval(F::one());
    let two: Var<_> = builder.eval(F::two());
    let three: Var<_> = builder.eval(F::from_canonical_u32(3));
    let four: Var<_> = builder.eval(F::from_canonical_u32(4));

    let c: Var<_> = builder.eval(F::zero());
    builder.if_eq(zero, zero).then(|builder| {
        builder.if_eq(one, one).then(|builder| {
            builder.if_eq(two, two).then(|builder| {
                builder.if_eq(three, three).then(|builder| {
                    builder.if_eq(four, four).then(|builder| builder.assign(c, F::one()))
                })
            })
        })
    });

    let code = builder.compile_asm();
    println!("{}", code);
    // let program = builder.compile();
    let program = code.machine_code();

    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run().unwrap();
}
