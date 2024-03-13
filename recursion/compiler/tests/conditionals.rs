use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::runtime::Runtime;

#[test]
fn test_compiler_conditionals() {
    let mut builder = VmBuilder::<BabyBear>::default();

    let a: Var<_> = builder.eval(BabyBear::zero());
    let b: Var<_> = builder.eval(BabyBear::one());
    let c: Var<_> = builder.eval(BabyBear::zero());

    builder
        .if_ne(a, b)
        .then(|builder| builder.assign(c, BabyBear::two()));

    let code = builder.compile_to_asm();
    println!("{}", code);
    // let program = builder.compile();
    let program = code.machine_code();

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;

    let mut runtime = Runtime::<F>::new(&program);
    runtime.run();
}
