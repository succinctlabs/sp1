use p3_field::TwoAdicField;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::runtime::Runtime;

#[test]
fn test_two_adic_generator() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    let mut builder = VmBuilder::<F, EF>::default();

    let g27 = builder.two_adic_generator(Usize::Const(27));
    let g26 = builder.two_adic_generator(Usize::Const(26));
    let g25 = builder.two_adic_generator(Usize::Const(25));

    let gt27: Felt<F> = builder.eval(F::two_adic_generator(27));
    let gt26: Felt<F> = builder.eval(F::two_adic_generator(26));
    let gt25: Felt<F> = builder.eval(F::two_adic_generator(25));

    builder.assert_felt_eq(g27, gt27);
    builder.assert_felt_eq(g26, gt26);
    builder.assert_felt_eq(g25, gt25);

    let code = builder.compile_to_asm();
    let program = code.machine_code();
    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run();
}
