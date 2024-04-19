use p3_field::AbstractField;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::AsmBuilder;
use sp1_recursion_core::runtime::Runtime;

#[test]
fn test_io() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    let mut builder = AsmBuilder::<F, EF>::default();

    let arr = builder.hint_vars();
    builder.range(0, arr.len()).for_each(|i, builder| {
        let el = builder.get(&arr, i);
        builder.print_v(el);
    });

    let arr = builder.hint_felts();
    builder.range(0, arr.len()).for_each(|i, builder| {
        let el = builder.get(&arr, i);
        builder.print_f(el);
    });

    let arr = builder.hint_exts();
    builder.range(0, arr.len()).for_each(|i, builder| {
        let el = builder.get(&arr, i);
        builder.print_e(el);
    });

    let program = builder.compile_program();

    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.witness_stream = vec![
        vec![F::zero().into(), F::zero().into(), F::one().into()],
        vec![F::zero().into(), F::zero().into(), F::two().into()],
        vec![F::one().into(), F::one().into(), F::two().into()],
    ]
    .into();
    runtime.run();
}
