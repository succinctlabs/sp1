use p3_field::AbstractField;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::runtime::Runtime;

#[test]
fn test_compiler_array() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    let mut builder = VmBuilder::<F, EF>::default();

    // Sum all the values of an array.
    let len: usize = 2;

    let mut static_array = builder.array::<Var<_>, _>(len);

    // Put values statically
    for i in 0..len {
        builder.set(&mut static_array, i, F::one());
    }
    // Assert values set.
    for i in 0..len {
        let value = builder.get(&static_array, i);
        builder.assert_var_eq(value, F::one());
    }

    let dyn_len: Var<_> = builder.eval(F::from_canonical_usize(len));
    let mut array = builder.array::<Ext<_, _>, _>(dyn_len);
    // Put values statically
    for i in 0..len {
        builder.set(&mut array, i, EF::one());
    }
    // Assert values set.
    for i in 0..len {
        let value = builder.get(&array, i);
        builder.assert_ext_eq(value, EF::one());
    }

    let code = builder.compile_to_asm();
    println!("{code}");

    let program = code.machine_code();

    let mut runtime = Runtime::<F, EF>::new(&program);
    runtime.run();
}
