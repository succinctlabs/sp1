use p3_field::AbstractField;
use rand::{thread_rng, Rng};
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
    let mut rng = thread_rng();

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
    let mut var_array = builder.array::<Var<_>, _>(dyn_len);
    let mut felt_array = builder.array::<Felt<_>, _>(dyn_len);
    let mut ext_array = builder.array::<Ext<_, _>, _>(dyn_len);
    // Put values statically
    let var_vals = (0..len).map(|_| rng.gen::<F>()).collect::<Vec<_>>();
    let felt_vals = (0..len).map(|_| rng.gen::<F>()).collect::<Vec<_>>();
    let ext_vals = (0..len).map(|_| rng.gen::<EF>()).collect::<Vec<_>>();
    for i in 0..len {
        builder.set(&mut var_array, i, var_vals[i]);
        builder.set(&mut felt_array, i, felt_vals[i]);
        builder.set(&mut ext_array, i, ext_vals[i]);
    }
    // Assert values set.
    for i in 0..len {
        let var_value = builder.get(&var_array, i);
        builder.assert_var_eq(var_value, var_vals[i]);
        let felt_value = builder.get(&felt_array, i);
        builder.assert_felt_eq(felt_value, felt_vals[i]);
        let ext_value = builder.get(&ext_array, i);
        builder.assert_ext_eq(ext_value, ext_vals[i]);
    }

    // Put values dynamically
    builder.range(0, dyn_len).for_each(|i, builder| {
        builder.set(&mut var_array, i, i * F::two());
        builder.set(&mut felt_array, i, F::from_canonical_u32(3));
        builder.set(&mut ext_array, i, EF::from_canonical_u32(4));
    });

    // Assert values set.
    builder.range(0, dyn_len).for_each(|i, builder| {
        let var_value = builder.get(&var_array, i);
        builder.assert_var_eq(var_value, i * F::two());
        let felt_value = builder.get(&felt_array, i);
        builder.assert_felt_eq(felt_value, F::from_canonical_u32(3));
        let ext_value = builder.get(&ext_array, i);
        builder.assert_ext_eq(ext_value, EF::from_canonical_u32(4));
    });

    let code = builder.compile_to_asm();
    println!("{code}");

    let program = code.machine_code();

    let mut runtime = Runtime::<F, EF>::new(&program);
    runtime.run();
}
