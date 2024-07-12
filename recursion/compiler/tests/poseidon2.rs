use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_symmetric::Permutation;
use rand::thread_rng;
use rand::Rng;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::setup_logger;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::AsmBuilder;
use sp1_recursion_compiler::ir::Array;
use sp1_recursion_compiler::ir::Var;
use sp1_recursion_core::runtime::Runtime;
use sp1_recursion_core::runtime::PERMUTATION_WIDTH;

#[test]
fn test_compiler_poseidon2_permute() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    let mut rng = thread_rng();

    let config = SC::default();
    let perm = &config.perm;

    let mut builder = AsmBuilder::<F, EF>::default();

    let random_state_vals: [F; PERMUTATION_WIDTH] = rng.gen();
    // Execute the reference permutation
    let expected_result = perm.permute(random_state_vals);

    // Execture the permutation in the VM
    // Initialize an array and populate it with the entries.
    let var_width: Var<F> = builder.eval(F::from_canonical_usize(PERMUTATION_WIDTH));
    let mut random_state = builder.array(var_width);
    for (i, val) in random_state_vals.iter().enumerate() {
        builder.set(&mut random_state, i, *val);
    }

    // Assert that the values are set correctly.
    for (i, val) in random_state_vals.iter().enumerate() {
        let res = builder.get(&random_state, i);
        builder.assert_felt_eq(res, *val);
    }

    let result = builder.poseidon2_permute(&random_state);

    assert!(matches!(result, Array::Dyn(_, _)));

    // Assert that the result is equal to the expected result.
    for (i, val) in expected_result.iter().enumerate() {
        let res = builder.get(&result, i);
        builder.assert_felt_eq(res, *val);
    }

    let program = builder.compile_program();

    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run().unwrap();
    println!(
        "The program executed successfully, number of cycles: {}",
        runtime.clk.as_canonical_u32() / 4
    );
}

#[test]
fn test_compiler_poseidon2_hash() {
    setup_logger();
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    let mut rng = thread_rng();

    let config = SC::default();

    let mut builder = AsmBuilder::<F, EF>::default();

    let random_state_vals_1: [F; 42] = rng.gen();
    println!("{:?}", random_state_vals_1);
    let random_state_vals_2: [F; 42] = rng.gen();
    println!("{:?}", random_state_vals_2);

    let mut random_state_v1 =
        builder.dyn_array(random_state_vals_1.len() + random_state_vals_2.len());
    for (i, val) in random_state_vals_1.iter().enumerate() {
        builder.set(&mut random_state_v1, i, *val);
    }
    for (i, val) in random_state_vals_2.iter().enumerate() {
        builder.set(&mut random_state_v1, i + random_state_vals_1.len(), *val);
    }

    let mut random_state_v2_1 = builder.dyn_array(random_state_vals_1.len());
    for (i, val) in random_state_vals_1.iter().enumerate() {
        builder.set(&mut random_state_v2_1, i, *val);
    }
    let mut random_state_v2_2 = builder.dyn_array(random_state_vals_2.len());
    for (i, val) in random_state_vals_2.iter().enumerate() {
        builder.set(&mut random_state_v2_2, i, *val);
    }

    let mut nested_random_state = builder.dyn_array(2);
    builder.set(&mut nested_random_state, 0, random_state_v2_1.clone());
    builder.set(&mut nested_random_state, 1, random_state_v2_2.clone());

    let result = builder.poseidon2_hash(&random_state_v1);
    let result_x = builder.poseidon2_hash_x(&nested_random_state);

    builder.range(0, result.len()).for_each(|i, builder| {
        let el = builder.get(&result, i);
        let el_x = builder.get(&result_x, i);
        builder.assert_felt_eq(el, el_x);
    });

    let program = builder.compile_program();

    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run().unwrap();
    println!(
        "The program executed successfully, number of cycles: {}",
        runtime.clk.as_canonical_u32() / 4
    );
    runtime.print_stats();
}

#[test]
fn test_compiler_poseidon2_hash_v2() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    let mut rng = thread_rng();

    let config = SC::default();

    let mut builder = AsmBuilder::<F, EF>::default();

    let random_state_vals: [F; 2] = rng.gen();

    let mut random_state = builder.dyn_array(PERMUTATION_WIDTH);
    for (i, val) in random_state_vals.iter().enumerate() {
        builder.set(&mut random_state, i, *val);
    }

    let idx: Var<_> = builder.eval(F::zero());
    builder.if_eq(idx, F::zero()).then(|builder| {
        let element = builder.get(&random_state, idx);
        builder.print_f(element);
    });

    let program = builder.compile_program();

    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run().unwrap();
    println!(
        "The program executed successfully, number of cycles: {}",
        runtime.clk.as_canonical_u32() / 4
    );
}
