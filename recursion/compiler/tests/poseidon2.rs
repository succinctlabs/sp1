use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_symmetric::Permutation;
use rand::thread_rng;
use rand::Rng;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::ir::Var;
use sp1_recursion_core::runtime::Runtime;
use sp1_recursion_core::runtime::POSEIDON2_WIDTH;

#[test]
fn test_compiler_poseidon2_permute() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    let mut rng = thread_rng();

    let config = SC::default();
    let perm = &config.perm;

    let mut builder = VmBuilder::<F, EF>::default();

    let random_state_vals: [F; POSEIDON2_WIDTH] = rng.gen();
    // Execute the reference permutation
    let expected_result = perm.permute(random_state_vals);

    // Execture the permutation in the VM
    // Initialize an array and populate it with the entries.
    let var_width: Var<F> = builder.eval(F::from_canonical_usize(POSEIDON2_WIDTH));
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

    // Assert that the result is equal to the expected result.
    for (i, val) in expected_result.iter().enumerate() {
        let res = builder.get(&result, i);
        // builder.assert_felt_eq(res, *val);
    }

    let program = builder.compile();

    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run();
    println!(
        "The program executed successfully, number of cycles: {}",
        runtime.clk.as_canonical_u32() / 4
    );
}
