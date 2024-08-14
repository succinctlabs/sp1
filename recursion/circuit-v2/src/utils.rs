use std::borrow::BorrowMut;

use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, Felt},
};
use sp1_recursion_core_v2::air::{
    RecursionPublicValues, NUM_PV_ELMS_TO_HASH, RECURSIVE_PROOF_NUM_PV_ELTS,
};

/// Register and commits the recursion public values.
pub fn commit_recursion_public_values<C: Config>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
) {
    let mut pv_elements: [Felt<_>; RECURSIVE_PROOF_NUM_PV_ELTS] =
        core::array::from_fn(|_| builder.uninit());
    *pv_elements.as_mut_slice().borrow_mut() = *public_values;
    let pv_elms_no_digest = &pv_elements[0..NUM_PV_ELMS_TO_HASH];

    for value in pv_elms_no_digest.iter() {
        builder.register_public_value(*value);
    }

    // Hash the public values.
    let pv_digest = builder.poseidon2_hash_v2(&pv_elements[0..NUM_PV_ELMS_TO_HASH]);
}

#[cfg(test)]
pub(crate) mod tests {
    use sp1_core::utils::setup_logger;
    use sp1_core::utils::BabyBearPoseidon2;
    use sp1_core::utils::InnerChallenge;
    use sp1_core::utils::InnerVal;
    use sp1_recursion_compiler::asm::AsmConfig;
    use sp1_recursion_compiler::circuit::AsmCompiler;
    use sp1_recursion_compiler::ir::DslIr;

    use sp1_recursion_compiler::ir::TracedVec;
    use sp1_recursion_core_v2::machine::RecursionAir;
    use sp1_recursion_core_v2::Runtime;

    use crate::witness::Witness;

    use sp1_core::utils::run_test_machine;

    type SC = BabyBearPoseidon2;
    type F = InnerVal;
    type EF = InnerChallenge;

    /// A simplified version of some code from `recursion/core/src/stark/mod.rs`.
    /// Takes in a program and runs it with the given witness and generates a proof with a variety of
    /// machines depending on the provided test_config.
    pub(crate) fn run_test_recursion(
        operations: TracedVec<DslIr<AsmConfig<F, EF>>>,
        witness_stream: impl IntoIterator<Item = Witness<AsmConfig<F, EF>>>,
    ) {
        setup_logger();

        let compile_span = tracing::debug_span!("compile").entered();
        let mut compiler = AsmCompiler::<AsmConfig<F, EF>>::default();
        let program = compiler.compile(operations);
        compile_span.exit();

        let config = SC::default();

        let run_span = tracing::debug_span!("run the recursive program").entered();
        let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
        runtime.witness_stream.extend(witness_stream);
        runtime.run().unwrap();
        assert!(runtime.witness_stream.is_empty());
        run_span.exit();

        let records = vec![runtime.record];

        // Run with the poseidon2 wide chip.
        let proof_wide_span = tracing::debug_span!("Prove with wide machine").entered();
        let wide_machine = RecursionAir::<_, 3, 0>::machine_wide(SC::default());
        let (pk, vk) = wide_machine.setup(&program);
        let result = run_test_machine(records.clone(), wide_machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
        proof_wide_span.exit();

        // This is commented out for now since it's slow for big programs.
        // // Run with the poseidon2 skinny chip.
        // let skinny_machine = RecursionAir::<_, 9, 0>::machine(SC::compressed());
        // let (pk, vk) = skinny_machine.setup(&program);
        // let result = run_test_machine(records.clone(), skinny_machine, pk, vk);
        // if let Err(e) = result {
        //     panic!("Verification failed: {:?}", e);
        // }
    }
}
