use std::{array, borrow::BorrowMut};

use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, Felt},
};
use sp1_recursion_core_v2::air::{
    ChallengerPublicValues, RecursionPublicValues, NUM_PV_ELMS_TO_HASH, RECURSIVE_PROOF_NUM_PV_ELTS,
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
    for element in pv_digest {
        builder.commit_public_value(element);
    }
}

pub fn uninit_challenger_pv<C: Config>(
    builder: &mut Builder<C>,
) -> ChallengerPublicValues<Felt<C::F>> {
    let sponge_state = array::from_fn(|_| builder.uninit());
    let num_inputs = builder.uninit();
    let input_buffer = array::from_fn(|_| builder.uninit());
    let num_outputs = builder.uninit();
    let output_buffer = array::from_fn(|_| builder.uninit());
    ChallengerPublicValues { sponge_state, num_inputs, input_buffer, num_outputs, output_buffer }
}

#[cfg(any(test, feature = "export-tests"))]
pub(crate) mod tests {
    use std::sync::Arc;

    use sp1_core_machine::utils::{run_test_machine_with_prover, setup_logger};
    use sp1_recursion_compiler::{asm::AsmConfig, circuit::AsmCompiler, ir::DslIr};

    use sp1_recursion_compiler::ir::TracedVec;
    use sp1_recursion_core_v2::{machine::RecursionAir, Runtime};
    use sp1_stark::{
        baby_bear_poseidon2::BabyBearPoseidon2, CpuProver, InnerChallenge, InnerVal, MachineProver,
    };

    use crate::witness::Witness;

    type SC = BabyBearPoseidon2;
    type F = InnerVal;
    type EF = InnerChallenge;

    /// A simplified version of some code from `recursion/core/src/stark/mod.rs`.
    /// Takes in a program and runs it with the given witness and generates a proof with a variety
    /// of machines depending on the provided test_config.
    pub(crate) fn run_test_recursion_with_prover<P: MachineProver<SC, RecursionAir<F, 3, 0>>>(
        operations: TracedVec<DslIr<AsmConfig<F, EF>>>,
        witness_stream: impl IntoIterator<Item = Witness<AsmConfig<F, EF>>>,
    ) {
        setup_logger();

        let compile_span = tracing::debug_span!("compile").entered();
        let mut compiler = AsmCompiler::<AsmConfig<F, EF>>::default();
        let program = Arc::new(compiler.compile(operations));
        compile_span.exit();

        let config = SC::default();

        let run_span = tracing::debug_span!("run the recursive program").entered();
        let mut runtime = Runtime::<F, EF, _>::new(program.clone(), config.perm.clone());
        runtime.witness_stream.extend(witness_stream);
        tracing::debug_span!("run").in_scope(|| runtime.run().unwrap());
        assert!(runtime.witness_stream.is_empty());
        run_span.exit();

        let records = vec![runtime.record];

        // Run with the poseidon2 wide chip.
        let proof_wide_span = tracing::debug_span!("Run test with wide machine").entered();
        let wide_machine = RecursionAir::<_, 3, 0>::machine_wide(SC::default());
        let (pk, vk) = wide_machine.setup(&program);
        let result = run_test_machine_with_prover::<_, _, P>(records.clone(), wide_machine, pk, vk);
        proof_wide_span.exit();

        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    #[allow(dead_code)]
    pub(crate) fn run_test_recursion(
        operations: TracedVec<DslIr<AsmConfig<F, EF>>>,
        witness_stream: impl IntoIterator<Item = Witness<AsmConfig<F, EF>>>,
    ) {
        run_test_recursion_with_prover::<CpuProver<_, _>>(operations, witness_stream)
    }
}
