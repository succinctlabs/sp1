mod builder;
mod compiler;

pub use builder::*;
pub use compiler::*;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::{AbstractExtensionField, AbstractField};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use sp1_core_machine::utils::{run_test_machine, setup_logger};
    use sp1_recursion_core_v2::{
        chips::{
            alu_base::BaseAluChip,
            alu_ext::ExtAluChip,
            exp_reverse_bits::ExpReverseBitsLenChip,
            fri_fold::FriFoldChip,
            mem::{MemoryConstChip, MemoryVarChip},
            poseidon2_wide::Poseidon2WideChip,
        },
        machine::RecursionAir,
        Runtime, RuntimeError,
    };
    use sp1_stark::{
        BabyBearPoseidon2Inner, Chip, StarkGenericConfig, StarkMachine, PROOF_MAX_NUM_PVS,
    };

    use crate::{
        asm::AsmBuilder,
        circuit::{AsmCompiler, CircuitV2Builder},
        ir::*,
    };

    const DEGREE: usize = 3;

    type SC = BabyBearPoseidon2Inner;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type A = RecursionAir<F, DEGREE, 0>;

    /// Rough test to give an idea of how long the compress stage would take on the v2 circuit
    /// relative to the recursion VM.
    ///
    /// The constants below were manually populated by running
    /// `RUST_LOG=debug RUST_LOGGER=forest FRI_QUERIES=100 cargo test
    /// --release --package sp1-prover -- --exact tests::test_e2e`
    /// and writing down numbers from the first `prove_shards` section of the compress stage.
    /// We use those numbers to create a dummy circuit that should roughly be the size of
    /// the finished circuit, which will be equivalent to the compress program on the VM.
    /// Therefore, by running `RUST_LOG=debug RUST_LOGGER=forest FRI_QUERIES=100 cargo test
    /// -release --lib --features native-gnark -- test_compress_dummy_circuit`
    /// and comparing the durations of the `prove_shards` sections, we can roughly estimate the
    /// speed-up factor. At the time of writing, the factor is approximately 30.4s/3.5s = 8.7.
    #[test]
    fn test_compress_dummy_circuit() {
        setup_logger();

        // To aid in testing.
        const SCALE: usize = 1;
        const FIELD_OPERATIONS: usize = 451653 * SCALE;
        const EXTENSION_OPERATIONS: usize = 82903 * SCALE;
        const POSEIDON_OPERATIONS: usize = 34697 * SCALE;
        const EXP_REVERSE_BITS_LEN_OPERATIONS: usize = 35200 * SCALE;
        const FRI_FOLD_OPERATIONS: usize = 152800 * SCALE;

        let mut builder = AsmBuilder::<F, EF>::default();

        let mut rng = StdRng::seed_from_u64(0xFEB29).sample_iter(rand::distributions::Standard);
        let mut random_felt = move || -> F { rng.next().unwrap() };
        let mut rng =
            StdRng::seed_from_u64(0x0451).sample_iter::<[F; 4], _>(rand::distributions::Standard);
        let mut random_ext = move || EF::from_base_slice(&rng.next().unwrap());

        for _ in 0..FIELD_OPERATIONS {
            let a: Felt<_> = builder.eval(random_felt());
            let b: Felt<_> = builder.eval(random_felt());
            let _: Felt<_> = builder.eval(a + b);
        }
        for _ in 0..EXTENSION_OPERATIONS {
            let a: Ext<_, _> = builder.eval(random_ext().cons());
            let b: Ext<_, _> = builder.eval(random_ext().cons());
            let _: Ext<_, _> = builder.eval(a + b);
        }

        let operations = builder.operations;
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile(operations));
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new(
            program.clone(),
            BabyBearPoseidon2Inner::new().perm,
        );
        runtime.run().unwrap();

        // Construct the machine ourselves so we can pad the tables, avoiding `A::machine`.
        let config = SC::default();
        let chips: Vec<Chip<F, A>> = vec![
            A::MemoryConst(MemoryConstChip::default()),
            A::MemoryVar(MemoryVarChip::default()),
            A::BaseAlu(BaseAluChip::default()),
            A::ExtAlu(ExtAluChip::default()),
            A::Poseidon2Wide(Poseidon2WideChip::<DEGREE> {
                fixed_log2_rows: Some(((POSEIDON_OPERATIONS - 1).ilog2() + 1) as usize),
                pad: true,
            }),
            A::ExpReverseBitsLen(ExpReverseBitsLenChip::<DEGREE> {
                fixed_log2_rows: Some(((EXP_REVERSE_BITS_LEN_OPERATIONS - 1).ilog2() + 1) as usize),
                pad: true,
            }),
            A::FriFold(FriFoldChip::<DEGREE> {
                fixed_log2_rows: Some(((FRI_FOLD_OPERATIONS - 1).ilog2() + 1) as usize),
                pad: true,
            }),
        ]
        .into_iter()
        .map(Chip::new)
        .collect();
        let machine = StarkMachine::new(config, chips, PROOF_MAX_NUM_PVS);

        let (pk, vk) = machine.setup(&program);
        let result =
            run_test_machine(vec![runtime.record], machine, pk, vk.clone()).expect("should verify");

        tracing::info!("num shard proofs: {}", result.shard_proofs.len());
    }

    #[test]
    fn test_io() {
        let mut builder = AsmBuilder::<F, EF>::default();

        let felts = builder.hint_felts_v2(3);
        assert_eq!(felts.len(), 3);
        let sum: Felt<_> = builder.eval(felts[0] + felts[1]);
        builder.assert_felt_eq(sum, felts[2]);

        let exts = builder.hint_exts_v2(3);
        assert_eq!(exts.len(), 3);
        let sum: Ext<_, _> = builder.eval(exts[0] + exts[1]);
        builder.assert_ext_ne(sum, exts[2]);

        let x = builder.hint_ext_v2();
        builder.assert_ext_eq(x, exts[0] + felts[0]);

        let y = builder.hint_felt_v2();
        let zero: Felt<_> = builder.constant(F::zero());
        builder.assert_felt_eq(y, zero);

        let operations = builder.operations;
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile(operations));
        let mut runtime =
            Runtime::<F, EF, DiffusionMatrixBabyBear>::new(program.clone(), SC::new().perm);
        runtime.witness_stream = [
            vec![F::one().into(), F::one().into(), F::two().into()],
            vec![F::zero().into(), F::one().into(), F::two().into()],
            vec![F::one().into()],
            vec![F::zero().into()],
        ]
        .concat()
        .into();
        runtime.run().unwrap();

        let machine = A::machine_wide(SC::new());

        let (pk, vk) = machine.setup(&program);
        let result =
            run_test_machine(vec![runtime.record], machine, pk, vk.clone()).expect("should verify");

        tracing::info!("num shard proofs: {}", result.shard_proofs.len());
    }

    #[test]
    fn test_empty_witness_stream() {
        let mut builder = AsmBuilder::<F, EF>::default();

        let felts = builder.hint_felts_v2(3);
        assert_eq!(felts.len(), 3);
        let sum: Felt<_> = builder.eval(felts[0] + felts[1]);
        builder.assert_felt_eq(sum, felts[2]);

        let exts = builder.hint_exts_v2(3);
        assert_eq!(exts.len(), 3);
        let sum: Ext<_, _> = builder.eval(exts[0] + exts[1]);
        builder.assert_ext_ne(sum, exts[2]);

        let operations = builder.operations;
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile(operations));
        let mut runtime =
            Runtime::<F, EF, DiffusionMatrixBabyBear>::new(program.clone(), SC::new().perm);
        runtime.witness_stream =
            [vec![F::one().into(), F::one().into(), F::two().into()]].concat().into();

        match runtime.run() {
            Err(RuntimeError::EmptyWitnessStream) => (),
            Ok(_) => panic!("should not succeed"),
            Err(x) => panic!("should not yield error variant: {}", x),
        }
    }
}
