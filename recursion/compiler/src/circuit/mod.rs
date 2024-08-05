mod builder;
mod compiler;

pub use builder::*;
pub use compiler::*;

#[cfg(test)]
mod tests {
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::AbstractExtensionField;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core::{
        stark::{Chip, StarkGenericConfig, StarkMachine, PROOF_MAX_NUM_PVS},
        utils::{run_test_machine, setup_logger, BabyBearPoseidon2Inner},
    };
    use sp1_recursion_core_v2::{
        chips::{
            alu_base::BaseAluChip, alu_ext::ExtAluChip, exp_reverse_bits::ExpReverseBitsLenChip,
            fri_fold::FriFoldChip, mem::MemoryConstChip, poseidon2_wide::Poseidon2WideChip,
        },
        machine::RecursionAir,
        Runtime,
    };

    use crate::{asm::AsmBuilder, circuit::AsmCompiler, ir::*};

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
        let program = compiler.compile(operations);
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new(
            &program,
            BabyBearPoseidon2Inner::new().perm,
        );
        runtime.run().unwrap();

        // Construct the machine ourselves so we can pad the tables, avoiding `A::machine`.
        let config = SC::default();
        let chips: Vec<Chip<F, A>> = vec![
            A::Memory(MemoryConstChip::default()),
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
}
