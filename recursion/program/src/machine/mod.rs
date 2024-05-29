mod compress;
mod core;
mod deferred;
mod root;
mod utils;

pub use compress::*;
pub use core::*;
pub use deferred::*;
pub use root::*;
pub use utils::*;

#[cfg(test)]
mod tests {

    use p3_baby_bear::BabyBear;
    use p3_challenger::CanObserve;
    use p3_maybe_rayon::prelude::*;
    use sp1_core::stark::{MachineVerificationError, RiscvAir, StarkGenericConfig};
    use sp1_core::utils::{BabyBearPoseidon2, SP1CoreOpts};
    use sp1_core::{
        io::SP1Stdin,
        runtime::Program,
        stark::{Challenge, LocalProver},
    };
    use sp1_recursion_compiler::config::InnerConfig;
    use sp1_recursion_core::{
        runtime::Runtime,
        stark::{config::BabyBearPoseidon2Outer, RecursionAir},
    };

    use crate::hints::Hintable;

    use super::*;

    enum Test {
        Recursion,
        Reduce,
        Compress,
        Wrap,
    }

    fn test_sp1_recursive_machine_verify(program: Program, batch_size: usize, test: Test) {
        type SC = BabyBearPoseidon2;
        type F = BabyBear;
        type EF = Challenge<SC>;

        sp1_core::utils::setup_logger();

        let machine = RiscvAir::machine(SC::default());
        let (_, vk) = machine.setup(&program);

        // Make the recursion program.
        let recursive_program = SP1RecursiveVerifier::<InnerConfig, SC>::build(&machine);
        let recursive_config = SC::default();
        type A = RecursionAir<BabyBear, 3>;
        let recursive_machine = A::machine(recursive_config.clone());
        let (rec_pk, rec_vk) = recursive_machine.setup(&recursive_program);

        // Make the deferred program.
        let deferred_program = SP1DeferredVerifier::<InnerConfig, SC, _>::build(&recursive_machine);
        let (_, deferred_vk) = recursive_machine.setup(&deferred_program);

        // Make the compress program.
        let reduce_program = SP1CompressVerifier::<InnerConfig, _, _>::build(
            &recursive_machine,
            &rec_vk,
            &deferred_vk,
        );

        let (reduce_pk, compress_vk) = recursive_machine.setup(&reduce_program);

        // Make the compress program.
        let compress_machine = RecursionAir::<_, 9>::machine(SC::compressed());
        let compress_program =
            SP1RootVerifier::<InnerConfig, _, _>::build(&recursive_machine, &compress_vk, true);
        let (compress_pk, compress_vk) = compress_machine.setup(&compress_program);

        // Make the wrap program.
        let wrap_machine = RecursionAir::<_, 5>::machine(BabyBearPoseidon2Outer::default());
        let wrap_program =
            SP1RootVerifier::<InnerConfig, _, _>::build(&compress_machine, &compress_vk, false);

        let mut challenger = machine.config().challenger();
        let time = std::time::Instant::now();
        let (proof, _) = sp1_core::utils::prove(
            program,
            &SP1Stdin::new(),
            SC::default(),
            SP1CoreOpts::default(),
        )
        .unwrap();
        machine.verify(&vk, &proof, &mut challenger).unwrap();
        tracing::info!("Proof generated successfully");
        let elapsed = time.elapsed();
        tracing::info!("Execution proof time: {:?}", elapsed);

        // Get the and leaf challenger.
        let mut leaf_challenger = machine.config().challenger();
        vk.observe_into(&mut leaf_challenger);
        proof.shard_proofs.iter().for_each(|proof| {
            leaf_challenger.observe(proof.commitment.main_commit);
            leaf_challenger.observe_slice(&proof.public_values[0..machine.num_pv_elts()]);
        });
        // Make sure leaf challenger is not mutable anymore.
        let leaf_challenger = leaf_challenger;

        let mut layouts = Vec::new();

        let mut reconstruct_challenger = machine.config().challenger();
        vk.observe_into(&mut reconstruct_challenger);

        let is_complete = proof.shard_proofs.len() == 1;
        for batch in proof.shard_proofs.chunks(batch_size) {
            let proofs = batch.to_vec();

            layouts.push(SP1RecursionMemoryLayout {
                vk: &vk,
                machine: &machine,
                shard_proofs: proofs,
                leaf_challenger: &leaf_challenger,
                initial_reconstruct_challenger: reconstruct_challenger.clone(),
                is_complete,
            });

            for proof in batch.iter() {
                reconstruct_challenger.observe(proof.commitment.main_commit);
                reconstruct_challenger
                    .observe_slice(&proof.public_values[0..machine.num_pv_elts()]);
            }
        }

        assert_eq!(
            reconstruct_challenger.sponge_state,
            leaf_challenger.sponge_state
        );
        assert_eq!(
            reconstruct_challenger.input_buffer,
            leaf_challenger.input_buffer
        );
        assert_eq!(
            reconstruct_challenger.output_buffer,
            leaf_challenger.output_buffer
        );

        // Run the recursion programs.
        let mut records = Vec::new();

        for layout in layouts {
            let mut runtime =
                Runtime::<F, EF, _>::new(&recursive_program, machine.config().perm.clone());

            let mut witness_stream = Vec::new();
            witness_stream.extend(layout.write());

            runtime.witness_stream = witness_stream.into();
            runtime.run();
            runtime.print_stats();

            records.push(runtime.record);
        }

        // Prove all recursion programs and verify the recursive proofs.

        // Make the recursive proofs.
        let time = std::time::Instant::now();
        let recursive_proofs = records
            .into_par_iter()
            .map(|record| {
                let mut recursive_challenger = recursive_machine.config().challenger();
                recursive_machine.prove::<LocalProver<_, _>>(
                    &rec_pk,
                    record,
                    &mut recursive_challenger,
                    SP1CoreOpts::recursion(),
                )
            })
            .collect::<Vec<_>>();
        let elapsed = time.elapsed();
        tracing::info!("Recursive first layer proving time: {:?}", elapsed);

        // Verify the recursive proofs.
        for rec_proof in recursive_proofs.iter() {
            let mut recursive_challenger = recursive_machine.config().challenger();
            let result = recursive_machine.verify(&rec_vk, rec_proof, &mut recursive_challenger);

            match result {
                Ok(_) => tracing::info!("Proof verified successfully"),
                Err(MachineVerificationError::NonZeroCumulativeSum) => {
                    tracing::info!("Proof verification failed: NonZeroCumulativeSum")
                }
                e => panic!("Proof verification failed: {:?}", e),
            }
        }
        if let Test::Recursion = test {
            return;
        }

        tracing::info!("Recursive proofs verified successfully");

        // Chain all the individual shard proofs.
        let mut recursive_proofs = recursive_proofs
            .into_iter()
            .flat_map(|proof| proof.shard_proofs)
            .collect::<Vec<_>>();

        // Iterate over the recursive proof batches until there is one proof remaining.
        let mut is_first_layer = true;
        let mut is_complete;
        let time = std::time::Instant::now();
        loop {
            tracing::info!("Recursive proofs: {}", recursive_proofs.len());
            is_complete = recursive_proofs.len() <= batch_size;
            recursive_proofs = recursive_proofs
                .par_chunks(batch_size)
                .map(|batch| {
                    let kind = if is_first_layer {
                        ReduceProgramType::Core
                    } else {
                        ReduceProgramType::Reduce
                    };
                    let kinds = batch.iter().map(|_| kind).collect::<Vec<_>>();
                    let input = SP1ReduceMemoryLayout {
                        compress_vk: &compress_vk,
                        recursive_machine: &recursive_machine,
                        shard_proofs: batch.to_vec(),
                        kinds,
                        is_complete,
                    };

                    let mut runtime = Runtime::<F, EF, _>::new(
                        &reduce_program,
                        recursive_machine.config().perm.clone(),
                    );

                    let mut witness_stream = Vec::new();
                    witness_stream.extend(input.write());

                    runtime.witness_stream = witness_stream.into();
                    runtime.run();
                    runtime.print_stats();

                    let mut recursive_challenger = recursive_machine.config().challenger();
                    let mut proof = recursive_machine.prove::<LocalProver<_, _>>(
                        &reduce_pk,
                        runtime.record,
                        &mut recursive_challenger,
                        SP1CoreOpts::recursion(),
                    );
                    let mut recursive_challenger = recursive_machine.config().challenger();
                    let result =
                        recursive_machine.verify(&compress_vk, &proof, &mut recursive_challenger);

                    match result {
                        Ok(_) => tracing::info!("Proof verified successfully"),
                        Err(MachineVerificationError::NonZeroCumulativeSum) => {
                            tracing::info!("Proof verification failed: NonZeroCumulativeSum")
                        }
                        e => panic!("Proof verification failed: {:?}", e),
                    }

                    assert_eq!(proof.shard_proofs.len(), 1);
                    proof.shard_proofs.pop().unwrap()
                })
                .collect();
            is_first_layer = false;

            if recursive_proofs.len() == 1 {
                break;
            }
        }
        let elapsed = time.elapsed();
        tracing::info!("Reduction successful, time: {:?}", elapsed);
        if let Test::Reduce = test {
            return;
        }

        assert_eq!(recursive_proofs.len(), 1);
        let reduce_proof = recursive_proofs.pop().unwrap();

        // Make the compress proof.
        let input = SP1RootMemoryLayout {
            machine: &recursive_machine,
            proof: reduce_proof,
            is_reduce: true,
        };

        // Run the compress program.
        let mut runtime =
            Runtime::<F, EF, _>::new(&compress_program, compress_machine.config().perm.clone());

        let mut witness_stream = Vec::new();
        witness_stream.extend(input.write());

        runtime.witness_stream = witness_stream.into();
        runtime.run();
        runtime.print_stats();
        tracing::info!("Compress program executed successfully");

        // Prove the compress program.
        let mut compress_challenger = compress_machine.config().challenger();

        let time = std::time::Instant::now();
        let mut compress_proof = compress_machine.prove::<LocalProver<_, _>>(
            &compress_pk,
            runtime.record,
            &mut compress_challenger,
            SP1CoreOpts::default(),
        );
        let elapsed = time.elapsed();
        tracing::info!("Compress proving time: {:?}", elapsed);
        let mut compress_challenger = compress_machine.config().challenger();
        let result =
            compress_machine.verify(&compress_vk, &compress_proof, &mut compress_challenger);
        match result {
            Ok(_) => tracing::info!("Proof verified successfully"),
            Err(MachineVerificationError::NonZeroCumulativeSum) => {
                tracing::info!("Proof verification failed: NonZeroCumulativeSum")
            }
            e => panic!("Proof verification failed: {:?}", e),
        }

        if let Test::Compress = test {
            return;
        }

        // Run and prove the wrap program.

        let (wrap_pk, wrap_vk) = wrap_machine.setup(&wrap_program);

        let compress_proof = compress_proof.shard_proofs.pop().unwrap();
        let input = SP1RootMemoryLayout {
            machine: &compress_machine,
            proof: compress_proof,
            is_reduce: false,
        };

        // Run the compress program.
        let mut runtime =
            Runtime::<F, EF, _>::new(&wrap_program, compress_machine.config().perm.clone());

        let mut witness_stream = Vec::new();
        witness_stream.extend(input.write());

        runtime.witness_stream = witness_stream.into();
        runtime.run();
        runtime.print_stats();
        tracing::info!("Wrap program executed successfully");

        // Prove the wrap program.
        let mut wrap_challenger = wrap_machine.config().challenger();
        let time = std::time::Instant::now();
        let wrap_proof = wrap_machine.prove::<LocalProver<_, _>>(
            &wrap_pk,
            runtime.record,
            &mut wrap_challenger,
            SP1CoreOpts::recursion(),
        );
        let elapsed = time.elapsed();
        tracing::info!("Wrap proving time: {:?}", elapsed);
        let mut wrap_challenger = wrap_machine.config().challenger();
        let result = wrap_machine.verify(&wrap_vk, &wrap_proof, &mut wrap_challenger);
        match result {
            Ok(_) => tracing::info!("Proof verified successfully"),
            Err(MachineVerificationError::NonZeroCumulativeSum) => {
                tracing::info!("Proof verification failed: NonZeroCumulativeSum")
            }
            e => panic!("Proof verification failed: {:?}", e),
        }
        tracing::info!("Wrapping successful");
    }

    #[test]
    fn test_sp1_recursive_machine_verify_fibonacci() {
        let elf = include_bytes!("../../../../tests/fibonacci/elf/riscv32im-succinct-zkvm-elf");
        test_sp1_recursive_machine_verify(Program::from(elf), 1, Test::Recursion)
    }

    #[test]
    #[ignore]
    fn test_sp1_reduce_machine_verify_fibonacci() {
        let elf = include_bytes!("../../../../tests/fibonacci/elf/riscv32im-succinct-zkvm-elf");
        test_sp1_recursive_machine_verify(Program::from(elf), 1, Test::Reduce)
    }

    #[test]
    #[ignore]
    fn test_sp1_compress_machine_verify_fibonacci() {
        let elf = include_bytes!("../../../../tests/fibonacci/elf/riscv32im-succinct-zkvm-elf");
        test_sp1_recursive_machine_verify(Program::from(elf), 1, Test::Compress)
    }

    #[test]
    #[ignore]
    fn test_sp1_wrap_machine_verify_fibonacci() {
        let elf = include_bytes!("../../../../tests/fibonacci/elf/riscv32im-succinct-zkvm-elf");
        test_sp1_recursive_machine_verify(Program::from(elf), 1, Test::Wrap)
    }

    #[test]
    #[ignore]
    fn test_sp1_reduce_machine_verify_tendermint() {
        let elf = include_bytes!(
            "../../../../tests/tendermint-benchmark/elf/riscv32im-succinct-zkvm-elf"
        );
        test_sp1_recursive_machine_verify(Program::from(elf), 2, Test::Reduce)
    }

    #[test]
    #[ignore]
    fn test_sp1_recursive_machine_verify_tendermint() {
        let elf = include_bytes!(
            "../../../../tests/tendermint-benchmark/elf/riscv32im-succinct-zkvm-elf"
        );
        test_sp1_recursive_machine_verify(Program::from(elf), 2, Test::Recursion)
    }

    #[test]
    #[ignore]
    fn test_sp1_compress_machine_verify_tendermint() {
        let elf = include_bytes!(
            "../../../../tests/tendermint-benchmark/elf/riscv32im-succinct-zkvm-elf"
        );
        test_sp1_recursive_machine_verify(Program::from(elf), 2, Test::Compress)
    }

    #[test]
    #[ignore]
    fn test_sp1_wrap_machine_verify_tendermint() {
        let elf = include_bytes!(
            "../../../../tests/tendermint-benchmark/elf/riscv32im-succinct-zkvm-elf"
        );
        test_sp1_recursive_machine_verify(Program::from(elf), 2, Test::Wrap)
    }
}
