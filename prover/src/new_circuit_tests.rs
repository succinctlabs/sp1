#[cfg(test)]
mod tests {
    use std::{
        borrow::Borrow,
        fs::File,
        io::{Read, Write},
        iter::once,
    };

    use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
    use sp1_core::{
        stark::{MachineProof, StarkGenericConfig},
        utils::{log2_strict_usize, run_test_machine, setup_logger, BabyBearPoseidon2Inner},
    };
    use sp1_recursion_compiler::{config::OuterConfig, constraints::Constraint, ir::Witness};
    // use sp1_recursion_compiler::{config::OuterConfig, constraints::ConstraintCompiler, ir::Felt};
    use sp1_recursion_core::{air::RecursionPublicValues, stark::config::BabyBearPoseidon2Outer};
    use sp1_recursion_gnark_ffi::PlonkBn254Prover;

    use sp1_recursion_circuit::witness::Witnessable;

    use sp1_recursion_circuit::stark::build_wrap_circuit_new;
    use sp1_recursion_core_v2::{
        machine::RecursionAir, runtime::instruction as instr, BaseAluOpcode, MemAccessKind,
        RecursionProgram, Runtime,
    };

    use crate::utils::{babybear_bytes_to_bn254, words_to_bytes};
    type SC = BabyBearPoseidon2Outer;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    // type A = RecursionAir<F, 3>;

    pub fn test_new_machine<
        const FRI_FOLD_PADDING: usize,
        const ERBL_PADDING: usize,
        const POSEIDON2_PADDING: usize,
        const DEGREE: usize,
    >() {
        setup_logger();
        let n = 10;

        let instructions = once(instr::mem(MemAccessKind::Write, 1, 0, 0))
            .chain(once(instr::mem(MemAccessKind::Write, 2, 1, 1)))
            .chain((2..=n).map(|i| instr::base_alu(BaseAluOpcode::AddF, 2, i, i - 2, i - 1)))
            .chain(once(instr::mem(MemAccessKind::Read, 1, n - 1, 34)))
            .chain(once(instr::mem(MemAccessKind::Read, 2, n, 55)))
            .collect::<Vec<_>>();

        let program = RecursionProgram { instructions };
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new(
            &program,
            BabyBearPoseidon2Inner::new().perm,
        );
        runtime.run();

        let config = SC::new_with_log_blowup(log2_strict_usize(DEGREE - 1));
        let machine = RecursionAir::<F, DEGREE>::machine_with_padding(
            config,
            FRI_FOLD_PADDING,
            POSEIDON2_PADDING,
            ERBL_PADDING,
        );
        let (pk, vk) = machine.setup(&program);
        let result = run_test_machine(vec![runtime.record], machine, pk, vk.clone()).unwrap();

        // let bytes = bincode::serialize(&result).unwrap();

        // // Save the proof.
        // let mut file = File::create("test-proof.bin").unwrap();
        // file.write_all(bytes.as_slice()).unwrap();

        // // Load the proof.
        // let mut file = File::open("test-proof.bin").unwrap();
        // let mut bytes = Vec::new();
        // file.read_to_end(&mut bytes).unwrap();

        // let result: MachineProof<SC> = bincode::deserialize(&bytes).unwrap();

        println!("num shard proofs: {}", result.shard_proofs.len());

        let constraints = build_wrap_circuit_new::<DEGREE>(&vk, result.shard_proofs[0].clone());

        // let bytes = bincode::serialize(&constraints).unwrap();

        // // Save the constraints.
        // let mut file = File::create("test-constraints.bin").unwrap();
        // file.write_all(bytes.as_slice()).unwrap();

        let pv: &RecursionPublicValues<_> =
            result.shard_proofs[0].public_values.as_slice().borrow();
        let vkey_hash = crate::utils::babybears_to_bn254(&pv.sp1_vk_digest);
        let committed_values_digest_bytes: [BabyBear; 32] =
            words_to_bytes(&pv.committed_value_digest)
                .try_into()
                .unwrap();
        let committed_values_digest = babybear_bytes_to_bn254(&committed_values_digest_bytes);

        // Build the witness.
        let mut witness = Witness::default();
        result.shard_proofs[0].write(&mut witness);
        witness.write_commited_values_digest(committed_values_digest);
        witness.write_vkey_hash(vkey_hash);

        // // Save the witness to a file.
        // let mut file2 = File::create("test-witness.bin").unwrap();
        // let bytes2 = bincode::serialize(&witness).unwrap();
        // file2.write_all(bytes2.as_slice()).unwrap();

        // // Load the constrints.
        // let mut file = File::open("test-constraints.bin").unwrap();
        // let mut bytes = Vec::new();
        // file.read_to_end(&mut bytes).unwrap();

        // // Load the witness.
        // let mut file2 = File::open("test-witness.bin").unwrap();
        // let mut bytes2 = Vec::new();
        // file2.read_to_end(&mut bytes2).unwrap();

        // let constraints: Vec<Constraint> = bincode::deserialize(&bytes).unwrap();
        // let witness: Witness<OuterConfig> = bincode::deserialize(&bytes2).unwrap();

        PlonkBn254Prover::test::<OuterConfig>(constraints, witness);
    }

    #[test]
    pub fn test_new_machine_diff_paddings() {
        // test_new_machine::<16, 16, 16, 3>();
        test_new_machine::<16, 16, 16, 9>();
    }
}
