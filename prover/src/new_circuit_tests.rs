#[cfg(test)]
mod tests {
    use std::{
        borrow::Borrow,
        fs::File,
        io::{Read, Write},
        iter::once,
        thread,
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
        const COL_PADDING: usize,
        const NUM_CONSTRAINTS: usize,
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
        let machine = RecursionAir::<F, DEGREE, COL_PADDING, NUM_CONSTRAINTS>::machine_with_padding(
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

        let constraints = build_wrap_circuit_new::<DEGREE, COL_PADDING, NUM_CONSTRAINTS>(
            &vk,
            result.shard_proofs[0].clone(),
        );

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
    pub fn test_new_machine_diff_degrees() {
        // test_new_machine::<16, 16, 16, 3, 1, 1>();
        // test_new_machine::<16, 16, 16, 5, 1, 1>();
        test_new_machine::<16, 16, 16, 9, 1, 1>();
        // test_new_machine::<16, 16, 16, 17, 1, 1>();
    }

    #[test]
    pub fn test_new_machine_diff_rows() {
        println!("Testing log_row = 1");
        test_new_machine::<1, 1, 1, 9, 1, 1>();
        println!("Testing log_row = 2");
        test_new_machine::<2, 2, 2, 9, 1, 1>();
        println!("Testing log_row = 3");
        test_new_machine::<3, 3, 3, 9, 1, 1>();
        println!("Testing log_row = 4");
        test_new_machine::<4, 4, 4, 9, 1, 1>();
        println!("Testing log_row = 5");
        test_new_machine::<5, 5, 5, 9, 1, 1>();
        println!("Testing log_row = 6");
        test_new_machine::<6, 6, 6, 9, 1, 1>();
        println!("Testing log_row = 7");
        test_new_machine::<7, 7, 7, 9, 1, 1>();
        println!("Testing log_row = 8");
        test_new_machine::<8, 8, 8, 9, 1, 1>();
        println!("Testing log_row = 9");
        test_new_machine::<9, 9, 9, 9, 1, 1>();
        println!("Testing log_row = 10");
        test_new_machine::<10, 10, 10, 9, 1, 1>();
        println!("Testing log_row = 11");
        test_new_machine::<11, 11, 11, 9, 1, 1>();
        println!("Testing log_row = 12");
        test_new_machine::<12, 12, 12, 9, 1, 1>();
        println!("Testing log_row = 13");
        test_new_machine::<13, 13, 13, 9, 1, 1>();
        println!("Testing log_row = 14");
        test_new_machine::<14, 14, 14, 9, 1, 1>();
        println!("Testing log_row = 15");
        test_new_machine::<15, 15, 15, 9, 1, 1>();
        println!("Testing log_row = 16");
        test_new_machine::<16, 16, 16, 9, 1, 1>();
    }

    #[test]
    pub fn test_new_machine_diff_cols() {
        println!("Testing cols = 100");
        // test_new_machine::<16, 16, 16, 9, 100>();
        // println!("Testing cols = 150");
        // test_new_machine::<16, 16, 16, 9, 150>();
        // println!("Testing cols = 200");
        // test_new_machine::<16, 16, 16, 9, 200>();
        // println!("Testing cols = 250");
        // test_new_machine::<16, 16, 16, 9, 250>();
        // println!("Testing cols = 300");
        // test_new_machine::<16, 16, 16, 9, 300>();
        // println!("Testing cols = 350");
        // test_new_machine::<16, 16, 16, 9, 350>();
        // println!("Testing cols = 400");
        // test_new_machine::<16, 16, 16, 9, 400>();
        // println!("Testing cols = 450");
        // test_new_machine::<16, 16, 16, 9, 450>();
        // println!("Testing cols = 500");
        // test_new_machine::<16, 16, 16, 9, 500>();
        test_new_machine::<16, 16, 16, 9, 550, 1>();
        test_new_machine::<16, 16, 16, 9, 600, 1>();
        test_new_machine::<16, 16, 16, 9, 650, 1>();
        test_new_machine::<16, 16, 16, 9, 700, 1>();
        test_new_machine::<16, 16, 16, 9, 750, 1>();
    }

    #[test]
    pub fn test_new_machine_diff_constraints() {
        test_new_machine::<16, 16, 16, 9, 1, 256>();
        test_new_machine::<16, 16, 16, 9, 1, 512>();
        test_new_machine::<16, 16, 16, 9, 1, 1024>();
        test_new_machine::<16, 16, 16, 9, 1, 2048>();
        test_new_machine::<16, 16, 16, 9, 1, 4096>();
        test_new_machine::<16, 16, 16, 9, 1, 9192>();
        test_new_machine::<16, 16, 16, 9, 1, 18384>();
        test_new_machine::<16, 16, 16, 9, 1, 36768>();
    }
}
