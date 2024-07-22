#[cfg(test)]
mod tests {
    use std::{borrow::Borrow, iter::once};

    use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
    use p3_field::extension::BinomialExtensionField;
    use sp1_core::{
        stark::StarkMachine,
        utils::{log2_strict_usize, run_test_machine, setup_logger, BabyBearPoseidon2Inner},
    };
    use sp1_recursion_compiler::{config::OuterConfig, ir::Witness};
    use sp1_recursion_core::{air::RecursionPublicValues, stark::config::BabyBearPoseidon2Outer};
    use sp1_recursion_gnark_ffi::PlonkBn254Prover;

    use crate::{stark::build_wrap_circuit_v2, witness::Witnessable};

    use sp1_recursion_core_v2::{
        machine::RecursionAir, runtime::instruction as instr, BaseAluOpcode, MemAccessKind,
        RecursionProgram, Runtime,
    };

    type SC = BabyBearPoseidon2Outer;

    pub fn test_machine<F, const DEGREE: usize, const COL_PADDING: usize>(machine_maker: F)
    where
        F: Fn()
            -> StarkMachine<BabyBearPoseidon2Outer, RecursionAir<BabyBear, DEGREE, COL_PADDING>>,
    {
        setup_logger();
        let n = 10;
        // Fibonacci(n)
        let instructions = once(instr::mem(MemAccessKind::Write, 1, 0, 0))
            .chain(once(instr::mem(MemAccessKind::Write, 2, 1, 1)))
            .chain((2..=n).map(|i| instr::base_alu(BaseAluOpcode::AddF, 2, i, i - 2, i - 1)))
            .chain(once(instr::mem(MemAccessKind::Read, 1, n - 1, 34)))
            .chain(once(instr::mem(MemAccessKind::Read, 2, n, 55)))
            .collect::<Vec<_>>();

        let machine = machine_maker();
        let program = RecursionProgram { instructions };
        let mut runtime = Runtime::<
            BabyBear,
            BinomialExtensionField<BabyBear, 4>,
            DiffusionMatrixBabyBear,
        >::new(&program, BabyBearPoseidon2Inner::new().perm);
        runtime.run();

        let (pk, vk) = machine.setup(&program);
        let result = run_test_machine(vec![runtime.record], machine, pk, vk.clone()).unwrap();

        let machine = machine_maker();
        let constraints = build_wrap_circuit_v2::<BabyBear, DEGREE, COL_PADDING>(
            &vk,
            result.shard_proofs[0].clone(),
            machine,
        );

        let pv: &RecursionPublicValues<_> =
            result.shard_proofs[0].public_values.as_slice().borrow();
        let vkey_hash = sp1_prover::utils::babybears_to_bn254(&pv.sp1_vk_digest);
        let committed_values_digest_bytes: [BabyBear; 32] =
            sp1_prover::utils::words_to_bytes(&pv.committed_value_digest)
                .try_into()
                .unwrap();
        let committed_values_digest =
            sp1_prover::utils::babybear_bytes_to_bn254(&committed_values_digest_bytes);

        // Build the witness.
        let mut witness = Witness::default();
        result.shard_proofs[0].write(&mut witness);
        witness.write_commited_values_digest(committed_values_digest);
        witness.write_vkey_hash(vkey_hash);

        PlonkBn254Prover::test::<OuterConfig>(constraints, witness);
    }

    pub fn machine_with_all_chips<const DEGREE: usize>(
        log_erbl_rows: usize,
        log_p2_rows: usize,
        log_frifold_rows: usize,
    ) -> StarkMachine<BabyBearPoseidon2Outer, RecursionAir<BabyBear, DEGREE, 0>> {
        let config = SC::new_with_log_blowup(log2_strict_usize(DEGREE - 1));
        RecursionAir::<BabyBear, DEGREE, 0>::machine_with_padding(
            config,
            log_frifold_rows,
            log_p2_rows,
            log_erbl_rows,
        )
    }

    pub fn machine_with_dummy<const DEGREE: usize, const COL_PADDING: usize>(
        log_height: usize,
    ) -> StarkMachine<BabyBearPoseidon2Outer, RecursionAir<BabyBear, DEGREE, COL_PADDING>> {
        let config = SC::new_with_log_blowup(log2_strict_usize(DEGREE - 1));
        RecursionAir::<BabyBear, DEGREE, COL_PADDING>::dummy_machine(config, log_height)
    }

    #[test]
    pub fn test_new_machine_diff_degrees() {
        // let machine_maker_3 = || machine_with_all_chips::<3>(16, 16, 16);
        // let machine_maker_5 = || machine_with_all_chips::<5>(16, 16, 16);
        // let machine_maker_9 = || machine_with_all_chips::<9>(16, 16, 16);
        let machine_maker_17 = || machine_with_all_chips::<17>(16, 16, 16);
        // test_machine(machine_maker_3);
        // test_machine(machine_maker_5);
        // test_machine(machine_maker_9);
        test_machine(machine_maker_17);
    }

    #[test]
    pub fn test_new_machine_diff_rows() {
        let machine_maker = |i| machine_with_all_chips::<9>(i, i, i);
        for i in 1..=5 {
            test_machine(|| machine_maker(i));
        }
    }

    #[test]
    pub fn test_dummy_diff_cols() {
        test_machine(|| machine_with_dummy::<9, 1>(15));
        test_machine(|| machine_with_dummy::<9, 50>(15));
        // test_machine(|| machine_with_dummy::<9, 100>(16));
        // test_machine(|| machine_with_dummy::<9, 150>(16));
        // test_machine(|| machine_with_dummy::<9, 200>(16));
        // test_machine(|| machine_with_dummy::<9, 250>(16));
        // test_machine(|| machine_with_dummy::<9, 300>(16));
        // test_machine(|| machine_with_dummy::<9, 350>(16));
        // test_machine(|| machine_with_dummy::<9, 400>(16));
        // test_machine(|| machine_with_dummy::<9, 450>(16));
        // test_machine(|| machine_with_dummy::<9, 500>(16));
        // test_machine(|| machine_with_dummy::<9, 550>(16));
        // test_machine(|| machine_with_dummy::<9, 600>(16));
        // test_machine(|| machine_with_dummy::<9, 650>(16));
        // test_machine(|| machine_with_dummy::<9, 700>(16));
        // test_machine(|| machine_with_dummy::<9, 750>(16));
    }

    #[test]
    pub fn test_skinny_dummy_diff_rows() {
        for i in 4..=7 {
            test_machine(|| machine_with_dummy::<9, 1>(i));
        }
    }

    #[test]
    pub fn test_dummy_diff_degrees() {
        // test_machine(|| machine_with_dummy::<3, 500>(16));
        // test_machine(|| machine_with_dummy::<5, 500>(16));
        test_machine(|| machine_with_dummy::<9, 500>(12));
        // test_machine(|| machine_with_dummy::<17, 500>(16));
    }
}
