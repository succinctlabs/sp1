use std::sync::Arc;

use super::*;
use crate::Program;

#[test]
fn test_chunk_stops_correctly() {
    use bincode::serialize;
    use sp1_jit::MinimalTrace;
    use test_artifacts::KECCAK256_ELF;

    let program = Program::from(&KECCAK256_ELF).unwrap();
    let program = Arc::new(program);

    let mut executor = MinimalExecutor::new(program.clone(), true, Some(10));
    executor.with_input(&serialize(&5_usize).unwrap());
    for i in 0..5 {
        executor.with_input(&serialize(&vec![i; i]).unwrap());
    }

    let mut lask_clk = 1;
    let mut last_pc = program.pc_start_abs;
    let mut last_registers = executor.registers();
    let mut chunk_count = 0;
    while let Some(chunk) = executor.execute_chunk() {
        assert_eq!(chunk.clk_start(), lask_clk, "chunk {chunk_count} clk_start mismatch");
        assert_eq!(chunk.pc_start(), last_pc, "chunk {chunk_count} pc_start mismatch");
        assert_eq!(
            chunk.start_registers(),
            last_registers,
            "chunk {chunk_count} registers mismatch"
        );

        lask_clk = chunk.clk_end();
        last_pc = executor.pc();
        last_registers = executor.registers();
        chunk_count += 1;
    }

    assert!(chunk_count > 5, "no chunks were executed");
}

/// Differential tests comparing the portable executor against the native `x86_64` executor.
/// Only compiled on `x86_64` with the profiling feature enabled.
#[cfg(all(target_arch = "x86_64", feature = "profiling"))]
mod differential_tests {
    use std::sync::Arc;

    use crate::{
        debug::compare_states, minimal::arch::x86_64::MinimalExecutor as NativeExecutor, Program,
    };
    use sp1_jit::debug::DebugState;
    use sp1_primitives::Elf;

    use super::MinimalExecutor;

    #[allow(clippy::cast_precision_loss)]
    fn run_program_and_compare_end_state(program: &Elf) {
        let program = Program::from(program).unwrap();
        let program = Arc::new(program);

        // Run the native x86_64 executor
        let mut native_executor = NativeExecutor::new(program.clone(), false, None);
        let native_time = {
            let start = std::time::Instant::now();
            while native_executor.execute_chunk().is_some() {}
            start.elapsed()
        };

        // Run the portable executor
        let mut portable_executor = MinimalExecutor::new(program.clone(), false, None);
        let portable_time = {
            let start = std::time::Instant::now();
            while portable_executor.execute_chunk().is_some() {}
            start.elapsed()
        };

        // Report performance
        let cycles = portable_executor.global_clk();
        let portable_mhz = cycles as f64 / (portable_time.as_micros() as f64);
        eprintln!("cycles={cycles}");
        eprintln!("Portable executor MHz={portable_mhz} MHz");

        let native_cycles = native_executor.global_clk();
        let native_mhz = native_cycles as f64 / (native_time.as_micros() as f64);
        eprintln!("Native executor MHz={native_mhz} MHz");

        // Compare states
        let (is_equal, report) = compare_states(
            &program,
            &portable_executor.current_state(),
            &native_executor.current_state(),
        );
        assert!(is_equal, "state mismatch:\n{report}");
    }

    #[test]
    fn test_run_keccak_with_input() {
        use bincode::serialize;
        use test_artifacts::KECCAK256_ELF;

        let program = Program::from(&KECCAK256_ELF).unwrap();
        let program = Arc::new(program);

        // Run the portable executor
        let mut portable_executor = MinimalExecutor::new(program.clone(), false, None);
        portable_executor.with_input(&serialize(&5_usize).unwrap());
        for i in 0..5 {
            portable_executor.with_input(&serialize(&vec![i; i]).unwrap());
        }
        while portable_executor.execute_chunk().is_some() {}

        // Run the native x86_64 executor
        let mut native_executor = NativeExecutor::new(program.clone(), false, None);
        native_executor.with_input(&serialize(&5_usize).unwrap());
        for i in 0..5 {
            native_executor.with_input(&serialize(&vec![i; i]).unwrap());
        }
        while native_executor.execute_chunk().is_some() {}

        let (is_equal, report) = compare_states(
            &program,
            &portable_executor.current_state(),
            &native_executor.current_state(),
        );
        assert!(is_equal, "state mismatch:\n{report}");
    }

    #[test]
    fn test_run_fibonacci() {
        run_program_and_compare_end_state(&test_artifacts::FIBONACCI_ELF);
    }

    #[test]
    fn test_run_sha256() {
        run_program_and_compare_end_state(&test_artifacts::SHA2_ELF);
    }

    #[test]
    fn test_run_sha_extend() {
        run_program_and_compare_end_state(&test_artifacts::SHA_EXTEND_ELF);
    }

    #[test]
    fn test_run_sha_compress() {
        run_program_and_compare_end_state(&test_artifacts::SHA_COMPRESS_ELF);
    }

    #[test]
    fn test_run_keccak_permute() {
        run_program_and_compare_end_state(&test_artifacts::KECCAK_PERMUTE_ELF);
    }

    #[test]
    fn test_run_secp256k1_add() {
        run_program_and_compare_end_state(&test_artifacts::SECP256K1_ADD_ELF);
    }

    #[test]
    fn test_run_secp256k1_double() {
        run_program_and_compare_end_state(&test_artifacts::SECP256K1_DOUBLE_ELF);
    }

    #[test]
    fn test_run_secp256r1_add() {
        run_program_and_compare_end_state(&test_artifacts::SECP256R1_ADD_ELF);
    }

    #[test]
    fn test_run_secp256r1_double() {
        run_program_and_compare_end_state(&test_artifacts::SECP256R1_DOUBLE_ELF);
    }

    #[test]
    fn test_run_bls12_381_add() {
        run_program_and_compare_end_state(&test_artifacts::BLS12381_ADD_ELF);
    }

    #[test]
    fn test_ed_add() {
        run_program_and_compare_end_state(&test_artifacts::ED_ADD_ELF);
    }

    #[test]
    fn test_bn254_add() {
        run_program_and_compare_end_state(&test_artifacts::BN254_ADD_ELF);
    }

    #[test]
    fn test_bn254_double() {
        run_program_and_compare_end_state(&test_artifacts::BN254_DOUBLE_ELF);
    }

    #[test]
    fn test_bn254_mul() {
        run_program_and_compare_end_state(&test_artifacts::BN254_MUL_ELF);
    }

    #[test]
    fn test_uint256_mul() {
        run_program_and_compare_end_state(&test_artifacts::UINT256_MUL_ELF);
    }

    #[test]
    fn test_bls12_381_fp() {
        run_program_and_compare_end_state(&test_artifacts::BLS12381_FP_ELF);
    }

    #[test]
    fn test_bls12_381_fp2_mul() {
        run_program_and_compare_end_state(&test_artifacts::BLS12381_FP2_MUL_ELF);
    }

    #[test]
    fn test_bls12_381_fp2_addsub() {
        run_program_and_compare_end_state(&test_artifacts::BLS12381_FP2_ADDSUB_ELF);
    }

    #[test]
    fn test_bn254_fp() {
        run_program_and_compare_end_state(&test_artifacts::BN254_FP_ELF);
    }

    #[test]
    fn test_bn254_fp2_addsub() {
        run_program_and_compare_end_state(&test_artifacts::BN254_FP2_ADDSUB_ELF);
    }

    #[test]
    fn test_bn254_fp2_mul() {
        run_program_and_compare_end_state(&test_artifacts::BN254_FP2_MUL_ELF);
    }

    #[test]
    fn test_ed_decompress() {
        run_program_and_compare_end_state(&test_artifacts::ED_DECOMPRESS_ELF);
    }

    #[test]
    fn test_ed25519_verify() {
        run_program_and_compare_end_state(&test_artifacts::ED25519_ELF);
    }

    #[test]
    fn test_ssz_withdrawls() {
        run_program_and_compare_end_state(&test_artifacts::SSZ_WITHDRAWALS_ELF);
    }

    #[test]
    #[ignore = "Expensive test that is very useful for debugging"]
    fn test_compare_registers_at_each_timestamp() {
        use crate::debug::render_current_instruction;
        use sp1_jit::debug;
        use std::fmt::Write;

        const ELF: Elf = test_artifacts::ED25519_ELF;

        let program = Program::from(&ELF).unwrap();
        let program = Arc::new(program);

        std::thread::scope(|s| {
            // Portable executor (MinimalExecutor when profiling is enabled)
            let mut portable = MinimalExecutor::new(program.clone(), true, Some(50));
            let portable_rx =
                portable.new_debug_receiver().expect("Failed to create debug receiver");

            // Native x86_64 executor
            let mut native = NativeExecutor::new(program.clone(), true, None);
            let native_rx = native.new_debug_receiver().expect("Failed to create debug receiver");

            s.spawn(move || while portable.execute_chunk().is_some() {});
            s.spawn(move || while native.execute_chunk().is_some() {});
            s.spawn(move || {
                let mut got_prev: Option<debug::State> = None;
                let mut expected_prev: Option<debug::State> = None;

                for (cycle, (portable_msg, native_msg)) in
                    portable_rx.into_iter().zip(native_rx).enumerate()
                {
                    let (portable_msg, native_msg) = match (portable_msg, native_msg) {
                        (Some(portable), Some(native)) => (portable, native),
                        (Some(_), None) => {
                            eprintln!("portable={portable_msg:?}");
                            eprintln!("native=  {native_msg:?}");
                            panic!("Portable executor finished, but native executor did not");
                        }
                        (None, Some(_)) => {
                            eprintln!("portable={portable_msg:?}");
                            eprintln!("native=  {native_msg:?}");
                            panic!("Native executor finished, but portable executor did not");
                        }
                        (None, None) => break,
                    };

                    let (is_equal, mut report) =
                        compare_states(&program, &portable_msg, &native_msg);
                    if let (Some(got), Some(expected)) = (got_prev, expected_prev) {
                        let got = render_current_instruction(&program, &got);
                        let expected = render_current_instruction(&program, &expected);
                        writeln!(report).unwrap();
                        writeln!(report, "PREVIOUS INSTRUCTION").unwrap();
                        writeln!(report, "       GOT: {got}").unwrap();
                        writeln!(report, "  EXPECTED: {expected}").unwrap();
                    }
                    if is_equal {
                        eprintln!("state matches at cycle {cycle}");
                    } else {
                        eprintln!("{report}");
                        panic!("state mismatch at cycle {cycle}");
                    }
                    got_prev = Some(portable_msg);
                    expected_prev = Some(native_msg);
                }
            });
        });
    }
}
