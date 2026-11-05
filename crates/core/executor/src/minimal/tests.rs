use std::sync::Arc;

use super::*;
use crate::{Program, SupervisorMode};

#[test]
fn test_chunk_stops_correctly() {
    use bincode::serialize;
    use sp1_jit::MinimalTrace;
    use test_artifacts::KECCAK256_ELF;

    let program = Program::from(&KECCAK256_ELF).unwrap();
    let program = Arc::new(program);

    let mut executor = MinimalExecutor::<SupervisorMode>::new(program.clone(), true, Some(10));
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

/// Poseidon2 host/guest agreement.
///
/// `sp1-lib` gives guests two ways to hash with the Poseidon2 precompile: the raw rate-8 sponge on
/// `Poseidon2State`, and the length-prefixed byte hasher `Poseidon2ByteHash`. Both were shipped
/// without any test. Nothing checked that either one agrees with the permutation the prover itself
/// hashes with (`inner_perm`), which is the property every program that hashes in the guest and
/// verifies the digest outside it relies on.
///
/// The host reference below is written out rather than shared with the guest on purpose. The guest
/// code cannot run here: off the zkVM target the entrypoint compiles `syscall_poseidon2` down to an
/// `unreachable!()` stub, so calling `Poseidon2ByteHash::hash` on the host panics rather than
/// hashing. Sharing an implementation would also defeat the point, since it could not catch a
/// change to the wire format. The packing this pins is what an external verifier has to reproduce.
mod poseidon2_tests {
    use bincode::serialize;
    use slop_algebra::{AbstractField, PrimeField32};
    use slop_symmetric::Permutation;
    use sp1_hypercube::inner_perm;
    use sp1_primitives::{io::SP1PublicValues, SP1Field, SP1Perm};

    use super::*;

    /// Mirrors `sp1_lib::poseidon2`.
    const WIDTH: usize = 16;
    const RATE: usize = 8;
    const BYTE_BLOCK_SIZE: usize = RATE * 3;

    /// The overwrite-mode sponge that `Poseidon2State` implements.
    struct HostSponge {
        state: [SP1Field; WIDTH],
        perm: SP1Perm,
    }

    impl HostSponge {
        fn new() -> Self {
            Self { state: [SP1Field::zero(); WIDTH], perm: inner_perm() }
        }

        /// Mirrors `Poseidon2State::absorb_field_block_unchecked`: overwrite the rate, permute.
        fn absorb_field_block(&mut self, block: &[u32; RATE]) {
            for (lane, value) in self.state[..RATE].iter_mut().zip(block) {
                *lane = SP1Field::from_canonical_u32(*value);
            }
            self.state = self.perm.permute(self.state);
        }

        /// Mirrors `Poseidon2State::absorb_byte_block`: little-endian, three bytes per element.
        fn absorb_byte_block(&mut self, block: &[u8; BYTE_BLOCK_SIZE]) {
            let mut field_block = [0u32; RATE];
            for (i, element) in field_block.iter_mut().enumerate() {
                *element = u32::from(block[3 * i])
                    | (u32::from(block[3 * i + 1]) << 8)
                    | (u32::from(block[3 * i + 2]) << 16);
            }
            self.absorb_field_block(&field_block);
        }

        /// Mirrors `Poseidon2State::output`: the rate portion, with no finalization.
        fn output(&self) -> [u32; RATE] {
            core::array::from_fn(|i| self.state[i].as_canonical_u32())
        }
    }

    /// Mirrors `Poseidon2ByteHash::hash`.
    fn host_byte_hash(input: &[u8]) -> [u32; RATE] {
        let mut sponge = HostSponge::new();

        let mut length_block = [0u8; BYTE_BLOCK_SIZE];
        length_block[..8].copy_from_slice(&input.len().to_le_bytes());
        sponge.absorb_byte_block(&length_block);

        let chunks = input.chunks_exact(BYTE_BLOCK_SIZE);
        let remainder = chunks.remainder();
        for chunk in chunks {
            sponge.absorb_byte_block(chunk.try_into().unwrap());
        }
        if !remainder.is_empty() {
            let mut last_block = [0u8; BYTE_BLOCK_SIZE];
            last_block[..remainder.len()].copy_from_slice(remainder);
            sponge.absorb_byte_block(&last_block);
        }

        sponge.output()
    }

    /// Rate-sized field blocks, all canonical so the `_unchecked` contract holds.
    fn field_blocks() -> Vec<[u32; RATE]> {
        vec![
            [0; RATE],
            core::array::from_fn(|i| i as u32),
            // The largest canonical `SP1Field` value, to catch a reduction applied on one side
            // of the boundary but not the other.
            [SP1Field::neg_one().as_canonical_u32(); RATE],
        ]
    }

    /// Messages chosen to straddle the 24-byte block boundary and to differ only by trailing
    /// zeros, which is the collision the length prefix exists to prevent.
    fn messages() -> Vec<Vec<u8>> {
        let mut messages = vec![
            Vec::new(),
            vec![0xab],
            vec![7u8; BYTE_BLOCK_SIZE - 1],
            vec![7u8; BYTE_BLOCK_SIZE],
            vec![7u8; BYTE_BLOCK_SIZE + 1],
            vec![7u8; 2 * BYTE_BLOCK_SIZE],
            (0..=255u8).collect(),
            vec![1, 2, 3],
            vec![1, 2, 3, 0],
            vec![1, 2, 3, 0, 0, 0, 0, 0],
        ];
        messages.push((0..100u8).rev().collect());
        messages
    }

    /// Byte packing must never produce a non-canonical field element, or
    /// `absorb_field_block_unchecked`'s documented safety contract would be violated by
    /// `absorb_byte_block` itself.
    #[test]
    fn byte_packing_stays_canonical() {
        let max_packed =
            u32::from(u8::MAX) | (u32::from(u8::MAX) << 8) | (u32::from(u8::MAX) << 16);
        assert!(max_packed < SP1Field::ORDER_U32, "three-byte packing can exceed the modulus");
    }

    /// The length prefix is what makes the hasher injective across lengths. Without it, a message
    /// and the same message with trailing zeros would land in the same padded blocks.
    #[test]
    fn length_prefix_separates_trailing_zeros() {
        let base = host_byte_hash(&[1, 2, 3]);
        assert_ne!(base, host_byte_hash(&[1, 2, 3, 0]));
        assert_ne!(base, host_byte_hash(&[1, 2, 3, 0, 0, 0, 0, 0]));
        assert_ne!(host_byte_hash(&[]), host_byte_hash(&[0]));
    }

    #[test]
    fn guest_hashing_matches_the_host_permutation() {
        let program = Arc::new(Program::from(&test_artifacts::POSEIDON2_ELF).unwrap());
        let field_blocks = field_blocks();
        let messages = messages();

        let mut executor = MinimalExecutor::<SupervisorMode>::new(program, false, None);
        executor.with_input(&serialize(&field_blocks).unwrap());
        executor.with_input(&serialize(&messages).unwrap());
        while executor.execute_chunk().is_some() {}

        let mut public_values = SP1PublicValues::from(executor.public_values_stream());

        let mut sponge = HostSponge::new();
        for block in &field_blocks {
            sponge.absorb_field_block(block);
        }
        assert_eq!(
            public_values.read::<[u32; RATE]>(),
            sponge.output(),
            "guest field-element sponge disagrees with the host permutation"
        );

        for message in &messages {
            assert_eq!(
                public_values.read::<[u32; RATE]>(),
                host_byte_hash(message),
                "guest byte hash disagrees with the host for a {}-byte message",
                message.len()
            );
        }
    }

    /// A state word `>= P` has no provable execution: the Poseidon2 AIR range checks all 16 input
    /// words against the modulus. `SP1Field::from_canonical_u32` only enforces that under
    /// `debug_assert`, so a release-mode executor used to reduce such a word modulo `P`, hash a
    /// value the guest never wrote, and run on to completion. The only symptom was a constraint
    /// failure inside the Poseidon2 chip at proving time, naming neither the syscall nor the
    /// guest. This pins the diagnostic that replaced it, which is the only thing the guest author
    /// ever sees, and it must hold in release builds where the `debug_assert` is compiled out.
    ///
    /// `absorb_field_block_unchecked` is the only way a guest can get a non-canonical word into
    /// the state, and the test program forwards the host's blocks to it verbatim.
    #[test]
    #[should_panic(expected = "non-canonical value to the Poseidon2 precompile")]
    fn non_canonical_absorb_input_is_rejected() {
        // Exactly the modulus: the smallest non-canonical word, and the one a reduction maps to
        // zero, so a silent reduction would look like an ordinary hash of an all-zero block.
        let mut block = [0u32; RATE];
        block[3] = SP1Field::ORDER_U32;

        let program = Arc::new(Program::from(&test_artifacts::POSEIDON2_ELF).unwrap());
        let mut executor = MinimalExecutor::<SupervisorMode>::new(program, false, None);
        executor.with_input(&serialize(&vec![block]).unwrap());
        executor.with_input(&serialize(&Vec::<Vec<u8>>::new()).unwrap());
        while executor.execute_chunk().is_some() {}
    }
}

/// Differential tests comparing the portable executor against the native `x86_64` executor.
/// Only compiled on `x86_64` with the profiling feature enabled.
#[cfg(all(target_arch = "x86_64", feature = "profiling"))]
mod differential_tests {
    use std::sync::Arc;

    use crate::{
        debug::compare_states, minimal::arch::x86_64::MinimalExecutor as NativeExecutor, Program,
        SupervisorMode,
    };
    use sp1_jit::debug::DebugState;
    use sp1_primitives::Elf;

    use super::MinimalExecutor;

    #[allow(clippy::cast_precision_loss)]
    fn run_program_and_compare_end_state(program: &Elf) {
        let program = Program::from(program).unwrap();
        let program = Arc::new(program);

        // Run the native x86_64 executor
        let mut native_executor =
            NativeExecutor::<SupervisorMode>::new(program.clone(), false, None);
        let native_time = {
            let start = std::time::Instant::now();
            while native_executor.execute_chunk().is_some() {}
            start.elapsed()
        };

        // Run the portable executor
        let mut portable_executor =
            MinimalExecutor::<SupervisorMode>::new(program.clone(), false, None);
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
        let mut portable_executor =
            MinimalExecutor::<SupervisorMode>::new(program.clone(), false, None);
        portable_executor.with_input(&serialize(&5_usize).unwrap());
        for i in 0..5 {
            portable_executor.with_input(&serialize(&vec![i; i]).unwrap());
        }
        while portable_executor.execute_chunk().is_some() {}

        // Run the native x86_64 executor
        let mut native_executor =
            NativeExecutor::<SupervisorMode>::new(program.clone(), false, None);
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
            let mut portable =
                MinimalExecutor::<SupervisorMode>::new(program.clone(), true, Some(50));
            let portable_rx =
                portable.new_debug_receiver().expect("Failed to create debug receiver");

            // Native x86_64 executor
            let mut native = NativeExecutor::<SupervisorMode>::new(program.clone(), true, None);
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
