//! Common test utilities shared across test modules.

#[cfg(any(test, feature = "test-utils"))]
pub mod tracegen_setup {
    use sp1_core_executor::{ExecutionRecord, Program, SP1CoreOpts};
    use sp1_core_machine::{io::SP1Stdin, riscv::RiscvAir, utils::generate_records};
    use sp1_hypercube::{air::PROOF_NONCE_NUM_WORDS, Machine};
    use std::sync::Arc;

    use sp1_gpu_utils::Felt;

    pub const CORE_MAX_LOG_ROW_COUNT: u32 = 22;
    pub const LOG_STACKING_HEIGHT: u32 = 21;

    /// Which test program to execute for trace generation.
    #[derive(Debug, Clone, Copy, Default)]
    pub enum TestProgram {
        /// Fibonacci program (hardcoded n=10)
        #[default]
        Fibonacci,
        /// Keccak permute program (no stdin needed)
        Keccak,
    }

    impl TestProgram {
        /// Returns the ELF bytes for this program.
        pub fn elf(&self) -> &'static [u8] {
            match self {
                TestProgram::Fibonacci => &test_artifacts::FIBONACCI_ELF,
                TestProgram::Keccak => &test_artifacts::KECCAK_PERMUTE_ELF,
            }
        }

        /// Returns the stdin for this program.
        pub fn stdin(&self) -> SP1Stdin {
            SP1Stdin::new()
        }

        /// Returns the program name for error messages.
        pub fn name(&self) -> &'static str {
            match self {
                TestProgram::Fibonacci => "Fibonacci",
                TestProgram::Keccak => "Keccak",
            }
        }

        /// Returns the number of records to skip before returning the desired one.
        /// Some programs have initialization shards that aren't representative.
        pub fn records_to_skip(&self) -> usize {
            0
        }
    }

    /// Get a core trace for proving by executing a program and taking the first record.
    ///
    /// This implementation directly executes the specified ELF to generate
    /// execution records.
    ///
    /// Returns (machine, record, program) for use in core execution tracegen tests.
    ///
    /// Note: This generates ExecutionRecord, not recursion/compression records.
    pub async fn setup() -> (Machine<Felt, RiscvAir<Felt>>, ExecutionRecord, Arc<Program>) {
        setup_with_program(TestProgram::default()).await
    }

    /// Get a core trace for proving by executing the specified program.
    ///
    /// Returns (machine, record, program) for use in core execution tracegen tests.
    pub async fn setup_with_program(
        test_program: TestProgram,
    ) -> (Machine<Felt, RiscvAir<Felt>>, ExecutionRecord, Arc<Program>) {
        // 1. Load program from ELF
        let program = Arc::new(Program::from(test_program.elf()).unwrap_or_else(|_| {
            panic!("Failed to load {} ELF - file may be corrupted", test_program.name())
        }));

        // 2. Create stdin with program-specific input
        let stdin = test_program.stdin();

        // 3. Generate records
        let sp1_core_opts = SP1CoreOpts { global_dependencies_opt: true, ..Default::default() };
        let (records, _cycles) = generate_records::<Felt>(
            program.clone(),
            stdin,
            sp1_core_opts,
            [0; PROOF_NONCE_NUM_WORDS],
        )
        .expect("failed to generate records");

        let record = records[test_program.records_to_skip()].clone();

        // 4. Get machine
        let machine = RiscvAir::<Felt>::machine();

        (machine, record, program)
    }
}
