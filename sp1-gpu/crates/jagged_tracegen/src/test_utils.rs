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

    /// Execute the given ELF with the provided stdin and return the machine, first record, and
    /// program for use in tracegen tests.
    pub async fn setup(
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> (Machine<Felt, RiscvAir<Felt>>, ExecutionRecord, Arc<Program>) {
        let program =
            Arc::new(Program::from(elf).expect("Failed to load ELF - file may be corrupted"));

        let sp1_core_opts = SP1CoreOpts { global_dependencies_opt: true, ..Default::default() };
        let (records, _cycles) = generate_records::<Felt>(
            program.clone(),
            stdin,
            sp1_core_opts,
            [0; PROOF_NONCE_NUM_WORDS],
        )
        .expect("failed to generate records");

        let record = records[0].clone();
        let machine = RiscvAir::<Felt>::machine();

        (machine, record, program)
    }
}
