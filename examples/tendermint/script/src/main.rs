use sp1_core::runtime::Program;
use sp1_core::runtime::Runtime;
use sp1_core::{utils, SP1Prover, SP1Stdin, SP1Verifier};

const ED25519_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
    utils::setup_logger();
    let stdin = SP1Stdin::new();

    let program = Program::from(ED25519_ELF);
    let mut runtime = Runtime::new(program);
    tracing::info_span!("b").in_scope(|| {
        runtime.run();
    });
}
