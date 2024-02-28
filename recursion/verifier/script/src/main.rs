//! A simple script to generate and verify the proof of a given program.

use sp1_core::runtime::Program;
use sp1_core::runtime::Runtime;
use sp1_core::utils::prove_core;
use sp1_core::utils::BabyBearBlake3;

const VERIFIER_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

const PROGRAM_ELF: &[u8] =
    include_bytes!("../../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup a tracer for logging.
    utils::setup_tracer();
    // Get the program ELF.
    let program = Program::from(PROGRAM_ELF);

    let config = BabyBearBlake3::new();

    // Run the program.
    let mut runtime = Runtime::new(program);
    runtime.run();

    // Generate abd serialize the proof.
    let config = BabyBearBlake3::new();
    let proof = prove_core(config, runtime);
    tracing::info!("Proof generated: {:?}", proof);
    let proof_bytes = bincode::serialize(&proof).unwrap();
}
