//! A simple script to generate and verify the proof of a given program.

use succinct_core::{utils, SuccinctProver};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    std::env::set_var("RUST_LOG", "info");
    utils::setup_logger();
    let prover = SuccinctProver::new();
    prover.run_and_prove(ELF);
}
