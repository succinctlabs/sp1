//! A simple script to generate and verify the proof of a given program.

use sp1_core::{SP1Prover, SP1Stdin, SP1Verifier};

const VERIFIER_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

const PROGRAM_ELF: &[u8] =
    include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Get the program ELF.
    let program = Program::from(PROGRAM_ELF);
}
