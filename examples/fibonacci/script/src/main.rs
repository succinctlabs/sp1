use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_core::air::Word;
use sp1_core::{utils, SP1Prover, SP1Stdin, SP1Verifier};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup a tracer for logging.
    utils::setup_logger();

    // Create an input stream.
    let stdin = SP1Stdin::new();

    // Generate the proof for the given program.
    let proof =
        SP1Prover::prove(ELF, stdin, [Word([BabyBear::one(); 4]); 8]).expect("proving failed");

    // Verify proof.
    SP1Verifier::verify(ELF, &proof, [Word([BabyBear::one(); 4]); 8]).expect("verification failed");

    // Save the proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
