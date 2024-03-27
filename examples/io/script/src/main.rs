use serde::{Deserialize, Serialize};
use sp1_core::{utils, SP1Prover, SP1Stdin, SP1Verifier};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct MyPointUnaligned {
    pub x: usize,
    pub y: usize,
    pub b: bool,
}

fn main() {
    // Setup a tracer for logging.
    utils::setup_tracer();

    // Create an input stream.
    let mut stdin = SP1Stdin::new();
    let p = MyPointUnaligned {
        x: 1,
        y: 2,
        b: true,
    };
    let q = MyPointUnaligned {
        x: 3,
        y: 4,
        b: false,
    };
    stdin.write(&p);
    stdin.write(&q);

    // Generate the proof for the given program.
    let mut proof = SP1Prover::prove(ELF, stdin).expect("proving failed");

    // Read the output.
    let r = proof.stdout.read::<MyPointUnaligned>();
    println!("r: {:?}", r);

    // Verify proof.
    SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // Save the proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
