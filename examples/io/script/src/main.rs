//! A simple script to generate and verify the proof of a given program.
use curta_core::{utils, CurtaProver, CurtaStdin, CurtaVerifier};

const IO_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-curta-zkvm-elf");

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct MyPointUnaligned {
    pub x: usize,
    pub y: usize,
    pub b: bool,
}

fn main() {
    // setup tracer for logging.
    utils::setup_tracer();

    // Generate proof.
    let mut stdin = CurtaStdin::new();

    let p1 = MyPointUnaligned {
        x: 1,
        y: 2,
        b: true,
    };

    let p2 = MyPointUnaligned {
        x: 3,
        y: 4,
        b: false,
    };

    stdin.write(&p1);
    stdin.write(&p2);

    let mut proof = CurtaProver::prove(IO_ELF, stdin).expect("proving failed");

    // Read output.
    let val = proof.stdout.read::<MyPointUnaligned>();
    println!("Result point: {:?}", val);
    println!(
        "Expected point: {:?}",
        MyPointUnaligned {
            x: 4,
            y: 6,
            b: false,
        }
    );

    // Verify proof.
    CurtaVerifier::verify(IO_ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
