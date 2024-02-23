#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_core::utils::BabyBearBlake3;
use sp1_core::{SP1ProofWithIO, SP1Verifier};

const FIBONACCI_ELF: &[u8] =
    include_bytes!("../../../../examples/fibonacci-io/program/elf/riscv32im-succinct-zkvm-elf");

pub fn main() {
    let proof_str = include_str!("./fixtures/fib-proof-with-pis.json");
    let proof: SP1ProofWithIO<BabyBearBlake3> =
        serde_json::from_str(proof_str).expect("loading proof failed");

    // Verify proof.
    SP1Verifier::verify(FIBONACCI_ELF, &proof).expect("verification failed");
}
