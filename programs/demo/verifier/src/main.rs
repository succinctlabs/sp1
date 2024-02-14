#![no_main]
curta_zkvm::entrypoint!(main);

use curta_core::utils::BabyBearBlake3;
use curta_core::{CurtaProofWithIO, CurtaVerifier};

const FIBONACCI_ELF: &[u8] = include_bytes!("../../fibonacci/elf/riscv32im-curta-zkvm-elf");

pub fn main() {
    let proof_str = include_str!("../../../../examples/fibonacci/proof-with-pis.json");
    let proof: CurtaProofWithIO<BabyBearBlake3> =
        serde_json::from_str(proof_str).expect("loading proof failed");

    // Verify proof.
    println!("cycle-tracker-start: verify");
    CurtaVerifier::verify(FIBONACCI_ELF, &proof).expect("verification failed");
    println!("cycle-tracker-end: verify");
}
