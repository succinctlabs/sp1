use succinct_core::{SuccinctProver, SuccinctStdin, SuccinctVerifier};

const ED25519_ELF: &[u8] =
    include_bytes!("../../../programs/demo/ed25519/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
    let stdin = SuccinctStdin::new();
    let proof = SuccinctProver::prove(ED25519_ELF, stdin).expect("proving failed");

    // Verify proof.
    SuccinctVerifier::verify(ED25519_ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
