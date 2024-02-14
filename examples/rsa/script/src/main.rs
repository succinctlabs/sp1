use curta_core::{utils, CurtaProver, CurtaStdin, CurtaVerifier};

/// The ELF we want to execute inside the zkVM.
const RSA_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup a tracer for logging.
    utils::setup_tracer();

    let mut stdin = CurtaStdin::new();

    // Generate the proof for the given program and input.
    let proof = CurtaProver::prove(RSA_ELF, stdin).expect("proving failed");

    // Verify proof.
    CurtaVerifier::verify(RSA_ELF, &proof).expect("verification failed");

    // Save the proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
