use succinct_core::{utils, SuccinctProver, SuccinctStdin, SuccinctVerifier};

const ELF: &[u8] =
    include_bytes!("../../../programs/demo/ssz-withdrawals/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
    // utils::setup_tracer();
    utils::setup_logger();

    let stdin = SuccinctStdin::new();
    let proof = SuccinctProver::prove(ELF, stdin).expect("proving failed");

    // Verify proof.
    SuccinctVerifier::verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
