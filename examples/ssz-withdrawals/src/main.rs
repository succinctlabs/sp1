use curta_core::{utils, CurtaProver, CurtaStdin, CurtaVerifier};

const ELF: &[u8] =
    include_bytes!("../../../programs/demo/ssz-withdrawals/elf/riscv32im-curta-zkvm-elf");

fn main() {
    // Generate proof.
    // utils::setup_tracer();
    utils::setup_logger();

    let stdin = CurtaStdin::new();
    let proof = CurtaProver::prove(ELF, stdin).expect("proving failed");

    // Verify proof.
    CurtaVerifier::verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
