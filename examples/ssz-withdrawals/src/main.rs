use sp1_core::{utils, SP1Prover, SP1Stdin, SP1Verifier};

const ELF: &[u8] =
    include_bytes!("../../../programs/demo/ssz-withdrawals/elf/riscv32im-curta-zkvm-elf");

fn main() {
    // Generate proof.
    // utils::setup_tracer();
    utils::setup_logger();

    let stdin = SP1Stdin::new();
    let proof = SP1Prover::prove(ELF, stdin).expect("proving failed");

    // Verify proof.
    SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
