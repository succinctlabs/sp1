use succinct_core::{utils, SuccinctProver, SuccinctVerifier};

const FIBONACCI_IO_ELF: &[u8] =
    include_bytes!("../../../programs/demo/fibonacci-io/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup.
    utils::setup_logger();

    // Generate proof.
    let mut prover = SuccinctProver::new();
    prover.write_stdin(&5000u32);
    let mut proof = prover.prove(FIBONACCI_IO_ELF);

    // Read output.
    let result = proof.read_stdout::<u32>();
    println!("result: {}", result);

    // Verify proof.
    let verifier = SuccinctVerifier::new();
    verifier
        .verify(FIBONACCI_IO_ELF, &proof)
        .expect("verification failed");

    println!("succesfully generated and verified proof for the program!")
}
