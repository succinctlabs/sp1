use curta_core::{utils, CurtaProver, CurtaStdin, CurtaVerifier};

/// The ELF we want to execute inside the zkVM.
const FIBONACCI_IO_ELF: &[u8] =
    include_bytes!("../../../programs/demo/fibonacci-io/elf/riscv32im-curta-zkvm-elf");

fn main() {
    // Setup a tracer for logging.
    utils::setup_tracer();

    // Create an input stream and write '5000' to it.
    let mut stdin = CurtaStdin::new();
    stdin.write(&5000u32);

    // Generate the proof for the given program and input.
    let mut proof = CurtaProver::prove(FIBONACCI_IO_ELF, stdin).expect("proving failed");

    // Read the output.
    let a = proof.stdout.read::<u32>();
    let b = proof.stdout.read::<u32>();
    println!("a: {}", a);
    println!("b: {}", b);

    // Verify proof.
    CurtaVerifier::verify(FIBONACCI_IO_ELF, &proof).expect("verification failed");

    // Save the proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
