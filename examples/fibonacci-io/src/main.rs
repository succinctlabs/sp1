use succinct_core::{SuccinctProver, SuccinctStdin};

const FIBONACCI_IO_ELF: &[u8] =
    include_bytes!("../../../programs/demo/fibonacci-io/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
    let mut stdin = SuccinctStdin::new();
    stdin.write(&5000u32);
    let mut proof = SuccinctProver::prove(FIBONACCI_IO_ELF, stdin).expect("proving failed");

    // Read output.
    let a = proof.stdout.read::<u32>();
    let b = proof.stdout.read::<u32>();
    println!("a: {}", a);
    println!("b: {}", b);

    // Verify proof.
    // SuccinctVerifier::verify(FIBONACCI_IO_ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
