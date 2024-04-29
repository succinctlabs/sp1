use sp1_sdk::{utils, ProverClient, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup logging.
    utils::setup_logger();

    // Create an input stream and write '500' to it.
    let n = 500u32;

    // The expected result of the fibonacci calculation
    let expected_a = 1926u32;
    let expected_b: u32 = 3194u32;

    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    // Generate the constant-sized proof for the given program and input.
    let client = ProverClient::new();
    // Only execute the program and get a `SP1PublicValues` object.
    let mut public_values = client.execute(&ELF, stdin).unwrap();

    println!("generated proof");

    // Read and verify the output.
    let _ = public_values.read::<u32>();
    let a = public_values.read::<u32>();
    let b = public_values.read::<u32>();
    assert_eq!(a, expected_a);
    assert_eq!(b, expected_b);

    println!("a: {}", a);
    println!("b: {}", b);
}
