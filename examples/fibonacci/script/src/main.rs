use sp1_sdk::{utils, ProverClient, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");
use peak_alloc::PeakAlloc;

#[global_allocator]
static PEAK_ALLOC: PeakAlloc = PeakAlloc;

#[no_mangle]
extern "Rust" fn print_memory(message: &str) {
    let current_mb = PEAK_ALLOC.current_usage_as_mb();
    let peak_mb = PEAK_ALLOC.peak_usage_as_mb();
    println!(
        "[mem] {}: current {} MB, peak {} MB",
        message, current_mb, peak_mb
    );
}

fn main() {
    // Setup logging.
    utils::setup_logger();

    // Create an input stream and write '500' to it.
    let n = 500u32;

    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    // Generate the proof for the given program and input.
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    print_memory("before");
    let mut proof = client.prove_compressed(&pk, stdin).unwrap();
    print_memory("after");

    println!("generated proof");

    // Read and verify the output.
    let _ = proof.public_values.read::<u32>();
    let a = proof.public_values.read::<u32>();
    let b = proof.public_values.read::<u32>();

    println!("a: {}", a);
    println!("b: {}", b);

    // Verify proof and public values
    client
        .verify_compressed(&proof, &vk)
        .expect("verification failed");

    // Save the proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
