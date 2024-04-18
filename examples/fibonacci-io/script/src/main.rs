use sha2::{Digest, Sha256};
use sp1_sdk::{utils, ProverClient, PublicValues, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup a tracer for logging.
    utils::setup_tracer();

    // Create an input stream and write '500' to it.
    let n = 500u32;

    // The expected result of the fibonacci calculation
    let expected_a = 2081405077u32;
    let expected_b = 315178285u32;

    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    // Generate the proof for the given program and input.
    let client = ProverClient::new();
    let mut proof = client.prove(ELF, stdin).unwrap();

    println!("generated proof");

    // Read and verify the output.
    let n: u32 = proof.public_values.read::<u32>();
    let a = proof.public_values.read::<u32>();
    let b = proof.public_values.read::<u32>();
    assert_eq!(a, expected_a);
    assert_eq!(b, expected_b);

    println!("a: {}", a);
    println!("b: {}", b);

    // Verify proof and public values
    client.verify(ELF, &proof).expect("verification failed");

    let mut pv_hasher = Sha256::new();
    pv_hasher.update(n.to_le_bytes());
    pv_hasher.update(expected_a.to_le_bytes());
    pv_hasher.update(expected_b.to_le_bytes());
    let expected_pv_digest: &[u8] = &pv_hasher.finalize();

    let public_values_bytes = proof.proof.shard_proofs[0].public_values.clone();
    let public_values = PublicValues::from_vec(public_values_bytes);
    assert_eq!(
        public_values.commit_digest_bytes().as_slice(),
        expected_pv_digest
    );

    // Save the proof.
    proof
        .save("proof-with-pis.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
