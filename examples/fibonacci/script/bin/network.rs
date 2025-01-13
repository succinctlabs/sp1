use sp1_sdk::{
    include_elf, network::Error, utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin,
};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci-program");

fn main() {
    // Setup logging.
    utils::setup_logger();

    // Create an input stream and write '500' to it.
    let n = 1000u32;

    // The input stream that the program will read from using `sp1_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    // Create a `ProverClient` method.
    let client = ProverClient::from_env();

    // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);
    let proof_result = client.prove(&pk, &stdin).compressed().run();

    // Handle possible prover network errors.
    let mut proof = match proof_result {
        Ok(proof) => proof,
        Err(e) => {
            if let Some(network_error) = e.downcast_ref::<Error>() {
                match network_error {
                    Error::RequestUnexecutable { request_id: _ } => {
                        eprintln!("Program is unexecutable: {}", e);
                        std::process::exit(1);
                    }
                    Error::RequestUnfulfillable { request_id: _ } => {
                        eprintln!("Proof request cannot be fulfilled: {}", e);
                        std::process::exit(1);
                    }
                    _ => {
                        eprintln!("Unexpected error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("Unexpected error: {}", e);
                std::process::exit(1);
            }
        }
    };

    println!("generated proof");

    // Read and verify the output.
    //
    // Note that this output is read from values committed to in the program using
    // `sp1_zkvm::io::commit`.
    let _ = proof.public_values.read::<u32>();
    let a = proof.public_values.read::<u32>();
    let b = proof.public_values.read::<u32>();

    println!("a: {}", a);
    println!("b: {}", b);

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        SP1ProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
