use sp1_sdk::{ProverClient, SP1Stdin};

use ark_circom::{CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;

use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;

use lib::{
    SerdeSerializableInputs, SerdeSerializablePreparedVerifyingKey, SerdeSerializableProof,
    SerializableInputs, SerializablePreparedVerifyingKey, SerializableProof,
};

type GrothBn = Groth16<Bn254>;
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    let cfg = CircomConfig::<Bn254>::new(
        "./test-vectors/mycircuit.wasm",
        "./test-vectors/mycircuit.r1cs",
    )
    .unwrap();

    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 11);

    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng).unwrap();

    let circom = builder.build().unwrap();

    let inputs = circom.get_public_inputs().unwrap();

    let proof = GrothBn::prove(&params, circom, &mut rng).unwrap();

    let pvk = GrothBn::process_vk(&params.vk).unwrap();

    println!("Inputs: {:?}", inputs);
    println!("Proof: {:?}", proof);

    let verified = GrothBn::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();

    println!("Proof verified: {}", verified);

    assert!(verified);

    // Write the pvk, inputs, and proof to the zkVM's input
    let mut stdin = SP1Stdin::new();
    stdin.write(&SerdeSerializablePreparedVerifyingKey::from(
        SerializablePreparedVerifyingKey(pvk),
    ));
    stdin.write(&SerdeSerializableInputs::from(SerializableInputs(inputs)));
    stdin.write(&SerdeSerializableProof::from(SerializableProof(proof)));

    // Generate proof for the zkVM program
    let client = ProverClient::new();
    let mut zkvm_proof = client.prove(ELF, stdin).expect("proving failed");

    // Read output.
    let groth16_verified = zkvm_proof.public_values.read::<bool>();
    println!("groth16_verified: {}", groth16_verified);

    // Verify the zkVM proof
    client
        .verify(ELF, &zkvm_proof)
        .expect("verification failed");

    // Save the zkVM proof
    zkvm_proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the zkVM program!");
}
