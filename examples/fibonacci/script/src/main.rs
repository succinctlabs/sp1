use sp1_sdk::{utils, SP1ProofWithIO, SP1Prover, SP1Stdin, SP1Verifier};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Load bytes from file `proof`
    // let bytes = std::fs::read("proof").expect("reading proof failed");
    // let proof: SP1ProofWithIO<utils::BabyBearPoseidon2> = bincode::deserialize(&bytes).unwrap();
    // println!("proof: {:?}", proof.stdout.buffer.data);

    // Setup a tracer for logging.
    utils::setup_logger();

    // Create an input stream.
    let stdin = SP1Stdin::new();

    // Generate the proof for the given program.
    let proof = SP1Prover::prove(ELF, stdin).expect("proving failed");

    // Verify proof.
    SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // Save the proof.
    // proof
    //     .save("proof-with-pis.json")
    //     .expect("saving proof failed");

    let serialized = bincode::serialize(&proof).expect("serializing proof failed");
    let deserialized: SP1ProofWithIO<utils::BabyBearPoseidon2> =
        bincode::deserialize(&serialized).expect("deserializing proof failed");
    // assert_eq!(proof, deserialized);

    println!("successfully generated and verified proof for the program!")
}
