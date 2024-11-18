use sp1_core_executor::{Executor, Program};
use sp1_sdk::{include_elf, utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use sp1_stark::SP1CoreOpts;
/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci-program");
const PROGRAM: &[u8] = include_bytes!("../../program_taiko");
const STDIN: &[u8] = include_bytes!("../../stdin_taiko");

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
    let client = ProverClient::new();
    let program: Vec<u8> = bincode::deserialize(PROGRAM).unwrap();
    let program = Program::from(&program).unwrap();

    // let program: Program = bincode::deserialize(PROGRAM).unwrap();
    let stdin: SP1Stdin = bincode::deserialize(STDIN).unwrap();

    let mut runtime = Executor::new(program, SP1CoreOpts::default());
    runtime.write_vecs(&stdin.buffer);
    runtime.run().unwrap();

    // // Execute the program using the `ProverClient.execute` method, without generating a proof.
    // let (_, report) = client.execute(ELF, stdin.clone()).run().unwrap();
    // println!("executed program with {} cycles", report.total_instruction_count());

    // // Generate the proof for the given program and input.
    // let (pk, vk) = client.setup(ELF);
    // let mut proof = client.prove(&pk, stdin).run().unwrap();

    // println!("generated proof");

    // // Read and verify the output.
    // //
    // // Note that this output is read from values committed to in the program using
    // // `sp1_zkvm::io::commit`.
    // let _ = proof.public_values.read::<u32>();
    // let a = proof.public_values.read::<u32>();
    // let b = proof.public_values.read::<u32>();

    // println!("a: {}", a);
    // println!("b: {}", b);

    // // Verify proof and public values
    // client.verify(&proof, &vk).expect("verification failed");

    // // Test a round trip of proof serialization and deserialization.
    // proof.save("proof-with-pis.bin").expect("saving proof failed");
    // let deserialized_proof =
    //     SP1ProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // // Verify the deserialized proof.
    // client.verify(&deserialized_proof, &vk).expect("verification failed");

    // println!("successfully generated and verified proof for the program!")
}
