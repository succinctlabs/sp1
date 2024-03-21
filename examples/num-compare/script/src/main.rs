//! A simple script to compare two numbers and generate or verify the proof of a given program.
use sp1_core::{utils, SP1Prover, SP1Stdin, SP1Verifier};

const JSON_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // setup tracer for logging.
    utils::setup_tracer();

    // Generate proof.
    let mut stdin = SP1Stdin::new();

    // Generic sample JSON (as a string input).
    let data_str = r#"
            {
                "num1": 10,
                "num2": 5,
                "operator": ">="
            }"#
    .to_string();
    let key = "operator".to_string();

    stdin.write(&data_str);
    stdin.write(&key);


    let mut proof = SP1Prover::prove(JSON_ELF, stdin).expect("proving failed");

    // Read output.
    let val = proof.stdout.read::<bool>();
    println!("Comparison result: {}", val);

    // Verify proof.
    SP1Verifier::verify(JSON_ELF, &proof).expect("verification failed");

    // Save proof.
    proof.save("proof-with-io.json").expect("saving proof failed");

    println!("successfully generated and verified proof for the program!");
}