//! A simple script to generate and verify the proof of a given program.

use curta_core::{utils, CurtaProver, CurtaStdin, CurtaVerifier};

const JSON_ELF: &[u8] = include_bytes!("../../../programs/demo/json/elf/riscv32im-curta-zkvm-elf");

fn main() {
    // setup tracer for logging.
    utils::setup_tracer();

    // Generate proof.
    let mut stdin = CurtaStdin::new();

    // Sample data.
    let data_str = r#"
            {
                "name": "John George",
                "age": "43",
                "net_worth" : "$1000000"
            }"#
    .to_string();
    let key = "net_worth".to_string();

    // write in simple JSON string and key.
    stdin.write(&data_str);
    stdin.write(&key);

    let mut proof = CurtaProver::prove(JSON_ELF, stdin).expect("proving failed");

    // Read output.
    let val = proof.stdout.read::<String>();
    println!("value of {} is {}", key, val);

    // Verify proof.
    CurtaVerifier::verify(JSON_ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
