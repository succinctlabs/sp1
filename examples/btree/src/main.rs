use curta_core::{CurtaProver, CurtaStdin, CurtaVerifier};
use std::collections::BTreeMap;

const ELF: &[u8] = include_bytes!("../../../programs/demo/btree/elf/riscv32im-curta-zkvm-elf");

fn main() {
    let mut stdin = CurtaStdin::new();

    // Prepare b-tree being operated on and key-value pair to be inserted.
    let tree: BTreeMap<String, String> = BTreeMap::new();
    let key = "key".to_string();
    let value = "value".to_string();

    // Write input to stdin.
    stdin.write(&tree);
    stdin.write(&key);
    stdin.write(&value);

    // Generate proof.
    let mut proof = CurtaProver::prove(ELF, stdin).expect("proving failed");

    // Read output.
    let result = proof.stdout.read::<BTreeMap<String, String>>();
    let insert_successful = result.contains_key(&key);
    println!("Insertion successful: {}", insert_successful);

    // Verify proof.
    CurtaVerifier::verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("succesfully generated and verified proof for the program!")
}
