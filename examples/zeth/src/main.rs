use hex_literal::hex;
use std::fs::File;
use succinct_core::{utils, SuccinctProver, SuccinctStdin, SuccinctVerifier};
use zeth_lib::{input::Input, EthereumTxEssence};

const ZETH_ELF: &[u8] =
    include_bytes!("../../../programs/demo/zeth/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    utils::setup_logger();

    // Get inputs.
    let file = File::open("./fixtures/19116035.bin").unwrap();
    let input: Input<EthereumTxEssence> = bincode::deserialize_from(file).unwrap();
    let mut stdin = SuccinctStdin::new();
    stdin.write::<Input<EthereumTxEssence>>(&input);

    // Generate proof.
    let mut proof = SuccinctProver::prove(ZETH_ELF, stdin).expect("proving failed");

    // Read output.
    let result_hash = proof.stdout.read::<[u8; 32]>();
    let expected_hash = hex!("09ab1a9eed392e53193a9ab5201e81f7cbcdb3ed5f4c51f46e16589ad847e113");
    assert_eq!(result_hash, expected_hash);

    // Verify proof.
    SuccinctVerifier::verify(ZETH_ELF, &proof).expect("verification failed");
}
