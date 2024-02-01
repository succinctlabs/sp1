use hex_literal::hex;
use std::{fs::File, io::Read};
use succinct_core::{utils, SuccinctProver};
use zeth_lib::{input::Input, EthereumTxEssence};

const ZETH_ELF: &[u8] = include_bytes!("../../../programs/zeth/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    utils::setup_logger();

    let file = File::open("./fixtures/19116035.bin").unwrap();
    let input: Input<EthereumTxEssence> = bincode::deserialize_from(file).unwrap();

    let mut prover = SuccinctProver::new();
    prover.write_stdin::<Input<EthereumTxEssence>>(&input);
    let mut runtime = prover.run(ZETH_ELF);
    let mut result_hash = [0u8; 32];
    runtime.read_exact(&mut result_hash);
    let expected_hash = hex!("09ab1a9eed392e53193a9ab5201e81f7cbcdb3ed5f4c51f46e16589ad847e113");
    assert_eq!(result_hash, expected_hash);

    prover.prove(&mut runtime);
}
