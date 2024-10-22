use sp1_sdk::{include_elf, utils, ProverClient, SP1Stdin};
pub const ELF: &[u8] = include_elf!("bls12381-program");

fn main() {
    utils::setup_logger();

    let stdin = SP1Stdin::new();

    let client = ProverClient::new();
    let (_public_values, _) = client.execute(ELF, stdin.clone()).run().expect("failed to prove");

    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).run().unwrap();

    client.verify(&proof, &vk).unwrap();
}
