use sp1_sdk::{include_elf, utils, ProverClient, SP1Stdin};
pub const ELF: &[u8] = include_elf!("bls12381-program");

fn main() {
    utils::setup_logger();

    let stdin = SP1Stdin::new();

    let client = ProverClient::new();
    let (_public_values, report) =
        client.execute(ELF, stdin.clone()).run().expect("failed to prove");
    println!("report: {:?}", report.total_instruction_count());

    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin).compressed().run().unwrap();

    client.verify(&proof, &vk).unwrap();
}
