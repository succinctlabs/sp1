use sp1_sdk::{include_elf, utils, ProverClient, SP1Stdin};
pub const ELF: &[u8] = include_elf!("bn254-program");

fn main() {
    utils::setup_logger();

    let stdin = SP1Stdin::new();

    let client = ProverClient::new();
    let (_public_values, report) = client.execute(ELF, stdin).run().expect("failed to prove");

    println!("executed: {}", report);
}
