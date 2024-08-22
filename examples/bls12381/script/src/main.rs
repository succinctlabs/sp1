use sp1_sdk::{utils, ProverClient, SP1Stdin};
pub const ELF: &[u8] = include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    utils::setup_logger();

    let mut stdin = SP1Stdin::new();

    let client = ProverClient::new();
    let (mut public_values, _) = client.execute(ELF, stdin).run().expect("failed to prove");
}
