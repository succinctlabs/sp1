use sp1_sdk::{utils, ProverClient, SP1Stdin};

const PATCH_TEST_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Generate proof.
    utils::setup_logger();

    let mut stdin = SP1Stdin::new();

    let client = ProverClient::new();
    let (pv, report) = client
        .execute(PATCH_TEST_ELF, stdin)
        .expect("proving failed");

    println!("Report: {:?}", report);
    println!("Total cycle count: {}", report.total_instruction_count());
    println!("successfully executed the program!")
}
