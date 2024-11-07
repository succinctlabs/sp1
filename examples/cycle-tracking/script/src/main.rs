use sp1_sdk::{include_elf, utils, ProverClient, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const REPORT_ELF: &[u8] = include_elf!("report");
const NORMAL_ELF: &[u8] = include_elf!("normal");

fn main() {
    // Setup a tracer for logging.
    utils::setup_logger();

    // Execute the normal program.
    let client = ProverClient::new();
    let (_, _) = client.execute(NORMAL_ELF, SP1Stdin::new()).run().expect("proving failed");

    // Execute the report program.
    let (_, report) = client.execute(REPORT_ELF, SP1Stdin::new()).run().expect("proving failed");

    // Get the "setup" cycle count from the report program.
    let setup_cycles = report.cycle_tracker.get("setup").unwrap();
    println!("Using cycle-tracker-report saves the number of cycles to the cycle-tracker mapping in the report.\nHere's the number of cycles used by the setup: {}", setup_cycles);
}
