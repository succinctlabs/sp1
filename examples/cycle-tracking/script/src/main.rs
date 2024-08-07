use sp1_sdk::{utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin};

/// The ELF with normal cycle tracking.
const NORMAL_ELF: &[u8] = include_bytes!("../../program/elf/normal");

/// The ELF with cycle tracking that gets added to the execution report.
const REPORT_ELF: &[u8] = include_bytes!("../../program/elf/report");

fn main() {
    // Setup a tracer for logging.
    utils::setup_logger();

    // Create an input stream.
    let stdin = SP1Stdin::new();

    // Generate the proof for the cycle tracking program.
    let client = ProverClient::new();

    // Execute the normal ELF, which shows the cycle tracking.
    let (_, report) = client
        .execute(NORMAL_ELF, stdin.clone())
        .run()
        .expect("execution failed");

    // Execute the report ELF, and print the tracked cycles added to the report.
    let (_, report) = client
        .execute(REPORT_ELF, stdin.clone())
        .run()
        .expect("execution failed");

    // Print the cycles added to the report.
    // Print all the keys from report.cycle_tracker.
    for (key, value) in report.cycle_tracker {
        println!("{}: {}", key, value);
    }
}
