use sp1_sdk::{utils, ProverClient, SP1Stdin};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup logging.
    utils::setup_logger();

    // Create an input stream and write '500' to it.
    let n = 500u32;

    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    // Only execute the program and get a `SP1PublicValues` object.
    let client = ProverClient::new();
    let (mut public_values, execution_report) = client.execute(ELF, stdin).run().unwrap();

    // Print the total number of cycles executed and the full execution report with a breakdown of
    // the RISC-V opcode and syscall counts.
    println!(
        "Executed program with {} cycles",
        execution_report.total_instruction_count() + execution_report.total_syscall_count()
    );
    println!("Full execution report:\n{:?}", execution_report);

    // Read and verify the output.
    let _ = public_values.read::<u32>();
    let a = public_values.read::<u32>();
    let b = public_values.read::<u32>();

    println!("a: {}", a);
    println!("b: {}", b);
}
