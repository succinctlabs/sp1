//! A program that takes a number `n` as input, and writes if `n` is prime as an output.
use sp1_sdk::ProverClient;
use sp1_sdk::prelude::*;

const ELF: Elf = include_elf!("untrusted-program-program");

#[tokio::main]
async fn main() {
    // Setup a tracer for logging.
    sp1_sdk::utils::setup_logger();

    let mut stdin = SP1Stdin::new();

    // Set the flags to true to test the failure cases.
    let execute_prot_should_fail = false;
    let test_prot_none_fail = false;

    stdin.write(&execute_prot_should_fail);
    stdin.write(&test_prot_none_fail);

    let client = ProverClient::from_env().await;

    let pk = client.setup(ELF).await.expect("setup failed");

    // Execute the program.
    let (_, execution_report) = client.execute(ELF, stdin.clone()).await.unwrap();

    let proof = client.prove(&pk, stdin.clone()).await.expect("proving failed");

    // Verify proof.
    client.verify(&proof, pk.verifying_key(), None).expect("verification failed");

    // Print the total number of cycles executed and the full execution report with a breakdown of
    // the RISC-V opcode and syscall counts.
    println!(
        "Executed program with {} cycles",
        execution_report.total_instruction_count() + execution_report.total_syscall_count()
    );
    println!("Full execution report:\n{:?}", execution_report);    
}
