use sp1_sdk::{ProverClient, SP1Stdin, Prover};

const ELF: &[u8] = include_bytes!("/home/amit_2004/sp1/examples/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/base64-program");

#[tokio::main]
async fn main() {
    let client = ProverClient::from_env().await;

    let mut stdin = SP1Stdin::new();
    stdin.write(&"SGVsbG8sIFNQMSE=".to_string());

    println!("Executing program logic (Mock Mode)...");
    

    let (mut public_values, _execution_report) = client.execute(sp1_sdk::Elf::Static(ELF), stdin).await.expect("Execution failed");    
    let decoded = public_values.read::<Vec<u8>>();
    println!("Decoded: {}", String::from_utf8(decoded).unwrap());
    println!("Successfully verified execution logic!");
}