use clap::Parser;
use sp1_sdk::{ProverClient, SP1Stdin};
use std::time::SystemTime;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long, default_value = "20")]
    n: u32,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    let start = SystemTime::now();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    println!(
        "\n Setup prover client (at {} sec)..",
        start.elapsed().unwrap().as_secs()
    );
    let client = ProverClient::new();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&args.n);

    println!("n: {}", args.n);

    // Setup the program for proving.
    println!(
        "\n Setup the program (at {} sec)..",
        start.elapsed().unwrap().as_secs()
    );
    let (pk, vk) = client.setup(ELF);

    // Generate the proof
    println!(
        "\n Generating proof (at {} sec)..",
        start.elapsed().unwrap().as_secs()
    );
    let proof = client
        .prove(&pk, stdin)
        .run()
        .expect("failed to generate proof");

    println!("Successfully generated proof!");

    // Verify the proof.
    println!(
        "\n Verifying proof (at {} sec)..",
        start.elapsed().unwrap().as_secs()
    );
    client.verify(&proof, &vk).expect("failed to verify proof");
    println!("Successfully verified proof!");
}