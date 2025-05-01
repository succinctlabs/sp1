//! An end-to-end example of using the SP1 SDK to generate a proof of a dice rolling program.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute --seed 12345
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove --seed 12345
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use dice_game_lib::{roll_dice, PublicValuesStruct};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const DICE_ELF: &[u8] = include_elf!("dice-game-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,
    
    #[arg(long)]
    prove: bool,
    
    #[arg(long, default_value = "12345")]
    seed: u32,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();
    
    // Parse the command line arguments.
    let args = Args::parse();
    
    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }
    
    // Setup the prover client.
    let client = ProverClient::from_env();
    
    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&args.seed);
    
    println!("Seed: {}", args.seed);
    
    if args.execute {
        // Execute the program
        let (output, report) = client.execute(DICE_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");
        
        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice()).unwrap();
        let PublicValuesStruct { seed, dice_roll } = decoded;
        
        println!("Seed: {}", seed);
        println!("Dice Roll: {}", dice_roll);
        
        let expected_roll = roll_dice(seed);
        assert_eq!(dice_roll, expected_roll);
        println!("Dice roll is correct and provably fair!");
        
        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(DICE_ELF);
        
        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");
        
        println!("Successfully generated proof!");
        
        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        
        println!("Successfully verified proof!");
        println!("Your dice roll is provably fair and can be verified by anyone!");
    }
}
