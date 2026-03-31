use powdr_autoprecompiles::PgoConfig;
use sp1_build::include_elf;
use sp1_build::Elf;
use sp1_core_executor::Program;
use sp1_core_machine::autoprecompiles::execution_profile_from_program;
use sp1_core_machine::autoprecompiles::sp1_powdr_config;
use sp1_core_machine::autoprecompiles::CompiledProgram;
use sp1_core_machine::io::SP1Stdin;
use sp1_sdk::prelude::*;
use sp1_sdk::{ProverClient, SP1ProofMode};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use rsp_client_executor::{io::ClientExecutorInput, CHAIN_ID_ETH_MAINNET};
use sp1_sdk::Prover;
use std::path::PathBuf;
use std::time::Instant;

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("rsp-program");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Execute the RSP program
    Execute,
    /// Generate APCs using Powdr
    Powdr,
    /// Prove the RSP program
    Prove {
        /// Number of APCs to enable (0 = disabled)
        #[arg(long, default_value_t = 0)]
        apcs: usize,
        /// Proof mode: "core" or "compress"
        #[arg(long, default_value = "core")]
        mode: String,
    },
}

fn load_input_from_cache(chain_id: u64, block_number: u64) -> ClientExecutorInput {
    let cache_path = PathBuf::from(format!("./input/{}/{}.bin", chain_id, block_number));
    let mut cache_file = std::fs::File::open(cache_path).unwrap();
    let client_input: ClientExecutorInput = bincode::deserialize_from(&mut cache_file).unwrap();

    client_input
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();

    // Load the input from the cache.
    // let block = 20526624; // ~2.4M Gas
    // let block = 21740164; // ~15M Gas
    let block = 21740137; // ~29M Gas
    let client_input = load_input_from_cache(CHAIN_ID_ETH_MAINNET, block);
    let mut stdin = SP1Stdin::default();
    let buffer = bincode::serialize(&client_input).unwrap();
    stdin.write_vec(buffer);

    let program = Arc::new(Program::from(&ELF).unwrap());

    match args.command {
        Commands::Execute => {
            // Create a `MockProver` because we only need to execute. Use no apcs.
            let client = sp1_sdk::MockProver::new().await;

            let (_, report) = client.execute(ELF, stdin.clone()).await.unwrap();
            println!("executed program with {} cycles", report.total_instruction_count());

            println!("Report {:?}", report);
        }
        Commands::Powdr => {
            println!("[powdr] Getting execution profile...");
            let execution_profile = execution_profile_from_program(program, stdin);

            println!("[powdr] Generating APCs...");
            let path = std::path::Path::new("apc_candidates");
            let config = sp1_powdr_config(1, 0).with_apc_candidates_dir(path);
            let pgo_config = PgoConfig::Cell(execution_profile, None);
            let _compiled_program = CompiledProgram::new(&ELF, config, pgo_config);

            println!("[powdr] Done!");
        }
        Commands::Prove { apcs, mode } => {
            let total_start = Instant::now();

            let mode = match mode.as_str() {
                "core" => SP1ProofMode::Core,
                "compress" => SP1ProofMode::Compressed,
                _ => panic!("Unknown mode: {mode}. Use 'core' or 'compress'."),
            };

            // Generate APCs if requested
            let apcs = if apcs > 0 {
                println!("[powdr] Getting execution profile...");
                let stage_start = Instant::now();
                let execution_profile = execution_profile_from_program(program, stdin.clone());

                println!("[powdr] Generating {} APCs...", apcs);
                let path = std::path::Path::new("apc_candidates");
                let config = sp1_powdr_config(apcs as u64, 0).with_apc_candidates_dir(path);
                let pgo_config = PgoConfig::Cell(execution_profile, None);
                let compiled_program = CompiledProgram::new(&ELF, config, pgo_config);
                println!("[powdr] Done! ({:.2}s)", stage_start.elapsed().as_secs_f64());

                compiled_program
                    .apcs_and_stats
                    .into_iter()
                    .map(|a| a.into_parts())
                    .map(|(apc, _, _)| apc)
                    .collect()
            } else {
                Vec::new()
            };

            let machine = RiscvAir::machine_with_apcs(apcs);

            let client = ProverClient::from_env_with_machine(machine).await;

            // Setup
            println!("Setting up...");
            let stage_start = Instant::now();
            let pk = client.setup(ELF).await.expect("setup failed");
            println!("Setup done ({:.2}s)", stage_start.elapsed().as_secs_f64());

            // Prove
            println!("Starting proving (mode={mode:?})...");
            let stage_start = Instant::now();
            let proof = client.prove(&pk, stdin).mode(mode).await.expect("proving failed");

            println!("Proving done! ({:.2}s)", stage_start.elapsed().as_secs_f64());

            // Verify
            println!("Verifying proof...");
            let stage_start = Instant::now();
            // Verify proof.
            client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
            println!("Verification done! ({:.2}s)", stage_start.elapsed().as_secs_f64());

            println!("\n=== TOTAL ===\nTotal time: {:.2}s", total_start.elapsed().as_secs_f64());
        }
    }
}
