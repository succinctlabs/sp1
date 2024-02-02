use std::fs;

// use clap::{command, Parser};
use std::process::exit;
use succinct_core::runtime::Program;
use succinct_core::runtime::Runtime;
use succinct_core::utils::BabyBearPoseidon2;
use succinct_core::utils::StarkUtils;

// #[derive(Parser, Debug, Clone)]
// #[command(about = "Profile a program.")]
// struct ProverArgs {
//     #[arg(long)]
//     pub program: String,

//     #[arg(long)]
//     pub proof_directory: String,
// }

fn main() {
    // let args = ProverArgs::parse();

    // log::info!("Proving program: {}", args.program.as_str());

    // let program = Program::from_elf(args.program.as_str());

    let program = Program::from_elf("../../programs/fibonacci/elf/riscv32im-succinct-zkvm-elf");

    let mut runtime = Runtime::new(program);
    runtime.run();

    let config = BabyBearPoseidon2::new();
    let mut challenger = config.challenger();

    // Prove the program.
    let (segment_proofs, global_proof) =
        runtime.prove::<_, _, BabyBearPoseidon2>(&config, &mut challenger);

    // Attempt to create the directory
    // let directory_name = args.proof_directory.as_str();
    let directory_name = "fib_proofs";
    match fs::create_dir(directory_name) {
        Ok(_) => (),
        Err(e) => {
            log::error!("Error creating directory: {}", e);
            exit(1);
        }
    }

    // Create the segment proofs file
    let segment_proofs_file_name = format!("{}/segment_proofs.json", directory_name);
    let segment_proofs_json = serde_json::to_string(&segment_proofs).unwrap();
    match fs::write(segment_proofs_file_name, segment_proofs_json) {
        Ok(_) => (),
        Err(e) => {
            log::error!("Error writing segment proofs file: {}", e);
            exit(1);
        }
    }

    // Save the global proof
    let global_proof_file_name = format!("{}/global_proof.json", directory_name);
    let global_proof_json = serde_json::to_string(&global_proof).unwrap();
    match fs::write(global_proof_file_name, global_proof_json) {
        Ok(_) => (),
        Err(e) => {
            log::error!("Error writing global proof file: {}", e);
            exit(1);
        }
    }

    // Verify the proof.
    let mut challenger = config.challenger();
    runtime
        .verify::<_, _, BabyBearPoseidon2>(&config, &mut challenger, &segment_proofs, &global_proof)
        .unwrap();
}
