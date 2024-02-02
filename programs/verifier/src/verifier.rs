use std::hint::black_box;

// use clap::{command, Parser};
use p3_commit::Pcs;
use p3_field::{ExtensionField, PrimeField, PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;

use succinct_core::runtime::Program;
use succinct_core::runtime::Runtime;
use succinct_core::stark::types::SegmentProof;
use succinct_core::stark::StarkConfig;
use succinct_core::utils;
use succinct_core::utils::BabyBearPoseidon2;
use succinct_core::utils::StarkUtils;

// #[derive(Parser, Debug, Clone)]
// #[command(about = "Profile a program.")]
// struct VerifierArgs {
//     #[arg(long)]
//     pub program: String,

//     #[arg(long)]
//     pub proof_directory: String,
// }

fn main() {
    // let args = VerifierArgs::parse();

    // log::info!("Verifying proof: {}", args.proof_directory.as_str());
    utils::setup_logger();

    let proof_directory = "fib_proofs";
    let segment_proofs_json = include_str!("./fib_proofs/segment_proofs.json");
    let segment_proofs: Vec<SegmentProof<BabyBearPoseidon2>> =
        serde_json::from_str(segment_proofs_json).unwrap();

    let global_proof_json = include_str!("./fib_proofs/global_proof.json");
    let global_proof = serde_json::from_str(global_proof_json).unwrap();

    let config = BabyBearPoseidon2::new();
    let mut challenger = config.challenger();

    let program_elf = include_bytes!("../../../programs/fibonacci/elf/riscv32im-succinct-zkvm-elf");
    let program = Program::from(program_elf);
    let mut runtime = Runtime::new(program);
    runtime
        .verify::<_, _, BabyBearPoseidon2>(&config, &mut challenger, &segment_proofs, &global_proof)
        .unwrap();
}
