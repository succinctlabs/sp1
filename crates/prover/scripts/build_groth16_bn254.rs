use std::path::PathBuf;

use clap::Parser;
use sp1_core_machine::utils::setup_logger;
use sp1_hypercube::{MachineVerifyingKey, SP1PcsProofOuter, ShardProof};
use sp1_primitives::SP1OuterGlobalContext;
use sp1_prover::{build::build_groth16_bn254_artifacts, verify::WRAP_VK_BYTES};

/// The wrapped proof used as a template for building the circuit.
const WRAPPED_PROOF_BYTES: &[u8] = include_bytes!("../wrapped_proof.bin");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    build_dir: PathBuf,
}

pub fn main() {
    setup_logger();
    let args = Args::parse();

    tracing::info!("loading wrap vk and wrapped proof");
    let wrap_vk: MachineVerifyingKey<SP1OuterGlobalContext> =
        bincode::deserialize(WRAP_VK_BYTES).expect("failed to deserialize wrap vk");
    let wrapped_proof: ShardProof<SP1OuterGlobalContext, SP1PcsProofOuter> =
        bincode::deserialize(WRAPPED_PROOF_BYTES).expect("failed to deserialize wrapped proof");

    tracing::info!("building groth16 bn254 artifacts to {:?}", args.build_dir);
    build_groth16_bn254_artifacts(&wrap_vk, &wrapped_proof, &args.build_dir)
        .expect("failed to build groth16 artifacts");

    tracing::info!("done");
}
