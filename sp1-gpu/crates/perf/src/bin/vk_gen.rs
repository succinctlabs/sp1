/*
This script generates a verification key (VK) map for a given SP1 program and input. It performs the following steps:
1. Loads the specified SP1 program and input.
2. Initializes a local SP1 prover node.
3. Generates a core proof for the program and input.
4. Identifies the core shard shapes used in the proof.
5. Builds the VK map based on the identified shapes (and the compose, shrink, and deferred shapes)
    and saves it to a temporary file. This uses the SP1LocalNode `build_vks` method.
6. Re-initializes the prover node with VK verification enabled, using the generated VK map.
7. Proves the program again to ensure that VK verification works correctly.

Usage:
`RUST_LOG=debug cargo run --profile lto --bin vk_gen -- --program <program_name> --param <parameter>`


 */
use std::collections::BTreeSet;

use clap::Parser;
use either::Either;
use sp1_core_executor::SP1Context;
use sp1_gpu_perf::get_program_and_input;
use sp1_gpu_prover::cuda_worker_builder;
use sp1_prover::{
    shapes::{SP1RecursionProgramShape, DEFAULT_ARITY},
    worker::{SP1LocalNodeBuilder, SP1Proof},
    CpuSP1ProverComponents, SP1ProverComponents,
};
use sp1_prover_types::network_base_types::ProofMode;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "local-fibonacci")]
    pub program: String,
    #[arg(long, default_value = "")]
    pub param: String,
}

#[tokio::main]
#[allow(clippy::field_reassign_with_default)]
async fn main() {
    let args = Args::parse();

    // Load the environment variables.
    dotenv::dotenv().ok();
    sp1_gpu_tracing::init_tracer();

    // Get the program and input.
    let (elf, stdin) = get_program_and_input(args.program.clone(), args.param);

    // Initialize the AirProver and permits
    sp1_gpu_cudart::spawn(move |t| async move {
        let node =
            SP1LocalNodeBuilder::from_worker_client_builder(cuda_worker_builder(t.clone()).await)
                .build()
                .await
                .unwrap();

        // Use a temporary directory for the vk_map file to avoid conflicts
        let temp_dir = std::env::current_dir().unwrap();
        let vk_map_path = temp_dir.join("vk_map.bin");

        // Clean up any existing file from previous runs
        let _ = std::fs::remove_file(&vk_map_path);

        let proof = node
            .prove_with_mode(&elf, stdin.clone(), SP1Context::default(), ProofMode::Core)
            .await
            .expect("Failed to prove");

        // Create all circuit shapes.
        let shapes = sp1_prover::shapes::create_all_input_shapes(
            CpuSP1ProverComponents::core_verifier().shard_verifier().machine().shape(),
            DEFAULT_ARITY,
        );

        // Determine the indices in `shapes` of the shapes appear in the proof.
        let mut shape_indices = vec![];

        let core_proof = match proof.proof {
            SP1Proof::Core(proof) => proof,
            _ => panic!("Expected core proof"),
        };

        for proof in &core_proof {
            let shape = SP1RecursionProgramShape::Normalize(
                CpuSP1ProverComponents::core_verifier().shape_from_proof(proof),
            );

            let index = shapes.iter().position(|s| *s == shape).expect("Shape not found in shapes");

            shape_indices.push(index);
        }

        let shape_indices = shape_indices
            .into_iter()
            .chain(shapes.len() - 12..shapes.len())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        let result = node.build_vks(Some(Either::Left(shape_indices)), 4).await.unwrap();

        let vk_map_path = temp_dir.join("vk_map.bin");

        // Create the file to store the vk map.
        let mut file = std::fs::File::create(vk_map_path.clone()).unwrap();

        bincode::serialize_into(&mut file, &result.vk_map).unwrap();

        drop(node);

        t.synchronize().await.unwrap();

        // Build a new prover that performs the vk verification check using the built vk map.
        let node = SP1LocalNodeBuilder::from_worker_client_builder(
            cuda_worker_builder(t.clone())
                .await
                .with_vk_map_path(vk_map_path.to_str().unwrap().to_string()),
        )
        .build()
        .await
        .unwrap();

        // Make a proof to get proof shapes to populate the vk map with.
        let vk = node.setup(&elf).await.expect("Failed to setup");

        tracing::info!("Rebuilt prover with vk map.");

        // Make a proof to get proof shapes to populate the vk map with.
        let proof = node
            .prove_with_mode(&elf, stdin, SP1Context::default(), ProofMode::Compressed)
            .await
            .expect("Failed to prove");

        node.verify(&vk, &proof.proof).unwrap();

        std::fs::remove_file(vk_map_path).unwrap();
    })
    .await
    .unwrap();
}
