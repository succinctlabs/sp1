use std::{fs::File, path::PathBuf};

use clap::Parser;
use p3_baby_bear::BabyBear;
use sp1_core_machine::{riscv::CoreShapeConfig, utils::setup_logger};
use sp1_prover::{utils::get_all_vk_digests, InnerSC, REDUCE_BATCH_SIZE};
use sp1_recursion_circuit_v2::merkle_tree::MerkleTree;
use sp1_recursion_core_v2::shape::RecursionShapeConfig;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: PathBuf,
    #[clap(short, long)]
    dummy: bool,
    #[clap(short, long, default_value_t = REDUCE_BATCH_SIZE)]
    reduce_batch_size: usize,
}

fn main() {
    setup_logger();
    let args = Args::parse();

    let reduce_batch_size = args.reduce_batch_size;
    let build_dir = args.build_dir;

    let core_shape_config = CoreShapeConfig::default();
    let recursion_shape_config = RecursionShapeConfig::default();

    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");

    tracing::info!("building compress vk map");
    let vk_map = get_all_vk_digests(&core_shape_config, &recursion_shape_config, reduce_batch_size);
    tracing::info!("compress vks generated, number of keys: {}", vk_map.len());

    // Save the vk map to a file.
    tracing::info!("saving vk map to file");
    let vk_map_path = build_dir.join("vk_map.bin");
    let mut vk_map_file = File::create(vk_map_path).unwrap();
    bincode::serialize_into(&mut vk_map_file, &vk_map).unwrap();
    tracing::info!("File saved successfully.");

    // Build a merkle tree from the vk map.
    tracing::info!("building merkle tree");
    let (root, merkle_tree) =
        MerkleTree::<BabyBear, InnerSC>::commit(vk_map.keys().cloned().collect());

    // Saving merkle tree data to file.
    tracing::info!("saving merkle tree to file");
    let merkle_tree_path = build_dir.join("merkle_tree.bin");
    let mut merkle_tree_file = File::create(merkle_tree_path).unwrap();
    bincode::serialize_into(&mut merkle_tree_file, &(root, merkle_tree)).unwrap();
    tracing::info!("File saved successfully.");
}
