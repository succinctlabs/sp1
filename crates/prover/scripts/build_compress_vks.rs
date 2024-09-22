use std::path::PathBuf;

use clap::Parser;
use sp1_core_machine::utils::setup_logger;
use sp1_prover::{components::DefaultProverComponents, shapes::build_vk_map, REDUCE_BATCH_SIZE};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: PathBuf,
    #[clap(short, long, default_value_t = false)]
    dummy: bool,
    #[clap(short, long, default_value_t = REDUCE_BATCH_SIZE)]
    reduce_batch_size: usize,
    #[clap(short, long, default_value_t = 1)]
    num_compiler_workers: usize,
    #[clap(short, long, default_value_t = 1)]
    num_setup_workers: usize,
    #[clap(short, long)]
    shape_capacity: Option<usize>,
}

fn main() {
    setup_logger();
    let args = Args::parse();

    let reduce_batch_size = args.reduce_batch_size;
    let build_dir = args.build_dir;
    let dummy = args.dummy;
    let num_compiler_workers = args.num_compiler_workers;
    let num_setup_workers = args.num_setup_workers;
    let shape_capacity = args.shape_capacity;

    build_vk_map::<DefaultProverComponents>(
        build_dir,
        reduce_batch_size,
        dummy,
        num_compiler_workers,
        num_setup_workers,
        shape_capacity,
    );
}
