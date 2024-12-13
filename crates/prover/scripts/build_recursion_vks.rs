use std::path::PathBuf;

use clap::Parser;
use sp1_core_machine::utils::setup_logger;
use sp1_prover::{
    components::CpuProverComponents, shapes::build_vk_map_to_file, REDUCE_BATCH_SIZE,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: PathBuf,
    //     #[clap(short, long, default_value_t = false)]
    //     dummy: bool,
    //     #[clap(short, long, default_value_t = REDUCE_BATCH_SIZE)]
    //     reduce_batch_size: usize,
    //     #[clap(short, long, default_value_t = 1)]
    //     num_compiler_workers: usize,
    //     #[clap(short, long, default_value_t = 1)]
    //     num_setup_workers: usize,
    //     #[clap(short, long)]
    //     start: Option<usize>,
    //     #[clap(short, long)]
    //     end: Option<usize>,
}

fn main() {
    setup_logger();
    let args = Args::parse();

    let reduce_batch_size = REDUCE_BATCH_SIZE;
    let build_dir = args.build_dir;
    let num_compiler_workers = 1;
    let num_setup_workers = 1;

    build_vk_map_to_file::<CpuProverComponents>(
        build_dir,
        reduce_batch_size,
        false,
        num_compiler_workers,
        num_setup_workers,
        None,
        None,
    )
    .unwrap();
}
