use std::path::PathBuf;

use clap::Parser;
use sp1_core_machine::utils::setup_logger;
use sp1_prover::{
    components::CpuProverComponents, shapes::build_vk_map_to_file, REDUCE_BATCH_SIZE,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    build_dir: PathBuf,
    #[arg(short, long, default_value_t = false)]
    dummy: bool,
    #[arg(short, long, default_value_t = REDUCE_BATCH_SIZE)]
    reduce_batch_size: usize,
    #[arg(short, long, default_value_t = 1)]
    num_compiler_workers: usize,
    #[arg(short, long, default_value_t = 1)]
    num_setup_workers: usize,
    #[arg(short, long)]
    start: Option<usize>,
    #[arg(short, long)]
    end: Option<usize>,
}

fn main() {
    setup_logger();
    let args = Args::parse();

    let reduce_batch_size = args.reduce_batch_size;
    let build_dir = args.build_dir;
    let dummy = args.dummy;
    let num_compiler_workers = args.num_compiler_workers;
    let num_setup_workers = args.num_setup_workers;
    let range_start = args.start;
    let range_end = args.end;

    build_vk_map_to_file::<CpuProverComponents>(
        build_dir,
        reduce_batch_size,
        dummy,
        num_compiler_workers,
        num_setup_workers,
        range_start,
        range_end,
    )
    .unwrap();
}
