use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    path::PathBuf,
};

use clap::Parser;
use p3_baby_bear::BabyBear;
use sp1_core_machine::utils::setup_logger;
use sp1_prover::{
    components::DefaultProverComponents,
    shapes::{build_vk_map_to_file, VkData},
    REDUCE_BATCH_SIZE,
};

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
    start: Option<usize>,
    #[clap(short, long)]
    end: Option<usize>,
    #[clap(short, long, default_value_t = false)]
    from_map_file: bool,
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
    let from_map_file = args.from_map_file;

    if from_map_file {
        tracing::info!("Creating vk data from vk set");
        let mut file = File::open(build_dir.join("vk_map_75740.bin")).unwrap();
        let (vk_map, _): (BTreeMap<[BabyBear; 8], usize>, Vec<usize>) =
            bincode::deserialize_from(&mut file).unwrap();
        let vk_set: BTreeSet<[BabyBear; 8]> = vk_map.keys().cloned().collect();
        let height = vk_set.len().next_power_of_two().ilog2() as usize;
        let vk_data = VkData::new(vk_set, height);

        vk_data.save(build_dir).expect("failed to save vk data");
    } else {
        build_vk_map_to_file::<DefaultProverComponents>(
            build_dir,
            reduce_batch_size,
            dummy,
            num_compiler_workers,
            num_setup_workers,
            range_start,
            range_end,
        );
    }
}
