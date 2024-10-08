use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use clap::Parser;
use p3_baby_bear::BabyBear;
use sp1_core_machine::utils::setup_logger;
use sp1_prover::{
    components::DefaultProverComponents, shapes::build_vk_map_to_file, REDUCE_BATCH_SIZE,
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

    let old_map_file = std::fs::File::open(build_dir.join("allowed_vk_map.bin")).unwrap();
    let old_map: BTreeMap<[BabyBear; 8], usize> = bincode::deserialize_from(old_map_file).unwrap();

    println!("old_set: {:?}", old_map.len());

    let shrink_set_file = std::fs::File::open(build_dir.join("shrink/vk_map.bin")).unwrap();
    let shrink_set: BTreeMap<[BabyBear; 8], usize> =
        bincode::deserialize_from(shrink_set_file).unwrap();

    println!("shrink_set: {:?}", shrink_set.len());

    let new_set = old_map.into_keys().chain(shrink_set.into_keys()).collect::<BTreeSet<_>>();

    println!("new_set: {:?}", new_set.len());

    let new_map =
        new_set.into_iter().enumerate().map(|(i, vk)| (vk, i)).collect::<BTreeMap<_, _>>();

    let mut file = std::fs::File::create(build_dir.join("allowed_vk_map_new.bin")).unwrap();
    bincode::serialize_into(&mut file, &new_map).unwrap();
    // build_vk_map_to_file::<DefaultProverComponents>(
    //     build_dir,
    //     reduce_batch_size,
    //     dummy,
    //     num_compiler_workers,
    //     num_setup_workers,
    //     range_start,
    //     range_end,
    // )
    // .unwrap();
}
