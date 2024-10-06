use std::path::PathBuf;

use clap::Parser;
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

    // let mut allowd_vk_file = std::fs::File::open(build_dir.join("allowed_vk_map.bin")).unwrap();
    // let allowed_vk_map: BTreeMap<[BabyBear; 8], usize> =
    //     bincode::deserialize_from(&mut allowd_vk_file).unwrap();

    // let deferered_data_file = std::fs::File::open(build_dir.join("deferred/vk_data.bin")).unwrap();
    // let data: VkData = bincode::deserialize_from(deferered_data_file).unwrap();

    // let new_set =
    //     allowed_vk_map.keys().copied().chain(data.vk_map.keys().copied()).collect::<BTreeSet<_>>();

    // let new_vk = VkData::new(new_set, 21);

    // // overwrite the allowd_vk_map with the new one
    // let mut allowd_vk_file =
    //     std::fs::File::create(build_dir.join("allowed_vk_map_new.bin")).unwrap();
    // bincode::serialize_into(&mut allowd_vk_file, &new_vk.vk_map).unwrap();

    // // bincode::serialize_into(&mut allowd_vk_file, &new_vk.vk_map).unwrap();

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
