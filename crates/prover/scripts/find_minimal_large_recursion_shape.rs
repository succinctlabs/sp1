use std::{collections::HashMap, path::PathBuf};

use clap::Parser;
use sp1_core_machine::utils::setup_logger;
use sp1_prover::{
    components::DefaultProverComponents,
    shapes::{build_vk_map_to_file, check_shapes},
    SP1Prover, REDUCE_BATCH_SIZE,
};
use sp1_recursion_core::shape::RecursionShapeConfig;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
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
    let dummy = args.dummy;
    let num_compiler_workers = args.num_compiler_workers;

    let mut prover = SP1Prover::<DefaultProverComponents>::new();
    prover.vk_verification = !dummy;

    let recursion_shape_config =
        prover.recursion_shape_config.as_ref().expect("recursion shape config not found");

    let recursion_shape_config = recursion_shape_config.union_config_with_extra_room();

    let candidate = recursion_shape_config.first().unwrap().clone();

    prover.recursion_shape_config = Some(RecursionShapeConfig::from_hash_map(&candidate));

    assert!(check_shapes(reduce_batch_size, true, num_compiler_workers, &prover));

    let mut answer = candidate.clone();

    for (key, value) in candidate.iter() {
        if key != "PublicValues" {
            let mut done = false;
            let mut new_val = *value;
            while !done {
                new_val -= 1;
                answer.insert(key.clone(), new_val);
                prover.recursion_shape_config = Some(RecursionShapeConfig::from_hash_map(&answer));
                done = !check_shapes(reduce_batch_size, true, num_compiler_workers, &prover);
            }
            answer.insert(key.clone(), new_val + 1);
        }
    }
    println!("Final shape: {:?}", answer);
}
