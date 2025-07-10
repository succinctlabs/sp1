#![allow(clippy::print_stdout)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use clap::Parser;
use p3_baby_bear::BabyBear;
use sp1_core_machine::utils::setup_logger;
use sp1_prover::{
    components::CpuProverComponents,
    shapes::{check_shapes, SP1ProofShape},
    SP1Prover, ShrinkAir, REDUCE_BATCH_SIZE,
};
use sp1_recursion_core::shape::RecursionShapeConfig;
use sp1_stark::{shape::OrderedShape, MachineProver};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = false)]
    dummy: bool,
    #[arg(short, long, default_value_t = REDUCE_BATCH_SIZE)]
    recursion_batch_size: usize,
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
    // Setup the logger.
    setup_logger();

    // Parse the arguments.
    let args = Args::parse();

    // Initialize the prover.
    let mut prover = SP1Prover::<CpuProverComponents>::new();

    // Set whether to verify verification keys.
    prover.vk_verification = !args.dummy;
    prover.join_programs_map.clear();

    // Get the default compress shape configuration.
    let compress_shape_config =
        prover.compress_shape_config.as_ref().expect("recursion shape config not found");

    // Create the maximal shape from all of the shapes in recursion_shape_config, then add 2 to
    // all the log-heights of that shape. This is the starting candidate for the "minimal large
    // shape".
    let candidate = compress_shape_config.union_config_with_extra_room().first().unwrap().clone();

    prover.compress_shape_config = Some(RecursionShapeConfig::from_hash_map(&candidate));

    // Check that this candidate is big enough for all core shapes, including those with
    // precompiles.
    assert!(
        check_shapes(args.recursion_batch_size, false, args.num_compiler_workers, &mut prover,)
    );

    let mut answer = candidate.clone();

    // Chip-by-chip in the candidate, reduce the log-height corresponding to that chip until the
    // shape is no longer big enough to support all the core shapes. Then, record the log height for
    // that chip into answer.
    for (key, value) in candidate.iter() {
        if key != "PublicValues" {
            let mut done = false;
            let mut new_val = *value;
            while !done {
                new_val -= 1;
                answer.insert(key.clone(), new_val);
                prover.compress_shape_config = Some(RecursionShapeConfig::from_hash_map(&answer));
                done = !check_shapes(
                    args.recursion_batch_size,
                    false,
                    args.num_compiler_workers,
                    &mut prover,
                );
            }
            answer.insert(key.clone(), new_val + 1);
        }
    }

    let mut no_precompile_answer = answer.clone();

    // Repeat the process but only for core shapes that don't have a precompile in them.
    for (key, value) in answer.iter() {
        if key != "PublicValues" {
            let mut done = false;
            let mut new_val = *value;
            while !done {
                new_val -= 1;
                no_precompile_answer.insert(key.clone(), new_val);
                prover.compress_shape_config =
                    Some(RecursionShapeConfig::from_hash_map(&no_precompile_answer));
                done = !check_shapes(
                    args.recursion_batch_size,
                    true,
                    args.num_compiler_workers,
                    &mut prover,
                );
            }
            no_precompile_answer.insert(key.clone(), new_val + 1);
        }
    }

    // Repeat this process to tune the shrink shape.
    let mut shrink_shape = ShrinkAir::<BabyBear>::shrink_shape().clone_into_hash_map();

    // First, check that the current shrink shape is compatible with the compress shape choice
    // arising from the tuning process above.

    // TODO: set the join program map to empty.
    assert!({
        prover.compress_shape_config = Some(RecursionShapeConfig::from_hash_map(&answer));
        catch_unwind(AssertUnwindSafe(|| {
            prover.shrink_prover.setup(&prover.program_from_shape(
                sp1_prover::shapes::SP1CompressProgramShape::from_proof_shape(
                    SP1ProofShape::Shrink(OrderedShape {
                        inner: answer.clone().into_iter().collect::<Vec<_>>(),
                    }),
                    5,
                ),
                Some(shrink_shape.clone().into()),
            ))
        }))
        .is_ok()
    });

    // Next, tune the shrink shape in the same manner as for the compress shapes.
    for (key, value) in shrink_shape.clone().iter() {
        if key != "PublicValues" {
            let mut done = false;
            let mut new_val = *value + 1;
            while !done {
                new_val -= 1;
                shrink_shape.insert(key.clone(), new_val);
                prover.compress_shape_config = Some(RecursionShapeConfig::from_hash_map(&answer));
                done = catch_unwind(AssertUnwindSafe(|| {
                    prover.shrink_prover.setup(&prover.program_from_shape(
                        sp1_prover::shapes::SP1CompressProgramShape::from_proof_shape(
                            SP1ProofShape::Shrink(OrderedShape {
                                inner: answer.clone().into_iter().collect::<Vec<_>>(),
                            }),
                            5,
                        ),
                        Some(shrink_shape.clone().into()),
                    ))
                }))
                .is_err();
            }
            shrink_shape.insert(key.clone(), new_val + 1);
        }
    }

    println!("Final compress shape: {answer:?}");
    println!("Final compress shape with no precompiles: {no_precompile_answer:?}");
    println!("Final shrink shape: {shrink_shape:?}");
}
