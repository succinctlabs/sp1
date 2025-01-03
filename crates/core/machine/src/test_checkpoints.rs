//! This script runs some programs in checkpoint mode and prints the hashes of the
//! checkpoints. It's useful for making sure that the checkpoints are created correctly.

use crate::programs::*;
use crate::shape::CoreShapeConfig;
use itertools::Itertools;
use k256::sha2::{Digest, Sha256};
use p3_baby_bear::BabyBear;
use sp1_core_executor::{Executor, MaximalShapes, Program};
use sp1_stark::SP1CoreOpts;

fn execute_and_print_hashes(
    program: Program,
    maximal_shapes: MaximalShapes,
    opts: SP1CoreOpts,
    emit_global_memory_events: bool,
) {
    // Set up the runtime.
    let mut runtime = Executor::new(program.clone(), opts);
    runtime.maximal_shapes = Some(maximal_shapes);

    let mut state_hashes = Vec::new();
    loop {
        let (state, _, done) =
            runtime.execute_state(emit_global_memory_events).expect("execution error");

        // Hash the the important parts of the checkpoint: the memory and uninitialized memory.
        // This format is necessary because it's standard across different memory implementations.
        state_hashes
            .push(bincode::serialize(&state.memory.into_iter().collect::<Vec<_>>()).unwrap());
        state_hashes.push(
            bincode::serialize(&state.uninitialized_memory.into_iter().collect::<Vec<_>>())
                .unwrap(),
        );
        if done {
            break;
        }
    }

    // Hash together all the checkpoints for each shard.
    let mut state_hasher = Sha256::new();
    state_hashes.iter().for_each(|state_hash| {
        state_hasher.update(state_hash);
    });
    let state_hash = state_hasher.finalize();

    println!("Emit global memory events: {}", emit_global_memory_events);
    println!("Cycles: {}", runtime.report.total_instruction_count());
    println!("State hash: {:?}", state_hash);
    // If we emit global memory events, additionally hash the global memory initialize and finalize events.
    if emit_global_memory_events {
        let mut event_hasher = Sha256::new();
        runtime
            .records
            .last()
            .unwrap()
            .global_memory_initialize_events
            .iter()
            .sorted_by_key(|event| event.timestamp)
            .for_each(|event| {
                event_hasher.update(bincode::serialize(&event).unwrap().as_slice());
            });
        runtime
            .records
            .last()
            .unwrap()
            .global_memory_finalize_events
            .iter()
            .sorted_by_key(|event| event.timestamp)
            .for_each(|event| {
                event_hasher.update(bincode::serialize(&event).unwrap().as_slice());
            });
        let event_hash = event_hasher.finalize();
        println!("Event hash: {:?}", event_hash);
    }
}

#[test]
fn test_checkpoints() {
    let programs = [fibonacci_program(), secp256r1_add_program()];
    for mut program in programs.into_iter() {
        // Set up the shape config.
        let shape_config = CoreShapeConfig::<BabyBear>::default();
        shape_config.fix_preprocessed_shape(&mut program).unwrap();

        // Set a low shard size and batch size to produce many checkpoints and check their consistency.
        let opts =
            SP1CoreOpts { shard_size: 1 << 10, shard_batch_size: 1, ..SP1CoreOpts::default() };
        let maximal_shapes: MaximalShapes = shape_config
            .maximal_core_shapes(opts.shard_size.ilog2() as usize)
            .into_iter()
            .collect::<_>();

        execute_and_print_hashes(program.clone(), maximal_shapes.clone(), opts, true);
        execute_and_print_hashes(program.clone(), maximal_shapes, opts, false);
        println!("==========================")
    }
}
