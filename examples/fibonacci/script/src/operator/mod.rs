use crate::common;
use crate::ProveArgs;
use anyhow::Result;
use sp1_core::{air::PublicValues, runtime::Runtime, utils::SP1CoreProverError};
use std::fs::File;

pub type PublicValueStreamType = Vec<u8>;
pub type PublicValuesType = PublicValues<u32, u32>;
pub type CheckpointType = File;

pub fn generate_checkpoints(
    runtime: &mut Runtime,
) -> Result<(PublicValueStreamType, PublicValuesType, Vec<CheckpointType>), SP1CoreProverError> {
    // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
    let create_checkpoints_span = tracing::debug_span!("create checkpoints").entered();
    let mut checkpoints = Vec::new();
    let (public_values_stream, public_values) = loop {
        // Execute the runtime until we reach a checkpoint.
        let (checkpoint, done) = runtime
            .execute_state()
            .map_err(SP1CoreProverError::ExecutionError)?;

        // Save the checkpoint to a temp file.
        let mut checkpoint_file = tempfile::tempfile().map_err(SP1CoreProverError::IoError)?;
        checkpoint
            .save(&mut checkpoint_file)
            .map_err(SP1CoreProverError::IoError)?;
        checkpoints.push(checkpoint_file);

        // If we've reached the final checkpoint, break out of the loop.
        if done {
            break (
                runtime.state.public_values_stream.clone(),
                runtime
                    .records
                    .last()
                    .expect("at least one record")
                    .public_values,
            );
        }
    };
    create_checkpoints_span.exit();

    Ok((public_values_stream, public_values, checkpoints))
}

pub fn prove_begin(
    args: ProveArgs,
) -> Result<(
    PublicValueStreamType,
    PublicValuesType,
    Vec<CheckpointType>,
    u64,
)> {
    let (client, stdin, pk, _) = common::init_client(args.clone());
    let (program, core_opts, context) = common::bootstrap(&client, &pk).unwrap();
    tracing::info!("Program size = {}", program.instructions.len());

    // Execute the program.
    let mut runtime = common::build_runtime(program, &stdin, core_opts, context);

    let (public_values_stream, public_values, checkpoints) =
        generate_checkpoints(&mut runtime).unwrap();

    Ok((
        public_values_stream,
        public_values,
        checkpoints,
        runtime.state.global_clk,
    ))
}
