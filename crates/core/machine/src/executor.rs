//! Execution utilities for tracing and generating execution records.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use slop_algebra::PrimeField32;
use sp1_core_executor::{events::MemoryRecord, ExecutionError, ExecutionRecord, SP1CoreOpts};
use sp1_core_executor::{Program, TracingVMEnum};
use sp1_hypercube::air::PROOF_NONCE_NUM_WORDS;
use sp1_jit::MinimalTrace;
use tracing::Level;

/// The output of the machine executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOutput {
    pub public_value_stream: Vec<u8>,
    pub cycles: u64,
}

/// Trace a single [`MinimalTrace`] (corresponding to a shard) and return the execution record.
///
/// This is the core tracing function that converts a minimal trace into a full execution record
/// with all the events needed for proving.
#[tracing::instrument(
    level = Level::DEBUG,
    name = "trace_chunk",
    skip_all,
)]
pub fn trace_chunk<F: PrimeField32>(
    program: Arc<Program>,
    opts: SP1CoreOpts,
    chunk: impl MinimalTrace,
    proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
    mut record: ExecutionRecord,
) -> Result<(bool, ExecutionRecord, [MemoryRecord; 32]), ExecutionError> {
    let mut vm = TracingVMEnum::new(&chunk, program, opts, proof_nonce, &mut record);
    let status = vm.execute()?;
    tracing::trace!("chunk ended at clk: {}", vm.clk());
    tracing::trace!("chunk ended at pc: {}", vm.pc());

    let pv = vm.public_values();

    if status.is_shard_boundry() && (pv.commit_syscall == 1 || pv.commit_deferred_syscall == 1) {
        tracing::trace!("commit syscall or commit deferred proofs across last two shards");

        loop {
            if vm.execute()?.is_done() {
                let pv = *vm.public_values();

                vm.record_mut().public_values.commit_syscall = 1;
                vm.record_mut().public_values.commit_deferred_syscall = 1;
                vm.record_mut().public_values.committed_value_digest = pv.committed_value_digest;
                vm.record_mut().public_values.deferred_proofs_digest = pv.deferred_proofs_digest;

                break;
            }
        }
    }

    vm.record_mut().finalize_public_values::<F>(true);

    let registers = *vm.registers();
    drop(vm);
    Ok((status.is_done(), record, registers))
}
