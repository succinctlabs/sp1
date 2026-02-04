use futures::{stream::FuturesUnordered, StreamExt};
use slop_futures::pipeline::{AsyncEngine, AsyncWorker, Pipeline, SubmitHandle};
use sp1_core_executor::{
    ExecutionError, ExecutionReport, GasEstimatingVM, MinimalExecutor, Program, SP1Context,
    SP1CoreOpts,
};
use sp1_core_machine::io::SP1Stdin;
use sp1_hypercube::air::PROOF_NONCE_NUM_WORDS;
use sp1_jit::TraceChunkRaw;
use sp1_primitives::io::SP1PublicValues;
use std::sync::Arc;
use tracing::Instrument;

use crate::worker::{
    FinalVmState, FinalVmStateLock, DEFAULT_GAS_EXECUTOR_BUFFER_SIZE,
    DEFAULT_NUM_GAS_EXECUTOR_WORKERS,
};

/// Configuration for the executor.
#[derive(Debug, Clone)]
pub struct SP1ExecutorConfig {
    /// The number of gas executors.
    pub num_gas_executors: usize,
    /// The buffer size for the gas executor.
    pub gas_executor_buffer_size: usize,
}

impl Default for SP1ExecutorConfig {
    fn default() -> Self {
        let num_gas_executors = std::env::var("SP1_WORKER_NUMBER_OF_GAS_EXECUTORS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_NUM_GAS_EXECUTOR_WORKERS);
        let gas_executor_buffer_size = std::env::var("SP1_WORKER_GAS_EXECUTOR_BUFFER_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_GAS_EXECUTOR_BUFFER_SIZE);
        Self { num_gas_executors, gas_executor_buffer_size }
    }
}

pub fn initialize_gas_engine(
    config: &SP1ExecutorConfig,
    program: Arc<Program>,
    nonce: [u32; PROOF_NONCE_NUM_WORDS],
    opts: SP1CoreOpts,
    calculate_gas: bool,
) -> GasExecutingEngine {
    let workers = (0..config.num_gas_executors)
        .map(|_| GasExecutingWorker::new(program.clone(), nonce, opts.clone(), calculate_gas))
        .collect();
    AsyncEngine::new(workers, config.gas_executor_buffer_size)
}

pub type GasExecutingEngine =
    AsyncEngine<GasExecutingTask, Result<ExecutionReport, ExecutionError>, GasExecutingWorker>;

/// A task for gas estimation on a trace chunk.
pub struct GasExecutingTask {
    pub chunk: TraceChunkRaw,
    /// Lock to store the final VM state when execution completes.
    pub final_vm_state: FinalVmStateLock,
}

#[derive(Debug, Clone)]
pub struct GasExecutingWorker {
    program: Arc<Program>,
    nonce: [u32; PROOF_NONCE_NUM_WORDS],
    opts: SP1CoreOpts,
    calculate_gas: bool,
}

impl GasExecutingWorker {
    pub fn new(
        program: Arc<Program>,
        nonce: [u32; PROOF_NONCE_NUM_WORDS],
        opts: SP1CoreOpts,
        calculate_gas: bool,
    ) -> Self {
        Self { program, nonce, opts, calculate_gas }
    }
}

impl AsyncWorker<GasExecutingTask, Result<ExecutionReport, ExecutionError>> for GasExecutingWorker {
    async fn call(&self, input: GasExecutingTask) -> Result<ExecutionReport, ExecutionError> {
        let GasExecutingTask { chunk, final_vm_state } = input;
        if !self.calculate_gas {
            return Ok(ExecutionReport::default());
        }
        let mut gas_estimating_vm =
            GasEstimatingVM::new(&chunk, self.program.clone(), self.nonce, self.opts.clone());
        let report = gas_estimating_vm.execute()?;

        // If the VM has completed execution, set the final state.
        if gas_estimating_vm.core.is_done() {
            let final_state = FinalVmState::new(&gas_estimating_vm.core);
            final_vm_state.set(final_state).map_err(|e| {
                ExecutionError::Other(format!("failed to set final vm state: {}", e))
            })?;
        }

        Ok(report)
    }
}

pub async fn execute_with_options(
    program: Arc<Program>,
    stdin: SP1Stdin,
    context: SP1Context<'static>,
    opts: SP1CoreOpts,
    executor_config: SP1ExecutorConfig,
) -> anyhow::Result<(SP1PublicValues, [u8; 32], ExecutionReport)> {
    let calculate_gas = context.calculate_gas;
    let nonce = context.proof_nonce;
    let max_cycles = context.max_cycles;
    let minimal_trace_chunk_threshold =
        if context.calculate_gas { Some(opts.minimal_trace_chunk_threshold) } else { None };
    let gas_engine =
        initialize_gas_engine(&executor_config, program.clone(), nonce, opts, calculate_gas);

    let mut minimal_executor =
        MinimalExecutor::new(program.clone(), false, minimal_trace_chunk_threshold);

    // Feed stdin buffers to the executor
    for buf in stdin.buffer {
        minimal_executor.with_input(&buf);
    }

    // Create a shared final VM state lock that will be set when execution completes.
    let final_vm_state = FinalVmStateLock::new();

    // Execute the program to completion, collecting all trace chunks
    let (handle_sender, mut handle_receiver) = tokio::sync::mpsc::unbounded_channel();

    // The return values of the two tasks in the join set.
    enum ExecutorOutput {
        Report(ExecutionReport),
        PublicValues {
            public_values: SP1PublicValues,
            #[cfg(feature = "profiling")]
            cycle_tracker: hashbrown::HashMap<String, u64>,
            #[cfg(feature = "profiling")]
            invocation_tracker: hashbrown::HashMap<String, u64>,
        },
    }

    let mut join_set = tokio::task::JoinSet::new();
    // Spawn a task that runs gas executors.
    join_set.spawn(async move {
        let mut report = ExecutionReport::default();
        let max_cycles = max_cycles.unwrap_or(u64::MAX);
        let mut gas_handles: FuturesUnordered<SubmitHandle<GasExecutingEngine>> =
            FuturesUnordered::new();
        loop {
            tokio::select! {
                Some(result) = handle_receiver.recv() => {
                    let gas_handles_len = gas_handles.len();
                    tracing::debug!(num_gas_handles = %gas_handles_len, "Received gas handle");
                    gas_handles.push(result);

                }

                Some(result) = gas_handles.next() => {
                    let chunk_report = result.map_err(|e| anyhow::anyhow!("gas task panicked: {}", e))??;
                    let gas_handles_len = gas_handles.len();
                    tracing::debug!(num_gas_handles = %gas_handles_len, "Gas task finished.");
                    report += chunk_report;

                    let total_instructions = report.total_instruction_count();
                    if total_instructions >= max_cycles {
                        tracing::debug!("Cycle limit reached, stopping execution");
                        return Err(anyhow::anyhow!("cycle limit reached"));
                    }
                }

                else => {
                    tracing::debug!("No more gas handles to receive");
                    break;
                }
            }
        }
        while let Some(result) = gas_handles.next().await {
            let chunk_report = result.map_err(|e| anyhow::anyhow!("gas task panicked: {}", e))??;
            report += chunk_report;
        }
        Ok::<_, anyhow::Error>(ExecutorOutput::Report(report))
    }.instrument(tracing::debug_span!("report_accumulator")));

    // Spawn a blocking task to run the minimal executor.
    let final_vm_state_clone = final_vm_state.clone();
    join_set.spawn_blocking(move || {
        while let Some(chunk) = minimal_executor.execute_chunk() {
            let handle = gas_engine
                .blocking_submit(GasExecutingTask {
                    chunk,
                    final_vm_state: final_vm_state_clone.clone(),
                })
                .map_err(|e| anyhow::anyhow!("Gas engine submission failed: {}", e))?;
            handle_sender.send(handle)?;
        }
        tracing::debug!("Minimal executor finished in {} cycles", minimal_executor.global_clk());

        // Extract cycle tracker data before consuming the executor
        #[cfg(feature = "profiling")]
        let cycle_tracker = minimal_executor.take_cycle_tracker_totals();
        #[cfg(feature = "profiling")]
        let invocation_tracker = minimal_executor.take_invocation_tracker();

        let public_value_stream = minimal_executor.into_public_values_stream();
        let public_values = SP1PublicValues::from(&public_value_stream);

        tracing::info!("public_value_stream: {:?}", public_value_stream);
        Ok::<_, anyhow::Error>(ExecutorOutput::PublicValues {
            public_values,
            #[cfg(feature = "profiling")]
            cycle_tracker,
            #[cfg(feature = "profiling")]
            invocation_tracker,
        })
    });

    // Wait for all gas calculations to complete.
    let mut final_report = ExecutionReport::default();
    let mut public_values = SP1PublicValues::default();
    #[cfg(feature = "profiling")]
    let mut cycle_tracker_data: Option<(
        hashbrown::HashMap<String, u64>,
        hashbrown::HashMap<String, u64>,
    )> = None;

    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok(output)) => match output {
                ExecutorOutput::PublicValues {
                    public_values: pv,
                    #[cfg(feature = "profiling")]
                    cycle_tracker,
                    #[cfg(feature = "profiling")]
                    invocation_tracker,
                } => {
                    public_values = pv;
                    #[cfg(feature = "profiling")]
                    {
                        cycle_tracker_data = Some((cycle_tracker, invocation_tracker));
                    }
                }
                ExecutorOutput::Report(report) => final_report = report,
            },
            Ok(Err(e)) => {
                // Task returned an error
                return Err(e);
            }
            Err(join_error) => {
                // Task panicked or was cancelled
                return Err(join_error.into());
            }
        }
    }

    // Merge cycle tracker data from MinimalExecutor into the final report
    // This must happen after all tasks complete to avoid race conditions
    #[cfg(feature = "profiling")]
    if let Some((cycle_tracker, invocation_tracker)) = cycle_tracker_data {
        final_report.cycle_tracker = cycle_tracker;
        final_report.invocation_tracker = invocation_tracker;
    }

    // Extract the public value digest from the final VM state.
    let public_value_digest: [u8; 32] = final_vm_state
        .get()
        .map(|state| {
            let mut committed_value_digest = [0u8; 32];
            state.public_value_digest.iter().enumerate().for_each(|(i, word)| {
                let bytes = word.to_le_bytes();
                committed_value_digest[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
            });
            committed_value_digest
        })
        .ok_or(anyhow::anyhow!("Failed to extract public value digest"))?;

    Ok((public_values, public_value_digest, final_report))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sp1_core_executor::{Program, SP1Context, SP1CoreOpts};
    use sp1_core_machine::io::SP1Stdin;

    use super::{execute_with_options, SP1ExecutorConfig};

    #[tokio::test]
    async fn test_execute_with_optional_gas() {
        let elf = test_artifacts::FIBONACCI_ELF;
        let program = Arc::new(Program::from(&elf).unwrap());
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let opts = SP1CoreOpts::default();
        let executor_config = SP1ExecutorConfig::default();

        let context = SP1Context::default();
        let (pv, digest, report) =
            execute_with_options(program, stdin, context, opts, executor_config).await.unwrap();

        assert!(pv.hash() == digest.to_vec() || pv.blake3_hash() == digest.to_vec());
        assert_eq!(report.exit_code, 0);
    }
}
