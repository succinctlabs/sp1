use futures::{stream::FuturesUnordered, StreamExt};
use slop_futures::pipeline::{AsyncEngine, AsyncWorker, Pipeline, SubmitHandle};
use sp1_core_executor::{
    ExecutionError, ExecutionReport, GasEstimatingVMEnum, Program, SP1Context, SP1CoreOpts,
    SP1RecursionProof,
};
use sp1_core_executor_runner::MinimalExecutorRunner;
use sp1_core_machine::io::SP1Stdin;
use sp1_core_machine::riscv::RiscvAir;
use sp1_hypercube::air::PROOF_NONCE_NUM_WORDS;
use sp1_hypercube::{Machine, MachineVerifyingKey, SP1PcsProofInner, SP1VerifyingKey};
use sp1_jit::TraceChunkRaw;
use sp1_primitives::consts::PV_DIGEST_NUM_WORDS;
use sp1_primitives::io::SP1PublicValues;
use sp1_primitives::{SP1Field, SP1GlobalContext};
use std::sync::Arc;
use tracing::Instrument;

use crate::verify::SP1Verifier;
#[cfg(feature = "mprotect")]
use crate::{recursion::RecursionVks, worker::DEFAULT_MAX_COMPOSE_ARITY};

type DeferredProofInput =
    (SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>, MachineVerifyingKey<SP1GlobalContext>);
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
            GasEstimatingVMEnum::new(&chunk, self.program.clone(), self.nonce, self.opts.clone());
        let report = gas_estimating_vm.execute()?;

        // If the VM has completed execution, set the final state.
        if gas_estimating_vm.is_done() {
            let final_state = FinalVmState::from_gas_estimating_vm_enum(&gas_estimating_vm);
            final_vm_state.set(final_state).map_err(|e| {
                ExecutionError::Other(format!("failed to set final vm state: {}", e))
            })?;
        }

        Ok(report)
    }
}

fn public_value_digest_from_words(words: &[u32; PV_DIGEST_NUM_WORDS]) -> [u8; 32] {
    let mut digest = [0u8; 32];

    for (word, out) in words.iter().zip(digest.chunks_exact_mut(4)) {
        out.copy_from_slice(&word.to_le_bytes());
    }

    digest
}

fn verify_deferred_proofs(
    machine: Machine<SP1Field, RiscvAir<SP1Field>>,
    proofs: &[DeferredProofInput],
) -> anyhow::Result<()> {
    if proofs.is_empty() {
        return Ok(());
    }
    #[cfg(feature = "mprotect")]
    let verifier_vks = RecursionVks::new(None, DEFAULT_MAX_COMPOSE_ARITY, false).to_verifier_vks();
    #[cfg(not(feature = "mprotect"))]
    let verifier_vks = crate::verify::VerifierRecursionVks::default();
    let verifier = SP1Verifier::new_with_machine(verifier_vks, machine.clone());
    for (index, (proof, vk)) in proofs.iter().enumerate() {
        let sp1_vk = SP1VerifyingKey { vk: vk.clone() };
        verifier
            .verify_compressed(proof, &sp1_vk)
            .map_err(|e| anyhow::anyhow!("deferred proof {index} failed verification: {e}"))?;
    }
    Ok(())
}

pub async fn execute_with_options(
    program: Arc<Program>,
    stdin: SP1Stdin,
    context: SP1Context<'static>,
    opts: SP1CoreOpts,
    executor_config: SP1ExecutorConfig,
) -> anyhow::Result<(SP1PublicValues, [u8; 32], ExecutionReport)> {
    execute_with_options_and_machine(
        program,
        stdin,
        context,
        opts,
        executor_config,
        RiscvAir::machine(),
    )
    .await
}

/// Same as [`execute_with_options`] but with a custom machine.
pub async fn execute_with_options_and_machine(
    program: Arc<Program>,
    stdin: SP1Stdin,
    context: SP1Context<'static>,
    opts: SP1CoreOpts,
    executor_config: SP1ExecutorConfig,
    machine: Machine<SP1Field, RiscvAir<SP1Field>>,
) -> anyhow::Result<(SP1PublicValues, [u8; 32], ExecutionReport)> {
    // The return values of the spawned tasks.
    enum ExecutorOutput {
        VerifyDone,
        Report(ExecutionReport),
        PublicValues {
            public_values: SP1PublicValues,
            public_value_digest_words: [u32; PV_DIGEST_NUM_WORDS],
            #[cfg(feature = "profiling")]
            cycle_tracker: hashbrown::HashMap<String, u64>,
            #[cfg(feature = "profiling")]
            invocation_tracker: hashbrown::HashMap<String, u64>,
        },
    }

    let mut join_set = tokio::task::JoinSet::new();
    let SP1Stdin { buffer, proofs, .. } = stdin;

    let calculate_gas = context.calculate_gas;
    let nonce = context.proof_nonce;
    let max_cycles = context.max_cycles;
    let minimal_trace_chunk_threshold =
        if context.calculate_gas { Some(opts.minimal_trace_chunk_threshold) } else { None };
    let memory_limit = opts.memory_limit;
    let trace_chunk_slots = opts.trace_chunk_slots;
    let gas_engine =
        initialize_gas_engine(&executor_config, program.clone(), nonce, opts, calculate_gas);

    if context.deferred_proof_verification {
        join_set.spawn_blocking(move || {
            verify_deferred_proofs(machine, &proofs)?;
            Ok::<_, anyhow::Error>(ExecutorOutput::VerifyDone)
        });
    }

    let mut minimal_executor = MinimalExecutorRunner::new(
        program.clone(),
        false,
        minimal_trace_chunk_threshold,
        memory_limit,
        trace_chunk_slots,
    );

    // Feed stdin buffers to the executor
    for buf in buffer {
        minimal_executor.with_input(&buf);
    }

    // Create a shared final VM state lock that will be set when execution completes.
    let final_vm_state = FinalVmStateLock::new();

    // Execute the program to completion, collecting all trace chunks
    let (handle_sender, mut handle_receiver) = tokio::sync::mpsc::unbounded_channel();

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
                        return Err(anyhow::Error::new(ExecutionError::ExceededCycleLimit(
                            max_cycles,
                        )));
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
        while let Some(chunk) = minimal_executor.try_execute_chunk()? {
            let handle = gas_engine
                .blocking_submit(GasExecutingTask {
                    chunk,
                    final_vm_state: final_vm_state_clone.clone(),
                })
                .map_err(|e| anyhow::anyhow!("Gas engine submission failed: {}", e))?;
            handle_sender.send(handle)?;
        }
        tracing::debug!("minimal executor finished in {} cycles", minimal_executor.global_clk());

        // Extract cycle tracker data before consuming the executor
        #[cfg(feature = "profiling")]
        let cycle_tracker = minimal_executor.take_cycle_tracker_totals();
        #[cfg(feature = "profiling")]
        let invocation_tracker = minimal_executor.take_invocation_tracker();

        let public_value_digest_words = *minimal_executor.public_value_digest();
        let public_value_stream = minimal_executor.into_public_values_stream();
        let public_values = SP1PublicValues::from(&public_value_stream);

        tracing::info!("public_value_stream: {:?}", public_value_stream);
        Ok::<_, anyhow::Error>(ExecutorOutput::PublicValues {
            public_values,
            public_value_digest_words,
            #[cfg(feature = "profiling")]
            cycle_tracker,
            #[cfg(feature = "profiling")]
            invocation_tracker,
        })
    });

    // Wait for all gas calculations to complete.
    let mut final_report = ExecutionReport::default();
    let mut public_values = SP1PublicValues::default();
    let mut public_value_digest_words = None;
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
                    public_value_digest_words: digest_words,
                    #[cfg(feature = "profiling")]
                    cycle_tracker,
                    #[cfg(feature = "profiling")]
                    invocation_tracker,
                } => {
                    public_values = pv;
                    public_value_digest_words = Some(digest_words);
                    #[cfg(feature = "profiling")]
                    {
                        cycle_tracker_data = Some((cycle_tracker, invocation_tracker));
                    }
                }
                ExecutorOutput::Report(report) => final_report = report,
                ExecutorOutput::VerifyDone => {}
            },
            Ok(Err(e)) => {
                // Task returned an error.
                return Err(e);
            }
            Err(join_error) => {
                // Task panicked or was cancelled.
                return Err(join_error.into());
            }
        }
    }

    // Merge cycle tracker data from MinimalExecutorRunner into the final report
    // This must happen after all tasks complete to avoid race conditions
    #[cfg(feature = "profiling")]
    if let Some((cycle_tracker, invocation_tracker)) = cycle_tracker_data {
        final_report.cycle_tracker = cycle_tracker;
        final_report.invocation_tracker = invocation_tracker;
    }

    // Gas replay owns `FinalVmState`. When gas is disabled, use the digest words
    // emitted by the guest's own COMMIT syscalls during minimal execution.
    let public_value_digest = match final_vm_state.get() {
        Some(state) => public_value_digest_from_words(&state.public_value_digest),
        None if !calculate_gas => {
            let words = public_value_digest_words
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Failed to extract public value digest"))?;
            public_value_digest_from_words(words)
        }
        None => return Err(anyhow::anyhow!("Failed to extract public value digest")),
    };

    Ok((public_values, public_value_digest, final_report))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sp1_core_executor::{ExecutionReport, Program, SP1Context, SP1CoreOpts};
    use sp1_core_machine::io::SP1Stdin;
    use sp1_primitives::io::SP1PublicValues;

    use super::{execute_with_options, SP1ExecutorConfig};

    fn fibonacci_stdin() -> SP1Stdin {
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        stdin
    }

    async fn execute_program(
        program: Arc<Program>,
        calculate_gas: bool,
    ) -> (SP1PublicValues, [u8; 32], ExecutionReport) {
        let context = SP1Context { calculate_gas, ..SP1Context::default() };
        execute_with_options(
            program,
            fibonacci_stdin(),
            context,
            SP1CoreOpts::default(),
            SP1ExecutorConfig::default(),
        )
        .await
        .unwrap()
    }

    fn assert_public_values_digest(public_values: &SP1PublicValues, digest: [u8; 32]) {
        let digest = digest.to_vec();
        assert!(public_values.hash() == digest || public_values.blake3_hash() == digest);
    }

    #[tokio::test]
    async fn test_execute_with_optional_gas() {
        let sha_program = Arc::new(Program::from(&test_artifacts::FIBONACCI_ELF).unwrap());
        let (sha_pv, sha_digest, sha_report) = execute_program(sha_program.clone(), true).await;
        let (sha_no_gas_pv, sha_no_gas_digest, sha_no_gas_report) =
            execute_program(sha_program, false).await;

        assert!(!sha_pv.as_slice().is_empty());
        assert_eq!(sha_pv.as_slice(), sha_no_gas_pv.as_slice());
        assert_eq!(sha_digest, sha_no_gas_digest);
        assert_eq!(sha_no_gas_digest.to_vec(), sha_no_gas_pv.hash());
        assert_public_values_digest(&sha_no_gas_pv, sha_no_gas_digest);
        assert_eq!(sha_report.exit_code, 0);
        assert_eq!(sha_no_gas_report.exit_code, 0);
        assert!(sha_no_gas_report.gas().is_none());

        let blake3_program =
            Arc::new(Program::from(&test_artifacts::FIBONACCI_BLAKE3_ELF).unwrap());
        let (blake3_pv, blake3_digest, blake3_report) =
            execute_program(blake3_program.clone(), true).await;
        let (blake3_no_gas_pv, blake3_no_gas_digest, blake3_no_gas_report) =
            execute_program(blake3_program, false).await;

        assert!(!blake3_pv.as_slice().is_empty());
        assert_eq!(blake3_pv.as_slice(), blake3_no_gas_pv.as_slice());
        assert_eq!(blake3_digest, blake3_no_gas_digest);
        assert_eq!(blake3_no_gas_digest.to_vec(), blake3_no_gas_pv.blake3_hash());
        assert_public_values_digest(&blake3_no_gas_pv, blake3_no_gas_digest);
        assert_eq!(blake3_report.exit_code, 0);
        assert_eq!(blake3_no_gas_report.exit_code, 0);
        assert!(blake3_no_gas_report.gas().is_none());
    }
}
