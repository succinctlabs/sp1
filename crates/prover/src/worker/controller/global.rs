use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use itertools::Itertools;
use sp1_core_executor::{
    chunked_memory_init_events, events::MemoryInitializeFinalizeEvent, Program, SP1CoreOpts,
    SplitOpts, UnsafeMemory,
};
use sp1_core_executor_runner::MinimalExecutorRunner;
use sp1_hypercube::air::ShardRange;
use sp1_prover_types::{Artifact, ArtifactClient};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tracing::Instrument;

use crate::worker::{
    controller::create_core_proving_task, FinalVmState, GlobalMemoryShard, MinimalExecutorCache,
    ProofData, SpawnProveOutput, TaskContext, TaskError, TraceData, WorkerClient,
};

pub struct SpliceAddresses {
    start_clk: u64,
    end_clk: u64,
    addresses: Vec<u64>,
}

#[derive(Clone)]
pub struct TouchedAddresses {
    inner: mpsc::Sender<SpliceAddresses>,
}

impl std::fmt::Debug for TouchedAddresses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TouchedAddresses")
    }
}

impl TouchedAddresses {
    pub fn blocking_extend(
        &self,
        start_clk: u64,
        end_clk: u64,
        addresses: Vec<u64>,
    ) -> anyhow::Result<()> {
        self.inner.blocking_send(SpliceAddresses { start_clk, end_clk, addresses })?;
        Ok(())
    }

    pub async fn extend(
        &self,
        start_clk: u64,
        end_clk: u64,
        addresses: Vec<u64>,
    ) -> anyhow::Result<()> {
        self.inner.send(SpliceAddresses { start_clk, end_clk, addresses }).await?;
        Ok(())
    }
}

pub struct GlobalMemoryHandler(mpsc::Receiver<SpliceAddresses>);

pub fn global_memory(capacity: usize) -> (TouchedAddresses, GlobalMemoryHandler) {
    let (tx, rx) = mpsc::channel(capacity);
    (TouchedAddresses { inner: tx }, GlobalMemoryHandler(rx))
}

impl GlobalMemoryHandler {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn emit_global_memory_shards(
        mut self,
        program: Arc<Program>,
        final_state_rx: oneshot::Receiver<FinalVmState>,
        executor_rx: oneshot::Receiver<MinimalExecutorRunner>,
        prove_shard_tx: mpsc::UnboundedSender<ProofData>,
        elf_artifact: Artifact,
        common_input_artifact: Artifact,
        context: TaskContext,
        memory: UnsafeMemory,
        opts: SP1CoreOpts,
        num_deferred_proofs: usize,
        artifact_client: impl ArtifactClient,
        worker_client: impl WorkerClient,
        minimal_executor_cache: Option<MinimalExecutorCache>,
    ) -> Result<(), TaskError> {
        let (shard_data_tx, mut shard_data_rx) =
            mpsc::unbounded_channel::<(ShardRange, TraceData)>();

        let span = tracing::debug_span!("collect global memory events");
        let mut join_set = JoinSet::<Result<_, TaskError>>::new();
        join_set.spawn_blocking({
            let program = program.clone();
            move || {
                let _guard = span.enter();
                let mut initialized_events = BTreeMap::<u64, MemoryInitializeFinalizeEvent>::new();
                let mut finalized_events = BTreeMap::<u64, MemoryInitializeFinalizeEvent>::new();
                let mut dirty_addresses = BTreeSet::<u64>::new();
                #[cfg(sp1_debug_global_memory)]
                let mut touched_addresses = hashbrown::HashSet::<u64>::new();

                // Collect the addresses
                while let Some(addresses) = self.0.blocking_recv() {
                    let SpliceAddresses { start_clk, end_clk, addresses } = addresses;
                    for addr in addresses {
                        #[cfg(sp1_debug_global_memory)]
                        touched_addresses.insert(addr);
                        // Add the address to the initialized events map if it was not already initialized.
                        initialized_events
                            .entry(addr)
                            .or_insert_with(|| MemoryInitializeFinalizeEvent::initialize(addr, 0));

                        // Get the memory value
                        // # Safety: since we are waiting for the minimal executor to finish, we assume that
                        // it is still alive. However, if it did panic, the whole proof flow should fail
                        // but the potential for undefined behavior is still there.
                        let value = unsafe { memory.get(addr) };
                        // If the value was touched after this splice has finished, add it to the 
                        // dirty addresses set and skip the finalization.
                        if value.clk > end_clk || value.clk < start_clk {
                            dirty_addresses.insert(addr);
                            continue;
                        }
                        // Add the address to the finalized events map. If it was already seen, 
                        // update the value, timestamp and clk. Otherwise, create a new event and 
                        // add it to the map.
                        finalized_events
                            .entry(addr)
                            .and_modify(|entry| {
                                if entry.timestamp < value.clk {
                                   entry.value = value.value;
                                   entry.timestamp = value.clk;
                                }
                            })
                            .or_insert_with(|| {
                                MemoryInitializeFinalizeEvent::finalize(
                                    addr,
                                    value.value,
                                    value.clk,
                                )
                            });
                        // If the address was previously dirty, remove it from the dirty addresses
                        // set.
                        dirty_addresses.remove(&addr);
                    }
                }

                // Collect the hints
                let minimal_executor = executor_rx
                    .blocking_recv()
                    .map_err(|_| anyhow::anyhow!("failed to receive minimal executor"))?;
                let hint_init_events = minimal_executor
                    .hints()
                    .iter()
                    .flat_map(|(addr, value)| chunked_memory_init_events(*addr, value));
                for event in hint_init_events {
                    #[cfg(sp1_debug_global_memory)]
                    touched_addresses.insert(event.addr);
                    // Initialize the hint address to the value of the hint
                    initialized_events.insert(event.addr, event);
                    // Finalize the addresses of hints.
                    let value = minimal_executor.get_memory_value(event.addr);
                    finalized_events.insert(
                        event.addr,
                        MemoryInitializeFinalizeEvent::finalize(event.addr, value.value, value.clk),
                    );
                }
                // Finalize the dirty addresses.
                for addr in dirty_addresses {
                    let value = minimal_executor.get_memory_value(addr);
                    finalized_events.insert(
                        addr,
                        MemoryInitializeFinalizeEvent::finalize(addr, value.value, value.clk),
                    );
                }

                // Wait for the final state
                let final_state = final_state_rx
                    .blocking_recv()
                    .map_err(|_| anyhow::anyhow!("failed to receive final state"))?;

                for (i, entry) in
                    final_state.registers.iter().enumerate().filter(|(_, e)| e.timestamp != 0)
                {
                    initialized_events
                        .insert(i as u64, MemoryInitializeFinalizeEvent::initialize(i as u64, 0));
                    finalized_events.insert(
                        i as u64,
                        MemoryInitializeFinalizeEvent::finalize(
                            i as u64,
                            entry.value,
                            entry.timestamp,
                        ),
                    );
                }

                // Remove initialized events for addresses in the program memory image.
                for addr in program.memory_image.keys() {
                    initialized_events.remove(addr);
                }

                // Handle the program memory image addresses.
                for addr in program.memory_image.keys() {
                    #[cfg(sp1_debug_global_memory)]
                    touched_addresses.insert(*addr);
                    // Remove the address from the initialized events map. This is because the 
                    // program memory image is already initialized as part of the program initial 
                    // cumulative sum.
                    initialized_events.remove(addr);
                    // Finalize the address.
                    let value = minimal_executor.get_memory_value(*addr);
                    let event =
                        MemoryInitializeFinalizeEvent::finalize(*addr, value.value, value.clk);
                    finalized_events.insert(*addr, event);
                }

                #[cfg(sp1_debug_global_memory)]
                for (i, addr) in touched_addresses.into_iter().enumerate() {
                    if i % 100_000 == 0 {
                        tracing::debug!("checked {i} addresses");
                    }
                    let value = minimal_executor.get_memory_value(addr);
                    let event = finalized_events.get(&addr).unwrap();

                    let expected_value = value.value;
                    let expected_clk = value.clk;
                    let seen_value = event.value;
                    let seen_clk = event.timestamp;
                    if expected_value != seen_value || expected_clk != seen_clk {
                        panic!("Address {addr} wrong value\n
                            Expected value: {expected_value}, expected clk: {expected_clk}/ 
                            seen value: {seen_value}, seen clk: {seen_clk}");
                    }

                }

                let mut memory_initialize_events = Vec::with_capacity(initialized_events.len());
                memory_initialize_events.extend(initialized_events.into_values());
                let mut memory_finalize_events = Vec::with_capacity(finalized_events.len());
                memory_finalize_events.extend(finalized_events.into_values());

                // Get the split opts.
                let split_opts = SplitOpts::new(&opts, program.instructions.len(), false);
                let threshold = split_opts.memory;

                let mut previous_init_addr = 0;
                let mut previous_finalize_addr = 0;
                let mut previous_init_page_idx = 0;
                let mut previous_finalize_page_idx = 0;
                for (i, chunks) in memory_initialize_events
                    .chunks(threshold)
                    .zip_longest(memory_finalize_events.chunks(threshold))
                    .enumerate()
                {
                    let (initialize_events, finalize_events) = match chunks {
                        itertools::EitherOrBoth::Left(initialize_events) => {
                            let mut init_events = Vec::with_capacity(threshold);
                            init_events.extend_from_slice(initialize_events);
                            (init_events, vec![])
                        }
                        itertools::EitherOrBoth::Right(finalize_events) => {
                            let mut final_events = Vec::with_capacity(threshold);
                            final_events.extend_from_slice(finalize_events);
                            (vec![], final_events)
                        }
                        itertools::EitherOrBoth::Both(initialize_events, finalize_events) => {
                            let mut init_events = Vec::with_capacity(threshold);
                            init_events.extend_from_slice(initialize_events);
                            let mut final_events = Vec::with_capacity(threshold);
                            final_events.extend_from_slice(finalize_events);
                            (init_events, final_events)
                        }
                    };
                    tracing::debug!("Got global memory shard number {i}");
                    let last_init_addr = initialize_events
                        .last()
                        .map(|event| event.addr)
                        .unwrap_or(previous_init_addr);
                    let last_finalize_addr = finalize_events
                        .last()
                        .map(|event| event.addr)
                        .unwrap_or(previous_finalize_addr);
                    tracing::debug!("last_init_addr: {last_init_addr}, last_finalize_addr: {last_finalize_addr}");
                    let last_init_page_idx = previous_init_page_idx;
                    let last_finalize_page_idx = previous_finalize_page_idx;
                    // Calculate the range of the shard.
                    let range = ShardRange {
                        timestamp_range: (final_state.timestamp, final_state.timestamp),
                        initialized_address_range: (previous_init_addr, last_init_addr),
                        finalized_address_range: (previous_finalize_addr, last_finalize_addr),
                        initialized_page_index_range: (previous_init_page_idx, last_init_page_idx),
                        finalized_page_index_range: (
                            previous_finalize_page_idx,
                            last_finalize_page_idx,
                        ),
                        deferred_proof_range: (
                            num_deferred_proofs as u64,
                            num_deferred_proofs as u64,
                        ),
                    };
                    let mem_global_shard = GlobalMemoryShard {
                        final_state,
                        initialize_events,
                        finalize_events,
                        previous_init_addr,
                        previous_finalize_addr,
                        previous_init_page_idx,
                        previous_finalize_page_idx,
                        last_init_addr,
                        last_finalize_addr,
                        last_init_page_idx,
                        last_finalize_page_idx,
                    };

                    let data = TraceData::Memory(Box::new(mem_global_shard));
                    shard_data_tx
                        .send((range, data))
                        .map_err(|e| anyhow::anyhow!("failed to send shard data: {}", e))?;

                    previous_init_addr = last_init_addr;
                    previous_finalize_addr = last_finalize_addr;
                    previous_init_page_idx = last_init_page_idx;
                    previous_finalize_page_idx = last_finalize_page_idx;
                }

                Ok(Some(minimal_executor))
            }
        });

        join_set.spawn(
            async move {
                let mut shard_join_set = JoinSet::new();
                while let Some((range, data)) = shard_data_rx.recv().await {
                    shard_join_set.spawn({
                        let worker_client = worker_client.clone();
                        let artifact_client = artifact_client.clone();
                        let elf_artifact = elf_artifact.clone();
                        let common_input_artifact = common_input_artifact.clone();
                        let context = context.clone();
                        let prove_shard_tx = prove_shard_tx.clone();
                        async move {
                            let SpawnProveOutput { proof_data, .. } = create_core_proving_task(
                                elf_artifact.clone(),
                                common_input_artifact.clone(),
                                context.clone(),
                                range,
                                data,
                                worker_client,
                                artifact_client,
                            )
                            .await?;

                            // Send the task data
                            prove_shard_tx
                                .send(proof_data)
                                .map_err(|e| anyhow::anyhow!("failed to send task id: {}", e))?;
                            Ok::<(), TaskError>(())
                        }
                        .in_current_span()
                    });
                }
                // Wait for all the shard task to be created
                while let Some(result) = shard_join_set.join_next().await {
                    result.map_err(|e| {
                        anyhow::anyhow!("failed to create a global memory shard task: {}", e)
                    })??;
                }
                Ok(None)
            }
            .instrument(tracing::debug_span!("create global memory shards")),
        );

        // Wait for the tasks to finish
        while let Some(result) = join_set.join_next().await {
            let maybe_minimal_executor = result
                .map_err(|e| anyhow::anyhow!("global memory shards task panicked: {}", e))??;
            if let Some(mut minimal_executor) = maybe_minimal_executor {
                if let Some(ref minimal_executor_cache) = minimal_executor_cache {
                    minimal_executor.reset();
                    let mut cache = minimal_executor_cache
                        .lock()
                        .instrument(tracing::debug_span!("wait for executor cache lock"))
                        .await;
                    if cache.is_some() {
                        tracing::warn!("Unexpected minimal executor cache is not empty");
                    }
                    *cache = Some(minimal_executor);
                }
            }
        }

        Ok(())
    }
}
