use std::sync::Arc;

use itertools::Itertools;
use sp1_core_executor::{
    chunked_memory_init_events,
    events::{MemoryInitializeFinalizeEvent, PageProtInitializeFinalizeEvent},
    CompressedMemory, CompressedPages, Program, SP1CoreOpts, SplitOpts, UnsafeMemory,
};
use sp1_core_executor_runner::MinimalExecutorRunner;
use sp1_hypercube::air::ShardRange;
use sp1_primitives::consts::DEFAULT_PAGE_PROT;
use sp1_prover_types::{Artifact, ArtifactClient};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tracing::Instrument;

use crate::worker::{
    controller::create_core_proving_task, FinalVmState, GlobalMemoryShard, MessageSender,
    MinimalExecutorCache, ProofData, SpawnProveOutput, TaskContext, TaskError, TraceData,
    WorkerClient,
};

#[derive(Clone)]
pub struct TouchedAddresses {
    inner: mpsc::Sender<CompressedMemory>,
}

impl std::fmt::Debug for TouchedAddresses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TouchedAddresses")
    }
}

impl TouchedAddresses {
    pub fn blocking_extend(&self, addresses: CompressedMemory) -> anyhow::Result<()> {
        self.inner.blocking_send(addresses)?;
        Ok(())
    }

    pub async fn extend(&self, addresses: CompressedMemory) -> anyhow::Result<()> {
        self.inner.send(addresses).await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct TouchedPages {
    inner: mpsc::UnboundedSender<CompressedPages>,
}

impl std::fmt::Debug for TouchedPages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TouchedPages")
    }
}

impl TouchedPages {
    pub fn blocking_extend(&self, pages: CompressedPages) -> anyhow::Result<()> {
        self.inner.send(pages)?;
        Ok(())
    }

    pub async fn extend(&self, pages: CompressedPages) -> anyhow::Result<()> {
        self.inner.send(pages)?;
        Ok(())
    }
}

pub struct GlobalMemoryHandler {
    addresses_rx: mpsc::Receiver<CompressedMemory>,
    pages_rx: mpsc::UnboundedReceiver<CompressedPages>,
}

pub fn global_memory(capacity: usize) -> (TouchedAddresses, TouchedPages, GlobalMemoryHandler) {
    let (addr_tx, addr_rx) = mpsc::channel(capacity);
    let (pages_tx, pages_rx) = mpsc::unbounded_channel();
    (
        TouchedAddresses { inner: addr_tx },
        TouchedPages { inner: pages_tx },
        GlobalMemoryHandler { addresses_rx: addr_rx, pages_rx },
    )
}

impl GlobalMemoryHandler {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn emit_global_memory_shards<A: ArtifactClient, W: WorkerClient>(
        mut self,
        program: Arc<Program>,
        final_state_rx: oneshot::Receiver<FinalVmState>,
        executor_rx: oneshot::Receiver<MinimalExecutorRunner>,
        prove_shard_tx: MessageSender<W, ProofData>,
        elf_artifact: Artifact,
        common_input_artifact: Artifact,
        context: TaskContext,
        memory: UnsafeMemory,
        opts: SP1CoreOpts,
        num_deferred_proofs: usize,
        artifact_client: A,
        worker_client: W,
        gate: super::ProveShardGate<A, W>,
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

                // Union the per-chunk touched-address bitmaps into a single global bitmap.
                // Each merge OR's the per-chunk pages into the global pages — addresses are
                // already 8-byte-aligned by construction (CompressedMemory's ALIGNMENT is 8).
                let mut touched_global = CompressedMemory::new();
                while let Some(chunk_mem) = self.addresses_rx.blocking_recv() {
                    touched_global.merge(&chunk_mem);
                }

                // Same for touched pages.
                let mut touched_pages = CompressedPages::new();
                while let Some(chunk_pages) = self.pages_rx.blocking_recv() {
                    touched_pages.merge(&chunk_pages);
                }

                // Get the minimal executor (now done with execution) so we can look up final
                // memory values via SHM-backed UnsafeMemory at drain time.
                let minimal_executor = executor_rx
                    .blocking_recv()
                    .map_err(|_| anyhow::anyhow!("failed to receive minimal executor"))?;

                // Add hint init addresses to the global bitmap and stash their init values
                // (hints get init events whose value is the hint chunk, not 0).
                let mut hint_init_values: hashbrown::HashMap<u64, u64> = hashbrown::HashMap::new();
                for (addr, value) in minimal_executor.hints().iter() {
                    for event in chunked_memory_init_events(*addr, value) {
                        touched_global.insert(event.addr, true);
                        hint_init_values.insert(event.addr, event.value);
                    }
                }

                // Add program-memory-image addresses to the bitmap; they DO get finalize events,
                // but NOT init events (initialization is folded into the program cumulative sum).
                for &addr in program.memory_image.keys() {
                    touched_global.insert(addr, true);
                }

                // Wait for the final VM state (registers).
                let final_state = final_state_rx
                    .blocking_recv()
                    .map_err(|_| anyhow::anyhow!("failed to receive final state"))?;

                // Get the split opts (needed up front to size shard buffers).
                let split_opts = SplitOpts::new(
                    &opts,
                    program.instructions.len(),
                    program.enable_untrusted_programs,
                );
                let threshold = split_opts.memory;

                let mut previous_init_addr = 0u64;
                let mut previous_finalize_addr = 0u64;
                let mut previous_init_page_idx = 0u64;
                let mut previous_finalize_page_idx = 0u64;
                let mut shard_counter = 0usize;

                // Streaming shard emission: instead of materializing the full
                // `memory_initialize_events` and `memory_finalize_events` Vecs and then
                // `.chunks(threshold)`-ing them, we accumulate per-shard buffers and emit
                // a shard as soon as either buffer fills.
                //
                // Since `finalize_buffer` grows >= `init_buffer` at every step (program-image
                // addresses push to finalize but not init), `finalize_buffer` always reaches
                // `threshold` first or at the same time. The total shard count is therefore
                // `ceil(N_finalize / threshold)`, matching what
                // `max(ceil(N_init/threshold), ceil(N_finalize/threshold))` produced before.
                let mut init_buffer: Vec<MemoryInitializeFinalizeEvent> =
                    Vec::with_capacity(threshold);
                let mut final_buffer: Vec<MemoryInitializeFinalizeEvent> =
                    Vec::with_capacity(threshold);

                // Macro to flush the current buffers as one global memory shard. Implemented
                // as a macro (not a closure) so the borrow checker doesn't have to reason
                // about simultaneous &mut borrows of the many surrounding locals.
                macro_rules! flush_memory_shard {
                    () => {{
                        if !init_buffer.is_empty() || !final_buffer.is_empty() {
                            let last_init_addr =
                                init_buffer.last().map(|e| e.addr).unwrap_or(previous_init_addr);
                            let last_finalize_addr = final_buffer
                                .last()
                                .map(|e| e.addr)
                                .unwrap_or(previous_finalize_addr);
                            let last_init_page_idx = previous_init_page_idx;
                            let last_finalize_page_idx = previous_finalize_page_idx;
                            tracing::debug!(
                                shard_counter,
                                init_len = init_buffer.len(),
                                final_len = final_buffer.len(),
                                last_init_addr,
                                last_finalize_addr,
                                "emit global memory shard"
                            );
                            let range = ShardRange {
                                timestamp_range: (final_state.timestamp, final_state.timestamp),
                                initialized_address_range: (previous_init_addr, last_init_addr),
                                finalized_address_range: (
                                    previous_finalize_addr,
                                    last_finalize_addr,
                                ),
                                initialized_page_index_range: (
                                    previous_init_page_idx,
                                    last_init_page_idx,
                                ),
                                finalized_page_index_range: (
                                    previous_finalize_page_idx,
                                    last_finalize_page_idx,
                                ),
                                deferred_proof_range: (
                                    num_deferred_proofs as u64,
                                    num_deferred_proofs as u64,
                                ),
                            };
                            // Swap the filled buffers out for fresh pre-allocated ones so we
                            // don't reallocate on every flush.
                            let initialize_events =
                                std::mem::replace(&mut init_buffer, Vec::with_capacity(threshold));
                            let finalize_events =
                                std::mem::replace(&mut final_buffer, Vec::with_capacity(threshold));
                            let mem_global_shard = GlobalMemoryShard {
                                final_state,
                                initialize_events,
                                finalize_events,
                                page_prot_initialize_events: vec![],
                                page_prot_finalize_events: vec![],
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
                            shard_counter += 1;
                        }
                    }};
                }

                // Now stream-merge the global touched bitmap and register addresses in
                // ascending order, pushing init/finalize events into the buffers.
                // Source A: the bitmap (8-byte-aligned memory addresses).
                // Source B: register addresses 0..32 with timestamp != 0 — registers use the
                // raw index as address and override any colliding bitmap entry.
                let bitmap_addrs = touched_global.is_set();
                let register_addrs: Vec<u64> = final_state
                    .registers
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| e.timestamp != 0)
                    .map(|(i, _)| i as u64)
                    .collect();
                // register_addrs is already sorted ascending (iter().enumerate()).

                let mut bit_i = 0usize;
                let mut reg_i = 0usize;
                while bit_i < bitmap_addrs.len() || reg_i < register_addrs.len() {
                    let (use_reg, addr) = match (
                        bitmap_addrs.get(bit_i).copied(),
                        register_addrs.get(reg_i).copied(),
                    ) {
                        (Some(b), Some(r)) => {
                            if r <= b {
                                (true, r)
                            } else {
                                (false, b)
                            }
                        }
                        (None, Some(r)) => (true, r),
                        (Some(b), None) => (false, b),
                        (None, None) => break,
                    };
                    if use_reg {
                        let entry = &final_state.registers[addr as usize];
                        init_buffer.push(MemoryInitializeFinalizeEvent::initialize(addr, 0));
                        final_buffer.push(MemoryInitializeFinalizeEvent::finalize(
                            addr,
                            entry.value,
                            entry.timestamp,
                        ));
                        reg_i += 1;
                        if bitmap_addrs.get(bit_i).copied() == Some(addr) {
                            bit_i += 1;
                        }
                    } else {
                        bit_i += 1;
                        if !program.memory_image.contains_key(&addr) {
                            let init_value = hint_init_values.get(&addr).copied().unwrap_or(0);
                            init_buffer
                                .push(MemoryInitializeFinalizeEvent::initialize(addr, init_value));
                        }
                        let v = unsafe { memory.get(addr) };
                        final_buffer
                            .push(MemoryInitializeFinalizeEvent::finalize(addr, v.value, v.clk));
                    }
                    if init_buffer.len() >= threshold || final_buffer.len() >= threshold {
                        flush_memory_shard!();
                    }
                }
                // Emit any trailing partial shard.
                flush_memory_shard!();
                tracing::debug!(
                    total_memory_shards = shard_counter,
                    "memory shard emission complete"
                );

                // Collect page prot events if untrusted programs are enabled.
                let (page_prot_initialize_events, page_prot_finalize_events) =
                    if program.enable_untrusted_programs {
                        // Union the program's page_prot_image keys into the touched-pages bitmap.
                        for &page_idx in program.page_prot_image.keys() {
                            touched_pages.insert(page_idx, true);
                        }

                        let pages_sorted = touched_pages.is_set();
                        let mut init_events = Vec::with_capacity(pages_sorted.len());
                        let mut finalize_events = Vec::with_capacity(pages_sorted.len());

                        for &page_idx in &pages_sorted {
                            let record = minimal_executor.get_page_prot_record(page_idx).unwrap();

                            if !program.page_prot_image.contains_key(&page_idx) {
                                init_events.push(PageProtInitializeFinalizeEvent::initialize(
                                    page_idx,
                                    DEFAULT_PAGE_PROT,
                                ));
                            }

                            finalize_events.push(PageProtInitializeFinalizeEvent {
                                page_idx,
                                page_prot: record.value,
                                timestamp: record.timestamp,
                            });
                        }

                        // `pages_sorted` is already ascending; no need to re-sort.
                        (init_events, finalize_events)
                    } else {
                        assert_eq!(touched_pages.count_set(), 0);
                        (vec![], vec![])
                    };

                // Emit page prot shards (separate from memory shards).
                let page_prot_threshold = split_opts.page_prot;
                if page_prot_threshold > 0 {
                    for chunks in page_prot_initialize_events
                        .chunks(page_prot_threshold)
                        .zip_longest(page_prot_finalize_events.chunks(page_prot_threshold))
                    {
                        let (pp_init_events, pp_finalize_events) = match chunks {
                            itertools::EitherOrBoth::Left(init) => (init.to_vec(), vec![]),
                            itertools::EitherOrBoth::Right(fin) => (vec![], fin.to_vec()),
                            itertools::EitherOrBoth::Both(init, fin) => {
                                (init.to_vec(), fin.to_vec())
                            }
                        };
                        let last_init_page_idx = pp_init_events
                            .last()
                            .map(|e| e.page_idx)
                            .unwrap_or(previous_init_page_idx);
                        let last_finalize_page_idx = pp_finalize_events
                            .last()
                            .map(|e| e.page_idx)
                            .unwrap_or(previous_finalize_page_idx);

                        let range = ShardRange {
                            timestamp_range: (final_state.timestamp, final_state.timestamp),
                            initialized_address_range: (previous_init_addr, previous_init_addr),
                            finalized_address_range: (
                                previous_finalize_addr,
                                previous_finalize_addr,
                            ),
                            initialized_page_index_range: (
                                previous_init_page_idx,
                                last_init_page_idx,
                            ),
                            finalized_page_index_range: (
                                previous_finalize_page_idx,
                                last_finalize_page_idx,
                            ),
                            deferred_proof_range: (
                                num_deferred_proofs as u64,
                                num_deferred_proofs as u64,
                            ),
                        };
                        let page_prot_shard = GlobalMemoryShard {
                            final_state,
                            initialize_events: vec![],
                            finalize_events: vec![],
                            page_prot_initialize_events: pp_init_events,
                            page_prot_finalize_events: pp_finalize_events,
                            previous_init_addr,
                            previous_finalize_addr,
                            previous_init_page_idx,
                            previous_finalize_page_idx,
                            last_init_addr: previous_init_addr,
                            last_finalize_addr: previous_finalize_addr,
                            last_init_page_idx,
                            last_finalize_page_idx,
                        };

                        let data = TraceData::Memory(Box::new(page_prot_shard));
                        shard_data_tx.send((range, data)).map_err(|e| {
                            anyhow::anyhow!("failed to send page prot shard data: {}", e)
                        })?;

                        previous_init_page_idx = last_init_page_idx;
                        previous_finalize_page_idx = last_finalize_page_idx;
                    }
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
                        let gate = gate.clone();
                        async move {
                            let SpawnProveOutput { proof_data, .. } = create_core_proving_task(
                                elf_artifact.clone(),
                                common_input_artifact.clone(),
                                context.clone(),
                                range,
                                data,
                                worker_client,
                                artifact_client,
                                &gate,
                            )
                            .await?;

                            prove_shard_tx
                                .send(proof_data)
                                .await
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
