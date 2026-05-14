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

                // Now emit memory init/finalize events with addresses in ascending order.
                // Source A: the global touched bitmap (8-byte-aligned memory addresses).
                // Source B: register addresses 0..32 whose timestamp != 0 (registers use the
                // raw index as address and override any colliding bitmap entry).
                let bitmap_addrs = touched_global.is_set();
                let register_addrs: Vec<u64> = final_state
                    .registers
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| e.timestamp != 0)
                    .map(|(i, _)| i as u64)
                    .collect();
                // register_addrs is already sorted ascending by construction (iter().enumerate()).

                let capacity_hint = bitmap_addrs.len() + register_addrs.len();
                let mut memory_initialize_events: Vec<MemoryInitializeFinalizeEvent> =
                    Vec::with_capacity(capacity_hint);
                let mut memory_finalize_events: Vec<MemoryInitializeFinalizeEvent> =
                    Vec::with_capacity(capacity_hint);

                let mut bit_i = 0usize;
                let mut reg_i = 0usize;
                while bit_i < bitmap_addrs.len() || reg_i < register_addrs.len() {
                    // Peek at the next address from each stream.
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
                        // Registers always get init=0 and finalize from final_state.
                        memory_initialize_events
                            .push(MemoryInitializeFinalizeEvent::initialize(addr, 0));
                        memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize(
                            addr,
                            entry.value,
                            entry.timestamp,
                        ));
                        reg_i += 1;
                        // If the bitmap also has this exact address, skip it — register overrides.
                        if bitmap_addrs.get(bit_i).copied() == Some(addr) {
                            bit_i += 1;
                        }
                    } else {
                        bit_i += 1;
                        // Init event: skip for program-memory-image; use hint value if present;
                        // otherwise default to 0.
                        if !program.memory_image.contains_key(&addr) {
                            let init_value = hint_init_values.get(&addr).copied().unwrap_or(0);
                            memory_initialize_events.push(
                                MemoryInitializeFinalizeEvent::initialize(addr, init_value),
                            );
                        }
                        // Finalize event: read the final value from live SHM. Safe because the
                        // minimal executor is still alive (we awaited it above).
                        let v = unsafe { memory.get(addr) };
                        memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize(
                            addr, v.value, v.clk,
                        ));
                    }
                }

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
                            let record =
                                minimal_executor.get_page_prot_record(page_idx).unwrap();

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

                // Get the split opts.
                let split_opts = SplitOpts::new(
                    &opts,
                    program.instructions.len(),
                    program.enable_untrusted_programs,
                );
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
                }

                // Emit page prot shards (separate from memory shards).
                let page_prot_threshold = split_opts.page_prot;
                if page_prot_threshold > 0 {
                    for chunks in page_prot_initialize_events
                        .chunks(page_prot_threshold)
                        .zip_longest(page_prot_finalize_events.chunks(page_prot_threshold))
                    {
                        let (pp_init_events, pp_finalize_events) = match chunks {
                            itertools::EitherOrBoth::Left(init) => {
                                (init.to_vec(), vec![])
                            }
                            itertools::EitherOrBoth::Right(fin) => {
                                (vec![], fin.to_vec())
                            }
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
