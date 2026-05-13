use std::sync::Arc;

use clap::Parser;
use slop_algebra::AbstractField;
use sp1_core_executor::{
    minimal::arch::portable::MinimalExecutor as PortableMinimalExecutor, CompressedMemory,
    CompressedPages, CycleResult, MinimalExecutor, Program, SP1CoreOpts, ShardData,
    SplicedMinimalTrace, SplicingVM, SupervisorMode, MERKLE_PAGE_BYTES, MERKLE_PAGE_WORDS,
};
use sp1_core_machine::{io::SP1Stdin, riscv::RiscvAir};
use sp1_hypercube::{septic_digest::SepticDigest, MachineVerifyingKey, UntrustedConfig};
use sp1_jit::{risc::MinimalTrace, MemValue};
use sp1_primitives::{Elf, SP1Field};
use sp1_prover::{
    worker::{
        CommonProverInput, MessageReceiver, MessageSender, ProofData, ProofId, ProveShardGate,
        RequesterId, SP1CoreExecutor, SplicingEngine, SplicingWorker, TaskContext, TaskId,
        TrivialWorkerClient, WorkerClient,
    },
    SP1VerifyingKey,
};
use sp1_prover_types::{network_base_types::ProofMode, ArtifactClient, InMemoryArtifactClient};
use sp1_sdk::{setup_logger, MockProver, Prover};
use std::collections::HashSet;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "local-fibonacci")]
    pub program: String,
    #[arg(long, default_value = "")]
    pub param: String,
    #[arg(long, default_value = "10")]
    pub splice_workers: usize,
    #[arg(long, default_value = "10")]
    pub splice_buffer: usize,
    #[arg(long, default_value = "2")]
    pub send_workers: usize,
    #[arg(long, default_value = "2")]
    pub send_buffer_size: usize,
    #[arg(long, default_value = None)]
    pub chunk_size: Option<u64>,
    #[arg(long, default_value = "10")]
    pub task_capacity: usize,
    #[arg(long, default_value = "false")]
    pub telemetry: bool,
    #[arg(long, default_value = "gas")]
    pub mode: String,
    #[arg(long, default_value = None)]
    pub cycle_limit: Option<u64>,
    #[arg(long, default_value = "false")]
    pub local: bool,
    #[arg(long, default_value = "false")]
    pub gpu_5090: bool,
    /// (`minimal_splice` mode only) Snapshot the first chunk's `MemValue`s before splicing
    /// and assert byte-equality after splicing. Validates that `SplicingVM`'s in-place
    /// `MemValue.clk` writeback reproduces what portable wrote. Off by default; the
    /// snapshot allocation is gated so non-`--verify` runs incur zero added overhead.
    #[arg(long, default_value = "false")]
    pub verify: bool,
}

// Executes a program similarly to the cluster controller.
async fn execute_node(args: Args, elf: Vec<u8>, stdin: SP1Stdin) {
    // Initialize the artifact and worker clients
    let artifact_client = InMemoryArtifactClient::new();
    let worker_client = TrivialWorkerClient::new(args.task_capacity, artifact_client.clone());

    let proof_id = ProofId::new("bench_pure_execution");
    let gate =
        ProveShardGate::new(artifact_client.clone(), worker_client.clone(), proof_id.clone())
            .await
            .expect("failed to create gate");

    let splicing_workers = (0..args.splice_workers)
        .map(|_| {
            SplicingWorker::new(
                artifact_client.clone(),
                worker_client.clone(),
                gate.clone(),
                args.send_workers,
                args.send_buffer_size,
            )
        })
        .collect::<Vec<_>>();

    let splicing_engine = Arc::new(SplicingEngine::new(splicing_workers, args.splice_buffer));

    let parent_id = None;
    let parent_context = None;
    let requester_id = RequesterId::new("bench_pure_execution");

    let dummy_vk = MachineVerifyingKey {
        pc_start: [SP1Field::zero(); 3],
        initial_global_cumulative_sum: SepticDigest::zero(),
        preprocessed_commit: [SP1Field::zero(); 8],
        untrusted_config: UntrustedConfig::zero(),
    };
    let dummy_vk = SP1VerifyingKey { vk: dummy_vk };

    let common_input = CommonProverInput {
        vk: dummy_vk,
        deferred_digest: [0; 8],
        mode: ProofMode::Core,
        num_deferred_proofs: 0,
        nonce: [0; 4],
    };
    let common_input_artifact =
        artifact_client.create_artifact().expect("failed to create artifact");
    artifact_client
        .upload(&common_input_artifact, common_input)
        .await
        .expect("failed to upload common input");

    let dummy_task_id = TaskId::new("perf-executor".to_string());
    let sender = MessageSender::<TrivialWorkerClient, ProofData>::new(
        worker_client.clone(),
        dummy_task_id.clone(),
    );
    let mut receiver = MessageReceiver::<ProofData>::new(
        worker_client.subscribe_task_messages(&dummy_task_id).await.unwrap(),
    );

    let elf_artifact = artifact_client.create_artifact().expect("failed to create artifact");
    let elf_bytes = elf.to_vec();
    artifact_client.upload(&elf_artifact, elf_bytes).await.expect("failed to upload elf");

    let stdin = Arc::new(stdin);

    let mut opts = SP1CoreOpts::default();
    if let Some(chunk_size) = args.chunk_size {
        opts.minimal_trace_chunk_threshold = chunk_size;
    }
    let task_context = TaskContext { proof_id, parent_id, parent_context, requester_id };
    let global_memory_buffer_size = 2 * args.splice_workers;
    let executor = SP1CoreExecutor::new(
        splicing_engine,
        global_memory_buffer_size,
        elf_artifact,
        stdin,
        common_input_artifact,
        opts,
        0,
        task_context,
        sender,
        artifact_client,
        worker_client,
        gate,
        None,
        args.cycle_limit,
        RiscvAir::machine(),
    );

    let counter_handle = tokio::task::spawn(async move {
        let mut shard_counter = 0;
        while receiver.recv().await.is_some() {
            shard_counter += 1;
        }
        println!("num shards: {shard_counter}");
    });

    // Execute and see the result
    let time = tokio::time::Instant::now();
    let result = executor.execute().await.expect("failed to execute");
    let time = time.elapsed();
    println!(
        "cycles: {}, execution time: {:?}, mhz: {}",
        result.cycles,
        time,
        result.cycles as f64 / (time.as_secs_f64() * 1_000_000.0)
    );

    // Make sure the counter is finished before exiting
    counter_handle.await.expect("counter task panicked");
}

// Executes a program while measuring gas and prints the gas report.
async fn execute_gas(elf: Vec<u8>, stdin: SP1Stdin) {
    let prover = MockProver::new().await;

    let now = std::time::Instant::now();
    let (_, report) = prover
        .execute(Elf::from(elf), stdin)
        .calculate_gas(true)
        .deferred_proof_verification(false)
        .await
        .unwrap();
    let time = now.elapsed();
    println!("gas report: {}", report);
    println!("time: {:?}", time);
    println!(
        "mhz: {}",
        report.total_instruction_count() as f64 / (time.as_secs_f64() * 1_000_000.0)
    );
}

// Executes MinimalExecutor alone
fn execute_minimal(elf: Vec<u8>, stdin: SP1Stdin, trace: bool) {
    let max_trace_size =
        if trace { Some(SP1CoreOpts::default().minimal_trace_chunk_threshold) } else { None };

    let now = std::time::Instant::now();
    let program = Arc::new(Program::from(&elf).expect("parse elf"));
    let mut executor = MinimalExecutor::<SupervisorMode>::new(program, false, max_trace_size);
    for buf in stdin.buffer {
        executor.with_input(&buf);
    }
    let time = now.elapsed();
    println!("MinimalExecutor creation time: {:?}", time);

    let now = std::time::Instant::now();
    while executor.execute_chunk().is_some() {}
    let time = now.elapsed();

    println!("exit code: {}, cycles: {}", executor.exit_code(), executor.global_clk());
    println!("execution time: {:?}", time);
    println!("mhz: {}", executor.global_clk() as f64 / (time.as_secs_f64() * 1_000_000.0));
}

// Executes MinimalExecutor + SplicingVM, collecting per-chunk stats.
struct ChunksData {
    chunks: Vec<sp1_jit::TraceChunkRaw>,
    chunk_dirty_pages: Vec<Vec<u32>>,
    chunk_dirty_pages_final: Vec<Vec<[u64; MERKLE_PAGE_WORDS]>>,
    total_cycles: u64,
    exec_time: std::time::Duration,
    backend_label: &'static str,
}

fn build_opts(chunk_threshold: Option<u64>, gpu_5090: bool) -> (SP1CoreOpts, u64) {
    use sp1_core_executor::ELEMENT_THRESHOLD;
    let mut opts = SP1CoreOpts::default();
    opts.sharding_threshold.element_threshold =
        if gpu_5090 { ELEMENT_THRESHOLD } else { ELEMENT_THRESHOLD - (1 << 26) - (1 << 25) };
    if let Some(threshold) = chunk_threshold {
        opts.minimal_trace_chunk_threshold = threshold;
    }
    let chunk_threshold_val = opts.minimal_trace_chunk_threshold;
    (opts, chunk_threshold_val)
}

fn collect_chunks_portable(
    program: Arc<Program>,
    stdin: SP1Stdin,
    chunk_threshold_val: u64,
) -> ChunksData {
    let max_trace_size = Some(chunk_threshold_val);
    let mut executor =
        PortableMinimalExecutor::<SupervisorMode>::new(program, false, max_trace_size);
    for buf in stdin.buffer {
        executor.with_input(&buf);
    }

    let exec_start = std::time::Instant::now();
    let mut chunks = Vec::new();
    let mut chunk_dirty_pages: Vec<Vec<u32>> = Vec::new();
    let mut chunk_dirty_pages_final: Vec<Vec<[u64; MERKLE_PAGE_WORDS]>> = Vec::new();

    while let Some(chunk) = executor.execute_chunk() {
        let mut pages_seen: HashSet<u32> = HashSet::new();
        let mut pages: Vec<u32> = Vec::new();
        for &addr in executor.chunk_touched_addrs().iter() {
            let pid = (addr / MERKLE_PAGE_BYTES) as u32;
            if pages_seen.insert(pid) {
                pages.push(pid);
            }
        }
        let pages_final: Vec<[u64; MERKLE_PAGE_WORDS]> = pages
            .iter()
            .map(|&pid| {
                let mut page = [0u64; MERKLE_PAGE_WORDS];
                let base = (pid as u64) * MERKLE_PAGE_BYTES;
                for (word, slot) in page.iter_mut().enumerate() {
                    *slot = executor.get_memory_value(base + (word as u64) * 8).value;
                }
                page
            })
            .collect();

        chunk_dirty_pages.push(pages);
        chunk_dirty_pages_final.push(pages_final);
        chunks.push(chunk);
    }
    let exec_time = exec_start.elapsed();
    let total_cycles = executor.global_clk();

    ChunksData {
        chunks,
        chunk_dirty_pages,
        chunk_dirty_pages_final,
        total_cycles,
        exec_time,
        backend_label: "Portable MinimalExecutor",
    }
}

// JIT-only: requires the native x86_64 minimal executor (`arch::x86_64`).
#[cfg(all(target_arch = "x86_64", target_os = "linux", not(feature = "mprotect")))]
fn collect_chunks_jit(
    program: Arc<Program>,
    stdin: SP1Stdin,
    chunk_threshold_val: u64,
) -> ChunksData {
    use sp1_core_executor::minimal::arch::x86_64::MinimalExecutor as JitMinimalExecutor;

    let max_trace_size = Some(chunk_threshold_val);
    let mut executor = JitMinimalExecutor::<SupervisorMode>::new(program, false, max_trace_size);
    for buf in stdin.buffer {
        executor.with_input(&buf);
    }

    let exec_start = std::time::Instant::now();
    let mut chunks: Vec<sp1_jit::TraceChunkRaw> = Vec::new();
    let mut chunk_dirty_pages: Vec<Vec<u32>> = Vec::new();
    let mut chunk_dirty_pages_final: Vec<Vec<[u64; MERKLE_PAGE_WORDS]>> = Vec::new();
    while let Some(chunk) = executor.execute_chunk() {
        let dirty = executor.emit_dirty_pages();
        let pages: Vec<u32> = dirty.pages.iter().map(|p| p.page_id).collect();
        let pages_final: Vec<[u64; MERKLE_PAGE_WORDS]> =
            dirty.pages.iter().map(|p| p.final_contents).collect();
        chunk_dirty_pages.push(pages);
        chunk_dirty_pages_final.push(pages_final);
        chunks.push(chunk);
    }
    let exec_time = exec_start.elapsed();
    let total_cycles = executor.global_clk();

    ChunksData {
        chunks,
        chunk_dirty_pages,
        chunk_dirty_pages_final,
        total_cycles,
        exec_time,
        backend_label: "Native MinimalExecutor",
    }
}

fn execute_minimal_splice(
    elf: Vec<u8>,
    stdin: SP1Stdin,
    chunk_threshold: Option<u64>,
    gpu_5090: bool,
    verify: bool,
) {
    let (opts, chunk_threshold_val) = build_opts(chunk_threshold, gpu_5090);
    let program = Arc::new(Program::from(&elf).expect("parse elf"));
    println!("chunk_threshold: {}", chunk_threshold_val);
    let cd = collect_chunks_portable(program.clone(), stdin, chunk_threshold_val);
    execute_minimal_splice_inner(program, opts, chunk_threshold_val, cd, verify, true);
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", not(feature = "mprotect")))]
fn execute_minimal_splice_jit(
    elf: Vec<u8>,
    stdin: SP1Stdin,
    chunk_threshold: Option<u64>,
    gpu_5090: bool,
    verify: bool,
) {
    let (opts, chunk_threshold_val) = build_opts(chunk_threshold, gpu_5090);
    let program = Arc::new(Program::from(&elf).expect("parse elf"));
    println!("chunk_threshold: {}", chunk_threshold_val);
    let cd = collect_chunks_jit(program.clone(), stdin, chunk_threshold_val);
    execute_minimal_splice_inner(program, opts, chunk_threshold_val, cd, verify, false);
}

fn execute_minimal_splice_inner(
    program: Arc<Program>,
    opts: SP1CoreOpts,
    chunk_threshold_val: u64,
    cd: ChunksData,
    verify: bool,
    do_chunk_byte_check: bool,
) {
    let ChunksData {
        chunks,
        chunk_dirty_pages,
        chunk_dirty_pages_final,
        total_cycles,
        exec_time,
        backend_label,
    } = cd;

    println!(
        "{}: {} chunks, {} cycles, {:.2?}, {:.2} mhz",
        backend_label,
        chunks.len(),
        total_cycles,
        exec_time,
        total_cycles as f64 / (exec_time.as_secs_f64() * 1e6)
    );

    // Now run SplicingVM on each chunk and collect stats.
    let mut total_shards: u64 = 0;
    let mut total_splicing_time = std::time::Duration::ZERO;
    let mut total_splicing_pure_time = std::time::Duration::ZERO;
    let mut chunk_serialized_sizes: Vec<usize> = Vec::new();
    let mut chunk_mem_reads: Vec<u64> = Vec::with_capacity(chunks.len());
    let mut chunk_touched_pages_256: Vec<usize> = Vec::with_capacity(chunks.len());
    let mut chunk_splice_ms: Vec<f64> = Vec::with_capacity(chunks.len());

    let chunk0_reference: Option<Vec<MemValue>> =
        if verify && do_chunk_byte_check && !chunks.is_empty() {
            use sp1_jit::MinimalTrace;
            let mut buf = Vec::with_capacity(chunks[0].num_mem_reads() as usize);
            for mv in chunks[0].mem_reads() {
                buf.push(mv);
            }
            Some(buf)
        } else {
            None
        };

    // Initialize the running memory state, used for verification.
    let mut running_state: std::collections::HashMap<u64, u64> =
        std::collections::HashMap::with_capacity(program.memory_image.len());
    for (&addr, &val) in program.memory_image.iter() {
        running_state.insert(addr, val);
    }

    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        println!("Starting {:?} chunk", chunk_idx);
        let mut touched_addresses = CompressedMemory::new();
        let mut touched_pages = CompressedPages::new();
        let mut vm: SplicingVM<'_, SupervisorMode> = SplicingVM::new(
            chunk,
            program.clone(),
            &mut touched_addresses,
            &mut touched_pages,
            [0u32; 4],
            opts.clone(),
        );

        // Set the dirty page information.
        vm.set_dirty_pages(&chunk_dirty_pages[chunk_idx], &chunk_dirty_pages_final[chunk_idx]);

        let chunk_mem_reads_count = chunk.num_mem_reads();
        let start_global_clk = vm.core.global_clk();
        let start_num_mem_reads = chunk.num_mem_reads();
        let mut last_splice = SplicedMinimalTrace::new_full_trace(chunk.clone());
        let mut shard_count: u64 = 0;
        let mut shards_collected: Vec<ShardData> = Vec::new();

        let mut chunk_spliced_bytes: u64 = 0;
        let mut chunk_shard_data_bytes: u64 = 0;
        let mut splices_to_send = Vec::new();

        // Serial `SplicingVM` speed, which doesn't include the time to serialize the results.
        let splice_pure_start = std::time::Instant::now();
        loop {
            let res = vm.execute().expect("SplicingVM execute failed");
            if let Some(d) = vm.take_pending_shard() {
                shards_collected.push(d);
            }
            match res {
                CycleResult::ShardBoundary => {
                    if let Some(spliced) = vm.splice(chunk.clone()) {
                        last_splice.set_last_clk(vm.core.clk());
                        last_splice.set_last_mem_reads_idx(
                            start_num_mem_reads as usize - vm.core.mem_reads.len(),
                        );
                        let splice_to_send = std::mem::replace(&mut last_splice, spliced);
                        splices_to_send.push(splice_to_send);
                        shard_count += 1;
                    } else {
                        // Trace ended at boundary.
                        last_splice.set_last_clk(vm.core.clk());
                        last_splice.set_last_mem_reads_idx(
                            start_num_mem_reads as usize - vm.core.mem_reads.len(),
                        );
                        splices_to_send.push(std::mem::replace(
                            &mut last_splice,
                            SplicedMinimalTrace::new_full_trace(chunk.clone()),
                        ));
                        shard_count += 1;
                        break;
                    }
                }
                CycleResult::Done(true) => {
                    last_splice.set_last_clk(vm.core.clk());
                    last_splice.set_last_mem_reads_idx(chunk.num_mem_reads() as usize);
                    splices_to_send.push(std::mem::replace(
                        &mut last_splice,
                        SplicedMinimalTrace::new_full_trace(chunk.clone()),
                    ));
                    shard_count += 1;
                    break;
                }
                CycleResult::Done(false) | CycleResult::TraceEnd => {
                    unreachable!("unexpected cycle result");
                }
            }
        }
        let splice_pure_elapsed = splice_pure_start.elapsed();

        // Serialize step, measured separately as `serialize_elapsed`.
        let serialize_start = std::time::Instant::now();
        for splice in &splices_to_send {
            let size = bincode::serialize(splice).expect("serialize failed").len();
            chunk_serialized_sizes.push(size);
            chunk_spliced_bytes += size as u64;
        }
        for shard_data in &shards_collected {
            let bytes = bincode::serialize(shard_data).expect("serialize failed");
            chunk_shard_data_bytes += bytes.len() as u64;
        }
        let merkle_payload_bytes = bincode::serialize(&vm.per_chunk.as_merkle_proving_payload())
            .expect("serialize MerkleProvingPayload failed");
        let chunk_merkle_payload_bytes = merkle_payload_bytes.len() as u64;
        let serialize_elapsed = serialize_start.elapsed();

        // Total `SplicingVM` related workload, including serialization time.
        let splice_elapsed = splice_pure_elapsed + serialize_elapsed;
        eprintln!(
            "BYTES chunk={} shards={} spliced={:.2}MB shard_data={:.2}MB merkle_payload={:.2}MB \
             shard_data_pct_of_spliced={:.1}% merkle_pct_of_spliced={:.1}%",
            chunk_idx,
            shard_count,
            chunk_spliced_bytes as f64 / (1024.0 * 1024.0),
            chunk_shard_data_bytes as f64 / (1024.0 * 1024.0),
            chunk_merkle_payload_bytes as f64 / (1024.0 * 1024.0),
            100.0 * chunk_shard_data_bytes as f64 / chunk_spliced_bytes.max(1) as f64,
            100.0 * chunk_merkle_payload_bytes as f64 / chunk_spliced_bytes.max(1) as f64,
        );
        let splice_cycles = vm.core.global_clk() - start_global_clk;
        let pages_tracked = vm.per_chunk.num_pages();

        // Check every dirty page has at least one `on_access` in the chunk.
        for page in vm.per_chunk.pages().iter() {
            assert!(page.last_clk.iter().any(|&c| c != 0));
        }

        // Verify that the first chunk's re-derived clk is identical with the portable executor.
        let per_chunk_state = if verify { Some(vm.take_per_chunk_state()) } else { None };
        drop(vm);

        if chunk_idx == 0 && do_chunk_byte_check {
            if let Some(reference) = chunk0_reference.as_ref() {
                use sp1_jit::MinimalTrace;
                let actual: Vec<MemValue> = chunk.mem_reads().collect();
                assert_eq!(actual, *reference);
                eprintln!(
                    "VERIFY chunk=0 mem_reads OK ({} entries matched portable's reference)",
                    actual.len()
                );
            }
        }

        // Check that the `initial_contents` agrees with the current `running_state`.
        if let Some(pcs) = per_chunk_state.as_ref() {
            let mut checked = 0usize;
            for pid in pcs.iter_page_ids() {
                let idx = pcs.page_idx_of_pub(pid).expect("page_id must be in lookup") as usize;
                let page_state = &pcs.pages()[idx];
                for word in 0..MERKLE_PAGE_WORDS {
                    let addr = (pid as u64) * MERKLE_PAGE_BYTES + (word as u64) * 8;
                    let expected = running_state.get(&addr).copied().unwrap_or(0);
                    let actual = page_state.initial_contents[word];
                    assert_eq!(actual, expected);
                    checked += 1;
                }
            }
            eprintln!(
                "VERIFY chunk={} initial_contents OK ({} words match running state)",
                chunk_idx, checked,
            );

            pcs.verify_shard_invariants(&shards_collected);

            eprintln!(
                "VERIFY chunk={} per-shard invariants OK ({} shards)",
                chunk_idx,
                shards_collected.len(),
            );

            // Update the running state.
            for (i, &pid) in chunk_dirty_pages[chunk_idx].iter().enumerate() {
                let page = &chunk_dirty_pages_final[chunk_idx][i];
                for (word, &val) in page.iter().enumerate() {
                    let addr = (pid as u64) * MERKLE_PAGE_BYTES + (word as u64) * 8;
                    running_state.insert(addr, val);
                }
            }
        }

        let touched_pages_256 = chunk_dirty_pages[chunk_idx].len();
        let splice_ms = splice_elapsed.as_secs_f64() * 1000.0;
        eprintln!(
            "SPLICE_CHUNK chunk={} shards={} cycles={} splice_ms={:.2} splice_mhz={:.2} \
             mem_reads={} touched_pages_256={} pages_tracked={}",
            chunk_idx,
            shard_count,
            splice_cycles,
            splice_ms,
            splice_cycles as f64 / (splice_elapsed.as_secs_f64() * 1e6),
            chunk_mem_reads_count,
            touched_pages_256,
            pages_tracked,
        );

        chunk_mem_reads.push(chunk_mem_reads_count);
        chunk_touched_pages_256.push(touched_pages_256);
        chunk_splice_ms.push(splice_ms);
        total_shards += shard_count;
        total_splicing_time += splice_elapsed;
        total_splicing_pure_time += splice_pure_elapsed;
    }

    // Print summary.
    let avg_size_mb = if chunk_serialized_sizes.is_empty() {
        0.0
    } else {
        chunk_serialized_sizes.iter().sum::<usize>() as f64
            / chunk_serialized_sizes.len() as f64
            / (1024.0 * 1024.0)
    };
    let avg_shards_per_chunk =
        if chunks.is_empty() { 0.0 } else { total_shards as f64 / chunks.len() as f64 };

    // Per-chunk aggregates.
    let (mem_reads_mean, mem_reads_min, mem_reads_max) = vec_stats_u64(&chunk_mem_reads);
    let (touched_pages_mean, touched_pages_min, touched_pages_max) =
        vec_stats_usize(&chunk_touched_pages_256);
    let (splice_ms_mean, splice_ms_min, splice_ms_max) = vec_stats_f64(&chunk_splice_ms);

    let exec_secs = exec_time.as_secs_f64();
    let splice_secs = total_splicing_time.as_secs_f64();
    let combined_secs = exec_secs + splice_secs;

    println!("=== SUMMARY ===");
    println!("backend: {}", backend_label);
    println!("chunk_threshold: {}", chunk_threshold_val);
    println!("total_cycles: {}", total_cycles);
    println!("total_chunks: {}", chunks.len());
    println!("total_shards: {}", total_shards);
    println!("avg_shards_per_chunk: {:.2}", avg_shards_per_chunk);
    println!("avg_spliced_chunk_size_mb: {:.2}", avg_size_mb);
    println!("executor_seconds: {:.3}", exec_secs);
    println!("splicing_seconds: {:.3}", splice_secs);
    println!("combined_serial_seconds: {:.3}", combined_secs);
    println!("splicing_mhz: {:.2}", total_cycles as f64 / (splice_secs * 1e6));
    let splice_pure_secs = total_splicing_pure_time.as_secs_f64();
    println!("splice_pure_seconds: {:.3}", splice_pure_secs);
    println!("splice_pure_mhz: {:.2}", total_cycles as f64 / (splice_pure_secs * 1e6));
    println!("executor_mhz: {:.2}", total_cycles as f64 / (exec_secs * 1e6));
    println!("combined_serial_mhz: {:.2}", total_cycles as f64 / (combined_secs * 1e6));
    println!(
        "mem_reads_per_chunk: mean={:.0} min={} max={}",
        mem_reads_mean, mem_reads_min, mem_reads_max
    );
    println!(
        "touched_pages_per_chunk: mean={:.0} min={} max={}",
        touched_pages_mean, touched_pages_min, touched_pages_max
    );
    println!(
        "splice_ms_per_chunk: mean={:.2} min={:.2} max={:.2}",
        splice_ms_mean, splice_ms_min, splice_ms_max
    );
}

fn vec_stats_u64(xs: &[u64]) -> (f64, u64, u64) {
    if xs.is_empty() {
        return (0.0, 0, 0);
    }
    let sum: u128 = xs.iter().map(|&x| x as u128).sum();
    let mean = sum as f64 / xs.len() as f64;
    (mean, *xs.iter().min().unwrap(), *xs.iter().max().unwrap())
}

fn vec_stats_usize(xs: &[usize]) -> (f64, usize, usize) {
    if xs.is_empty() {
        return (0.0, 0, 0);
    }
    let sum: u128 = xs.iter().map(|&x| x as u128).sum();
    let mean = sum as f64 / xs.len() as f64;
    (mean, *xs.iter().min().unwrap(), *xs.iter().max().unwrap())
}

fn vec_stats_f64(xs: &[f64]) -> (f64, f64, f64) {
    if xs.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let sum: f64 = xs.iter().sum();
    let mean = sum / xs.len() as f64;
    let min = xs.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    (mean, min, max)
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", not(feature = "mprotect")))]
fn read_page_from_raw_mem(raw: &[u8], page_id: u32) -> [u64; sp1_jit::MERKLE_PAGE_WORDS] {
    let mut out = [0u64; sp1_jit::MERKLE_PAGE_WORDS];
    let byte_offset = page_id as usize * sp1_jit::MERKLE_PAGE_WORDS * 8;
    let byte_len = sp1_jit::MERKLE_PAGE_WORDS * 8;
    let out_bytes =
        unsafe { std::slice::from_raw_parts_mut(out.as_mut_ptr().cast::<u8>(), byte_len) };
    out_bytes.copy_from_slice(&raw[byte_offset..byte_offset + byte_len]);
    out
}

// Executes the minimal executor and measures performance + verifies dirty-page correctness.
#[cfg(all(target_arch = "x86_64", target_os = "linux", not(feature = "mprotect")))]
fn execute_minimal_merkle(elf: Vec<u8>, stdin: SP1Stdin, chunk_threshold: Option<u64>) {
    use sp1_core_executor::minimal::arch::x86_64::MinimalExecutor;
    use std::collections::HashSet;

    let mut opts = SP1CoreOpts::default();
    if let Some(threshold) = chunk_threshold {
        opts.minimal_trace_chunk_threshold = threshold;
    }
    let chunk_threshold_val = opts.minimal_trace_chunk_threshold;
    let max_trace_size = Some(chunk_threshold_val);
    let program = Arc::new(Program::from(&elf).expect("parse elf"));

    println!("=== Minimal Executor Benchmark ===");
    println!("chunk_threshold: {chunk_threshold_val}");
    println!();

    let mut exec = MinimalExecutor::<SupervisorMode>::new(program.clone(), false, max_trace_size);
    for buf in stdin.buffer.clone() {
        exec.with_input(&buf);
    }

    let mut seen_pages: HashSet<u32> = HashSet::new();
    let mut chunk_count = 0usize;
    let mut total_dirty_pages = 0usize;

    let mut execute_time = std::time::Duration::ZERO;
    let mut emit_time = std::time::Duration::ZERO;
    let mut check_time = std::time::Duration::ZERO;

    let start = std::time::Instant::now();
    loop {
        let t0 = std::time::Instant::now();
        let is_chunk = exec.execute_chunk().is_some();
        execute_time += t0.elapsed();
        if !is_chunk {
            break;
        }
        chunk_count += 1;

        // Emit the dirty pages.
        let t1 = std::time::Instant::now();
        let dirty = exec.emit_dirty_pages();
        emit_time += t1.elapsed();
        total_dirty_pages += dirty.pages.len();

        // Check that the `final_contents` is equal to the final memory state.
        let t2 = std::time::Instant::now();
        let cur_mem: &[u8] = &exec.compiled().memory;
        for page in &dirty.pages {
            let expected_final = read_page_from_raw_mem(cur_mem, page.page_id);
            assert_eq!(page.final_contents, expected_final);
            seen_pages.insert(page.page_id);
        }
        check_time += t2.elapsed();
    }
    let elapsed = start.elapsed();
    let serial_production = execute_time + emit_time;
    let cycles = exec.global_clk();
    let mhz = cycles as f64 / (serial_production.as_secs_f64() * 1e6);
    let mhz_total = cycles as f64 / (elapsed.as_secs_f64() * 1e6);

    println!("  cycles:               {cycles}");
    println!("  chunks:               {chunk_count}");
    println!("  total (incl. check):  {elapsed:.2?}   ({mhz_total:.2} MHz)");
    println!("  serial (exec+emit):   {serial_production:.2?}   ({mhz:.2} MHz)");
    println!(
        "    execute: {execute_time:.2?}   emit: {emit_time:.2?}   check (bench-only): {check_time:.2?}"
    );
    println!("  dirty pages (total across chunks): {total_dirty_pages}");
    println!("  unique touched pages: {}", seen_pages.len());
    println!("  correctness (final_contents): OK");
    println!();
}

pub fn get_program_and_input(program: String, param: String, local: bool) -> (Vec<u8>, SP1Stdin) {
    // When local flag is set, read program and input in local environment.
    if local {
        let program = std::fs::read(&program).unwrap();
        let stdin = std::fs::read(&param).unwrap();
        let stdin: SP1Stdin = bincode::deserialize(&stdin).unwrap();

        return (program, stdin);
    }

    // Otherwise, assume it's a program from the s3 bucket.
    // Download files from S3
    let s3_path = program;
    let output = std::process::Command::new("aws")
        .args(["s3", "cp", &format!("s3://sp1-testing-suite/{s3_path}/program.bin"), "program.bin"])
        .output()
        .unwrap();
    if !output.status.success() {
        panic!("failed to download program.bin");
    }
    let output = if param.is_empty() {
        std::process::Command::new("aws")
            .args(["s3", "cp", &format!("s3://sp1-testing-suite/{s3_path}/stdin.bin"), "stdin.bin"])
            .output()
            .unwrap()
    } else {
        std::process::Command::new("aws")
            .args([
                "s3",
                "cp",
                &format!("s3://sp1-testing-suite/{s3_path}/input/{param}.bin"),
                "stdin.bin",
            ])
            .output()
            .unwrap()
    };
    if !output.status.success() {
        panic!("failed to download stdin.bin");
    }

    let program_path = "program.bin";
    let stdin_path = "stdin.bin";
    let program = std::fs::read(program_path).unwrap();
    let stdin = std::fs::read(stdin_path).unwrap();
    let stdin: SP1Stdin = bincode::deserialize(&stdin).unwrap();

    // remove the files
    std::fs::remove_file(program_path).unwrap();
    std::fs::remove_file(stdin_path).unwrap();

    (program, stdin)
}

#[tokio::main]
#[allow(clippy::field_reassign_with_default)]
async fn main() {
    let args = Args::parse();
    let args_clone = args.clone();

    // Initialize the logger.
    setup_logger();

    // Get the program and input.
    let (elf, stdin) = get_program_and_input(args.program, args.param, args.local);

    match args.mode.as_str() {
        "node" => execute_node(args_clone, elf, stdin).await,
        "gas" => execute_gas(elf, stdin).await,
        "minimal" => execute_minimal(elf, stdin, false),
        "minimal_trace" => execute_minimal(elf, stdin, true),
        "minimal_splice" => execute_minimal_splice(
            elf,
            stdin,
            args_clone.chunk_size,
            args_clone.gpu_5090,
            args_clone.verify,
        ),
        #[cfg(all(target_arch = "x86_64", target_os = "linux", not(feature = "mprotect")))]
        "minimal_splice_jit" => execute_minimal_splice_jit(
            elf,
            stdin,
            args_clone.chunk_size,
            args_clone.gpu_5090,
            args_clone.verify,
        ),
        #[cfg(all(target_arch = "x86_64", target_os = "linux", not(feature = "mprotect")))]
        "minimal_merkle" => execute_minimal_merkle(elf, stdin, args_clone.chunk_size),
        _ => panic!("invalid mode"),
    }
}
