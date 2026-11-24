use std::sync::Arc;

use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_cudart::{cuda_memory_info, cuda_pool_available_memory, TaskScope};

use sp1_core_executor::{SP1CoreOpts, ELEMENT_THRESHOLD, HEIGHT_THRESHOLD};
use sp1_gpu_shard_prover::CudaShardProver;
use sp1_hypercube::{prover::ProverSemaphore, InnerSC, Machine, MachineVerifier};
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_prover::{
    worker::SP1WorkerBuilder, CompressAir, ReadyWrapProverBuilder, SP1ProverComponents,
    CORE_LOG_STACKING_HEIGHT,
};

pub const RECURSION_TRACE_ALLOCATION: usize = 1 << 27;
pub const SHRINK_TRACE_ALLOCATION: usize = 1 << 25;

/// Taken from "Total number of Cells" when generating traces for wrap. Plus an extra 5%.
pub const WRAP_TRACE_ALLOCATION: usize = 85_376_340;

use crate::{
    components::{new_cuda_prover_with_buffers, trace_buffers},
    new_cuda_prover, CudaProverCoreComponents, CudaProverRecursionComponents,
    SP1CudaProverComponents,
};

pub fn local_gpu_opts() -> SP1CoreOpts {
    let mut opts = SP1CoreOpts::default();

    let log2_shard_size = 24;
    opts.shard_size = 1 << log2_shard_size;

    let gb = 1024.0 * 1024.0 * 1024.0;

    // Get the amount of memory on the GPU.
    let gpu_memory_gb: usize = (((cuda_memory_info().unwrap().1 as f64) / gb).ceil() as usize) + 4;

    if gpu_memory_gb < 24 {
        panic!("Unsupported GPU memory: {gpu_memory_gb}, must be at least 24GB");
    }

    let shard_threshold = if !opts.full_size_shards && gpu_memory_gb <= 30 {
        ELEMENT_THRESHOLD - (1 << 26) - (1 << 25) - (1 << 24)
    } else {
        ELEMENT_THRESHOLD
    };

    tracing::debug!("Shard threshold: {shard_threshold}");
    opts.sharding_threshold.element_threshold = shard_threshold;

    opts.global_dependencies_opt = true;
    opts.recompute_gkr_trace = false;
    opts.drop_ldes = opts.full_size_shards && gpu_memory_gb <= 30;

    opts
}

/// Create a [SP1CudaProverWorkerBuilder] with a default machine.
pub async fn cuda_worker_builder(scope: TaskScope) -> SP1WorkerBuilder<SP1CudaProverComponents> {
    cuda_worker_builder_with_machine(scope, RiscvAir::machine()).await
}

fn core_trace_allocation(opts: &SP1CoreOpts) -> usize {
    opts.sharding_threshold.element_threshold as usize + (1 << CORE_LOG_STACKING_HEIGHT)
}

pub async fn core_prover_and_verifier(
    scope: TaskScope,
    machine: Machine<SP1Field, RiscvAir<SP1Field>>,
) -> (
    CudaShardProver<SP1GlobalContext, CudaProverCoreComponents>,
    MachineVerifier<SP1GlobalContext, InnerSC<RiscvAir<SP1Field>>>,
) {
    let opts = local_gpu_opts();
    let core_verifier = SP1CudaProverComponents::core_verifier(machine);
    (
        new_cuda_prover(
            &core_verifier,
            core_trace_allocation(&opts),
            4,
            opts.recompute_gkr_trace,
            opts.drop_ldes,
            scope,
        )
        .await,
        core_verifier,
    )
}

pub async fn recursion_prover_and_verifier(
    scope: TaskScope,
) -> (
    CudaShardProver<SP1GlobalContext, CudaProverRecursionComponents>,
    MachineVerifier<SP1GlobalContext, InnerSC<CompressAir<SP1Field>>>,
) {
    let recursion_verifier = SP1CudaProverComponents::compress_verifier();
    (
        new_cuda_prover(&recursion_verifier, RECURSION_TRACE_ALLOCATION, 4, false, false, scope)
            .await,
        recursion_verifier,
    )
}

/// Same as [`cuda_worker_builder`] but with a custom machine.
pub async fn cuda_worker_builder_with_machine(
    scope: TaskScope,
    machine: Machine<SP1Field, RiscvAir<SP1Field>>,
) -> SP1WorkerBuilder<SP1CudaProverComponents> {
    let free_bytes = cuda_memory_info().unwrap().0;
    const MAX_WORKERS: usize = 4;
    // Separate admission granularity from the maximum number of staging jobs.
    const DEVICE_PERMITS: u32 = 24;
    let workers = if free_bytes >= 16usize << 30 { MAX_WORKERS } else { 2 };
    let prover_permits = if workers == MAX_WORKERS {
        // Gnark keeps its key in separate device allocations across proof requests.
        // Recheck the space left for the STARK pool when each shard is admitted.
        ProverSemaphore::with_trace_budget(DEVICE_PERMITS, || {
            cuda_pool_available_memory().map_or(0, |available| {
                // Cached recursion keys also live inside the pool. Count only
                // its reusable pages and the memory still free on the device.
                let bytes_per_cell = if available >= 13usize << 30 { 12 } else { 20 };
                tracing::debug!(available, bytes_per_cell, "independent trace workspace");
                available / bytes_per_cell / DEVICE_PERMITS as usize
            })
        })
    } else {
        ProverSemaphore::new(1)
    };

    // Get the core options.
    let opts = local_gpu_opts();

    // Bound the number of host trace jobs in flight. Each host AIR allocates its actual trace.
    let core_allocation = core_trace_allocation(&opts);
    let buffers = trace_buffers(0, workers);
    let core_verifier = SP1CudaProverComponents::core_verifier(machine.clone());
    let core_prover = Arc::new(new_cuda_prover_with_buffers(
        &core_verifier,
        core_allocation,
        buffers.clone(),
        opts.recompute_gkr_trace,
        opts.drop_ldes,
        scope.clone(),
    ));
    let recursion_prover = Arc::new(new_cuda_prover_with_buffers(
        &SP1CudaProverComponents::compress_verifier(),
        RECURSION_TRACE_ALLOCATION,
        buffers.clone(),
        false,
        false,
        scope.clone(),
    ));

    let shrink_verifier = SP1CudaProverComponents::shrink_verifier();
    let shrink_prover = Arc::new(new_cuda_prover_with_buffers(
        &shrink_verifier,
        SHRINK_TRACE_ALLOCATION,
        buffers.clone(),
        false,
        false,
        scope.clone(),
    ));

    let wrap_verifier = SP1CudaProverComponents::wrap_verifier();
    let wrap_prover = Arc::new(new_cuda_prover_with_buffers(
        &wrap_verifier,
        WRAP_TRACE_ALLOCATION,
        buffers,
        false,
        false,
        scope,
    ));

    let base_builder = SP1WorkerBuilder::new_with_machine(machine)
        .with_core_opts(opts)
        .with_config(|config| {
            if std::env::var_os("SP1_WORKER_NUM_CORE_WORKERS").is_none() {
                // Large execution records coexist with the SNARK key during trace generation.
                // Smaller shards can keep more CPU workers busy within the same row budget.
                let height = config.controller_config.opts.sharding_threshold.height_threshold;
                let max_workers = if workers == MAX_WORKERS { 5 } else { 2 };
                config.prover_config.core_prover_config.num_core_workers =
                    (3 * HEIGHT_THRESHOLD / height.max(1)).clamp(2, max_workers) as usize;
            }
        })
        .with_core_air_prover(core_prover, prover_permits.clone())
        .with_compress_air_prover(recursion_prover, prover_permits.clone())
        .with_shrink_air_prover(shrink_prover, prover_permits.clone())
        .with_wrap_air_prover(ReadyWrapProverBuilder::new(wrap_prover), prover_permits);

    #[cfg(feature = "experimental")]
    {
        if cfg!(feature = "mprotect") {
            return base_builder.without_vk_verification();
        }
        if let Ok(setting) = std::env::var("WITHOUT_VK_VERIFICATION") {
            if setting == "1" || setting == "true" {
                return base_builder.without_vk_verification();
            }
        }
    }
    base_builder
}
