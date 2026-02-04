use std::sync::Arc;

use sp1_gpu_cudart::{cuda_memory_info, TaskScope};

use sp1_core_executor::{SP1CoreOpts, ELEMENT_THRESHOLD};
use sp1_hypercube::prover::ProverSemaphore;
use sp1_prover::{worker::SP1WorkerBuilder, SP1ProverComponents, CORE_LOG_STACKING_HEIGHT};

pub const RECURSION_TRACE_ALLOCATION: usize = 1 << 27;
pub const SHRINK_TRACE_ALLOCATION: usize = 1 << 25;

/// Taken from "Total number of Cells" when generating traces for wrap. Plus an extra 5%.
pub const WRAP_TRACE_ALLOCATION: usize = 85_376_340;

use crate::{new_cuda_prover, SP1CudaProverComponents};

pub fn local_gpu_opts() -> (SP1CoreOpts, bool) {
    let mut opts = SP1CoreOpts::default();

    let log2_shard_size = 24;
    opts.shard_size = 1 << log2_shard_size;

    let gb = 1024.0 * 1024.0 * 1024.0;

    // Get the amount of memory on the GPU.
    let gpu_memory_gb: usize = (((cuda_memory_info().unwrap().1 as f64) / gb).ceil() as usize) + 4;

    if gpu_memory_gb < 24 {
        panic!("Unsupported GPU memory: {gpu_memory_gb}, must be at least 24GB");
    }

    let shard_threshold = if gpu_memory_gb <= 30 {
        ELEMENT_THRESHOLD - (1 << 26) - (1 << 25)
    } else {
        ELEMENT_THRESHOLD
    };

    tracing::debug!("Shard threshold: {shard_threshold}");
    opts.sharding_threshold.element_threshold = shard_threshold;

    opts.global_dependencies_opt = true;

    (opts, gpu_memory_gb <= 30)
}

/// Create a [SP1CudaProverWorkerBuilder]
pub async fn cuda_worker_builder(scope: TaskScope) -> SP1WorkerBuilder<SP1CudaProverComponents> {
    // Create a prover permits, assuming a single proof happens at a time.
    let prover_permits = ProverSemaphore::new(1);

    // Get the core options.
    let (opts, recompute_first_layer) = local_gpu_opts();

    let num_elts =
        opts.sharding_threshold.element_threshold as usize + (1 << CORE_LOG_STACKING_HEIGHT);

    let core_verifier = SP1CudaProverComponents::core_verifier();
    let core_prover = Arc::new(
        new_cuda_prover(core_verifier.clone(), num_elts, 4, recompute_first_layer, scope.clone())
            .await,
    );

    // TODO: tune this more precisely and make it a constant.
    let recursion_verifier = SP1CudaProverComponents::compress_verifier();
    let recursion_prover = Arc::new(
        new_cuda_prover(
            recursion_verifier.clone(),
            RECURSION_TRACE_ALLOCATION,
            4,
            false,
            scope.clone(),
        )
        .await,
    );

    let shrink_verifier = SP1CudaProverComponents::shrink_verifier();
    let shrink_prover = Arc::new(
        new_cuda_prover(shrink_verifier.clone(), SHRINK_TRACE_ALLOCATION, 1, false, scope.clone())
            .await,
    );

    let wrap_verifier = SP1CudaProverComponents::wrap_verifier();
    let wrap_prover = Arc::new(
        new_cuda_prover(wrap_verifier.clone(), WRAP_TRACE_ALLOCATION, 1, false, scope.clone())
            .await,
    );

    SP1WorkerBuilder::new()
        .with_core_opts(opts)
        .with_core_air_prover(core_prover, prover_permits.clone())
        .with_compress_air_prover(recursion_prover, prover_permits.clone())
        .with_shrink_air_prover(shrink_prover, prover_permits.clone())
        .with_wrap_air_prover(wrap_prover, prover_permits)
}
