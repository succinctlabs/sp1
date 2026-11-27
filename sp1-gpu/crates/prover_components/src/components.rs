use std::{collections::BTreeMap, sync::Arc};

use sp1_gpu_challenger::{DuplexChallenger, MultiField32Challenger};
use sp1_gpu_cudart::{PinnedBuffer, TaskScope};

use slop_basefold::BasefoldVerifier;
use slop_bn254::Bn254Fr;
use slop_challenger::IopCtx;
use slop_futures::queue::WorkerQueue;
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_basefold::FriCudaProver;
use sp1_gpu_merkle_tree::{CudaTcsProver, Poseidon2Bn254CudaProver, Poseidon2SP1Field16CudaProver};
use sp1_gpu_shard_prover::{CudaShardProver, CudaShardProverComponents};
use sp1_hypercube::{air::MachineAir, SP1InnerPcs, SP1OuterPcs, SP1SC};
use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext, SP1OuterGlobalContext};
use sp1_prover::{CompressAir, ReadyWrapProverBuilder, SP1ProverComponents, WrapAir};

pub struct SP1CudaProverComponents;

impl SP1ProverComponents for SP1CudaProverComponents {
    type CoreProver = CudaShardProver<SP1GlobalContext, CudaProverCoreComponents>;
    type RecursionProver = CudaShardProver<SP1GlobalContext, CudaProverRecursionComponents>;
    type WrapProver = CudaShardProver<SP1OuterGlobalContext, CudaProverWrapComponents>;
    type WrapProverBuilder = ReadyWrapProverBuilder<Self>;
}

/// Core prover components for the CUDA prover.
pub struct CudaProverCoreComponents;

impl CudaShardProverComponents<SP1GlobalContext> for CudaProverCoreComponents {
    type P = Poseidon2SP1Field16CudaProver;
    type Air = RiscvAir<SP1Field>;
    type C = SP1InnerPcs;
    type DeviceChallenger = DuplexChallenger<SP1Field, TaskScope>;
}

/// Recursion prover components for the CUDA prover.
pub struct CudaProverRecursionComponents;

impl CudaShardProverComponents<SP1GlobalContext> for CudaProverRecursionComponents {
    type P = Poseidon2SP1Field16CudaProver;
    type Air = CompressAir<<SP1GlobalContext as IopCtx>::F>;
    type C = SP1InnerPcs;
    type DeviceChallenger = DuplexChallenger<SP1Field, TaskScope>;
}

/// Wrap prover components for the CUDA prover.
pub struct CudaProverWrapComponents;

impl CudaShardProverComponents<SP1OuterGlobalContext> for CudaProverWrapComponents {
    type P = Poseidon2Bn254CudaProver;
    type Air = WrapAir<<SP1OuterGlobalContext as IopCtx>::F>;
    type C = SP1OuterPcs;
    type DeviceChallenger = MultiField32Challenger<SP1Field, Bn254Fr, TaskScope>;
}

pub(crate) type TraceBuffers = Arc<WorkerQueue<PinnedBuffer<SP1Field>>>;

pub(crate) fn trace_buffers(capacity: usize, workers: usize) -> TraceBuffers {
    Arc::new(WorkerQueue::new(
        (0..workers).map(|_| PinnedBuffer::with_capacity(capacity)).collect(),
    ))
}

pub async fn new_cuda_prover<GC, PC>(
    verifier: &sp1_hypercube::MachineVerifier<GC, SP1SC<GC, PC::Air>>,
    max_trace_size: usize,
    num_workers: usize,
    recompute_first_layer: bool,
    drop_ldes: bool,
    scope: TaskScope,
) -> CudaShardProver<GC, PC>
where
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField>,
    PC: CudaShardProverComponents<GC>,
    PC::P: CudaTcsProver<GC>,
    PC::Air: std::fmt::Debug,
{
    new_cuda_prover_with_buffers(
        verifier,
        max_trace_size,
        trace_buffers(max_trace_size, num_workers),
        recompute_first_layer,
        drop_ldes,
        scope,
    )
}

pub(crate) fn new_cuda_prover_with_buffers<GC, PC>(
    verifier: &sp1_hypercube::MachineVerifier<GC, SP1SC<GC, PC::Air>>,
    max_trace_size: usize,
    trace_buffers: TraceBuffers,
    recompute_first_layer: bool,
    drop_ldes: bool,
    scope: TaskScope,
) -> CudaShardProver<GC, PC>
where
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField>,
    PC: CudaShardProverComponents<GC>,
    PC::P: CudaTcsProver<GC>,
    PC::Air: std::fmt::Debug,
{
    let machine = verifier.machine().clone();

    let log_stacking_height = verifier.log_stacking_height();
    let max_log_row_count = verifier.max_log_row_count();

    // Create the basefold prover from the verifier's PCS config
    let basefold_verifier = BasefoldVerifier::<GC>::new(*verifier.fri_config(), 2);

    let tcs_prover = PC::P::new(&scope);
    let basefold_prover = FriCudaProver::<GC, PC::P, GC::F>::new(
        tcs_prover,
        basefold_verifier.fri_config,
        log_stacking_height,
    );

    let mut all_interactions = BTreeMap::new();

    for chip in machine.chips().iter() {
        let host_interactions = sp1_gpu_logup_gkr::Interactions::new(chip.sends(), chip.receives());
        let device_interactions = host_interactions.copy_to_device(&scope).unwrap();
        all_interactions.insert(chip.name().to_string(), Arc::new(device_interactions));
    }

    CudaShardProver::<GC, PC>::new(
        trace_buffers,
        max_log_row_count as u32,
        basefold_prover,
        machine,
        max_trace_size,
        scope,
        all_interactions,
        recompute_first_layer,
        drop_ldes,
    )
}
