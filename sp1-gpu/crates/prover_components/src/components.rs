use std::{collections::BTreeMap, sync::Arc};

use sp1_gpu_air::ir::DagBuilder;
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
use sp1_gpu_tracegen::CudaTracegenAir;
use sp1_hypercube::{air::MachineAir, prover::ZerocheckAir, SP1InnerPcs, SP1OuterPcs, SP1SC};
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

pub async fn new_cuda_prover<GC, PC>(
    verifier: &sp1_hypercube::MachineVerifier<GC, SP1SC<GC, PC::Air>>,
    max_trace_size: usize,
    num_workers: usize,
    recompute_first_layer: bool,
    scope: TaskScope,
) -> CudaShardProver<GC, PC>
where
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField>,
    PC: CudaShardProverComponents<GC>,
    PC::P: CudaTcsProver<GC>,
    PC::Air: CudaTracegenAir<GC::F>
        + for<'a> slop_air::Air<DagBuilder<'a>>
        + ZerocheckAir<GC::F, GC::EF>
        + std::fmt::Debug,
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

    // H1 (host-memory-workstream Phase 2): when the device-tracegen path covers the
    // trace mass (some chip generates its main trace AND its dependencies on device),
    // per-shard host-resident bytes are measured in MB, not GB — so don't pre-allocate
    // `num_workers × max_trace_size` of page-locked memory. A static sound bound can't
    // capture this (the not-yet-ported precompile tail keeps the worst case at
    // `max_trace_size`), so the pool starts small and every shard checkout ratchets its
    // worker's buffer up to that shard's exact requirement
    // (`sp1_gpu_jagged_tracegen::required_trace_buffer_elems`, derived from the same
    // `supports_device_*` predicates as the tracegen partition). With the device path
    // off — the `AR_DEVICE_CHIPS` default, and always for recursion/wrap machines —
    // allocate the full `max_trace_size` up front, exactly today's behavior; a shard's
    // requirement never exceeds it, so growth never triggers.
    let device_path_on = machine
        .chips()
        .iter()
        .any(|c| c.air.supports_device_main_tracegen() && c.air.supports_device_dependencies());
    // Covers the measured device-on steady state for ALU-class workloads (written
    // prefix of 4–5 MB per shard) without a first-shard grow; precompile-heavy shards
    // ratchet up from here.
    const DEVICE_ON_INITIAL_BUFFER_SIZE: usize = 1 << 22;
    let buffer_size = if device_path_on {
        DEVICE_ON_INITIAL_BUFFER_SIZE.min(max_trace_size)
    } else {
        max_trace_size
    };
    let mut trace_buffers = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let pinned_buffer = PinnedBuffer::<GC::F>::with_capacity(buffer_size);
        trace_buffers.push(pinned_buffer);
    }

    let trace_buffers = Arc::new(WorkerQueue::new(trace_buffers));
    CudaShardProver::<GC, PC>::new(
        trace_buffers,
        max_log_row_count as u32,
        basefold_prover,
        machine,
        max_trace_size,
        scope,
        all_interactions,
        recompute_first_layer,
        recompute_first_layer,
    )
}
