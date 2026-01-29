use std::{collections::BTreeSet, sync::Arc};

use slop_challenger::IopCtx;
use sp1_gpu_utils::{Ext, Felt};
use sp1_hypercube::{
    prover::{AirProver, ProverPermit, ProvingKey},
    Chip, ShardContext, ShardContextImpl,
};

use crate::CudaShardProverComponents;

/// A collection of main traces with a permit.
#[allow(clippy::type_complexity)]
pub struct ShardData<GC: IopCtx<F = Felt, EF = Ext>, PC: CudaShardProverComponents<GC>>
where
    crate::CudaShardProver<GC, PC>: AirProver<GC, ShardContextImpl<GC, PC::C, PC::Air>>,
{
    /// Main trace data
    pub main_trace_data:
        MainTraceData<GC, ShardContextImpl<GC, PC::C, PC::Air>, crate::CudaShardProver<GC, PC>>,
}

pub struct MainTraceData<
    GC: IopCtx<F = Felt, EF = Ext>,
    SC: ShardContext<GC>,
    Prover: AirProver<GC, SC>,
> {
    /// The traces.
    pub traces: Arc<ProvingKey<GC, SC, Prover>>,
    /// The public values.
    pub public_values: Vec<GC::F>,
    /// The shape cluster corresponding to the traces.
    pub shard_chips: BTreeSet<Chip<GC::F, SC::Air>>,
    /// A permit for a prover resource.
    pub permit: ProverPermit,
}
