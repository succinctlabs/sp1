use slop_alloc::CpuBackend;
use slop_challenger::IopCtx;
use slop_merkle_tree::{ComputeTcsOpenings, TensorCsProver};

/// Auto-implemented trait that bundles the merkle commitment bounds needed by prover code.
///
/// Any type implementing `TensorCsProver + ComputeTcsOpenings + Default` automatically
/// satisfies this trait. Pass it as a separate generic `MK: ZkMerkleizer<GC>` on
/// prover-side structs and functions instead of baking it into `ZkIopCtx`.
pub trait ZkMerkleizer<GC: IopCtx>:
    TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend> + Default
{
}

impl<MK, GC: IopCtx> ZkMerkleizer<GC> for MK where
    MK: TensorCsProver<GC, CpuBackend> + ComputeTcsOpenings<GC, CpuBackend> + Default
{
}

/// Type alias for the prover data produced by a `ZkMerkleizer`.
pub type MerkleProverData<GC, MK> = <MK as TensorCsProver<GC, CpuBackend>>::ProverData;
