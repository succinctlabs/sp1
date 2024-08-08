use sp1_core::stark::{CpuProver, MachineProver, RiscvAir, StarkGenericConfig};

use crate::{CompressAir, CoreSC, InnerSC, OuterSC, ShrinkAir, WrapAir};

pub trait SP1ProverComponents: Send + Sync {
    /// The prover for making SP1 core proofs.
    type CoreProver: MachineProver<CoreSC, RiscvAir<<CoreSC as StarkGenericConfig>::Val>>
        + Send
        + Sync;

    /// The prover for making SP1 recursive proofs.
    type CompressProver: MachineProver<InnerSC, CompressAir<<InnerSC as StarkGenericConfig>::Val>>
        + Send
        + Sync;

    /// The prover for shrinking compressed proofs.
    type ShrinkProver: MachineProver<InnerSC, ShrinkAir<<InnerSC as StarkGenericConfig>::Val>>
        + Send
        + Sync;

    /// The prover for wrapping compressed proofs into SNARK-friendly field elements.
    type WrapProver: MachineProver<OuterSC, WrapAir<<OuterSC as StarkGenericConfig>::Val>>
        + Send
        + Sync;
}

pub struct DefaultProverComponents;

impl SP1ProverComponents for DefaultProverComponents {
    type CoreProver = CpuProver<CoreSC, RiscvAir<<CoreSC as StarkGenericConfig>::Val>>;
    type CompressProver = CpuProver<InnerSC, CompressAir<<InnerSC as StarkGenericConfig>::Val>>;
    type ShrinkProver = CpuProver<InnerSC, ShrinkAir<<InnerSC as StarkGenericConfig>::Val>>;
    type WrapProver = CpuProver<OuterSC, WrapAir<<OuterSC as StarkGenericConfig>::Val>>;
}
