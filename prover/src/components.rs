use sp1_core::stark::{DefaultProver, MachineProver, RiscvAir, StarkGenericConfig};

use crate::{CompressAir, CoreSC, InnerSC, OuterSC, ReduceAir, WrapAir};

pub trait SP1ProverComponents: Send + Sync {
    /// The prover for making SP1 core proofs.
    type CoreProver: MachineProver<CoreSC, RiscvAir<<CoreSC as StarkGenericConfig>::Val>>
        + Send
        + Sync;

    /// The prover for making SP1 recursive proofs.
    type CompressProver: MachineProver<InnerSC, ReduceAir<<InnerSC as StarkGenericConfig>::Val>>
        + Send
        + Sync;

    /// The prover for shrinking compressed proofs.
    type ShrinkProver: MachineProver<InnerSC, CompressAir<<InnerSC as StarkGenericConfig>::Val>>
        + Send
        + Sync;

    /// The prover for wrapping compressed proofs into SNARK-friendly field elements.
    type WrapProver: MachineProver<OuterSC, WrapAir<<OuterSC as StarkGenericConfig>::Val>>
        + Send
        + Sync;
}

pub struct DefaultProverComponents;

impl SP1ProverComponents for DefaultProverComponents {
    type CoreProver = DefaultProver<CoreSC, RiscvAir<<CoreSC as StarkGenericConfig>::Val>>;
    type CompressProver = DefaultProver<InnerSC, ReduceAir<<InnerSC as StarkGenericConfig>::Val>>;
    type ShrinkProver = DefaultProver<InnerSC, CompressAir<<InnerSC as StarkGenericConfig>::Val>>;
    type WrapProver = DefaultProver<OuterSC, WrapAir<<OuterSC as StarkGenericConfig>::Val>>;
}
