use std::iter::once;

use p3_air::AirBuilder;
use sp1_stark::{
    air::{AirInteraction, BaseAirBuilder, InteractionScope},
    InteractionKind,
};

use crate::cpu::columns::{InstructionCols, OpcodeSelectorCols};

/// A trait which contains methods related to program interactions in an AIR.
pub trait ProgramAirBuilder: BaseAirBuilder {
    /// Sends an instruction.
    fn send_program(
        &mut self,
        pc: impl Into<Self::Expr>,
        instruction: InstructionCols<impl Into<Self::Expr> + Copy>,
        selectors: OpcodeSelectorCols<impl Into<Self::Expr> + Copy>,
        shard: impl Into<Self::Expr> + Copy,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(pc.into())
            .chain(once(instruction.opcode.into()))
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(selectors.into_iter().map(|x| x.into()))
            .chain(once(shard.into()))
            .collect();

        self.send(
            AirInteraction::new(values, multiplicity.into(), InteractionKind::Program),
            InteractionScope::Local,
        );
    }

    /// Receives an instruction.
    fn receive_program(
        &mut self,
        pc: impl Into<Self::Expr>,
        instruction: InstructionCols<impl Into<Self::Expr> + Copy>,
        selectors: OpcodeSelectorCols<impl Into<Self::Expr> + Copy>,
        shard: impl Into<Self::Expr> + Copy,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values: Vec<<Self as AirBuilder>::Expr> = once(pc.into())
            .chain(once(instruction.opcode.into()))
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(selectors.into_iter().map(|x| x.into()))
            .chain(once(shard.into()))
            .collect();

        self.receive(
            AirInteraction::new(values, multiplicity.into(), InteractionKind::Program),
            InteractionScope::Local,
        );
    }
}
