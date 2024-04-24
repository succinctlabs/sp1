use crate::cpu::InstructionCols;
use crate::memory::{MemoryAccessTimestampCols, MemoryCols};
use core::iter::{once, repeat};
use p3_air::AirBuilderWithPublicValues;
use p3_field::AbstractField;
use sp1_core::{
    air::{AirInteraction, BaseAirBuilder, MachineAirBuilder},
    lookup::InteractionKind,
};

use super::Block;
/// A trait which contains all helper methods for building SP1 recursion machine AIRs.
pub trait SP1RecursionAirBuilder: MachineAirBuilder + RecursionMemoryAirBuilder {}

impl<AB: AirBuilderWithPublicValues + RecursionMemoryAirBuilder> SP1RecursionAirBuilder for AB {}
impl<AB: BaseAirBuilder + AirBuilderWithPublicValues> RecursionMemoryAirBuilder for AB {}

pub trait RecursionMemoryAirBuilder: BaseAirBuilder {
    fn recursion_eval_memory_access<E: Into<Self::Expr> + Clone>(
        &mut self,
        timestamp: impl Into<Self::Expr>,
        addr: impl Into<Self::Expr>,
        memory_access: &impl MemoryCols<E, Block<E>>,
        is_real: impl Into<Self::Expr>,
    ) {
        let is_real: Self::Expr = is_real.into();
        let timestamp: Self::Expr = timestamp.into();
        let mem_access = memory_access.access();

        self.eval_memory_access_timestamp(timestamp.clone(), mem_access, is_real.clone());

        let addr = addr.into();
        let prev_timestamp = mem_access.prev_timestamp.clone().into();
        let prev_values = once(prev_timestamp)
            .chain(once(addr.clone()))
            .chain(memory_access.prev_value().clone().map(Into::into))
            .collect();
        let current_values = once(timestamp)
            .chain(once(addr.clone()))
            .chain(memory_access.value().clone().map(Into::into))
            .collect();

        self.receive(AirInteraction::new(
            prev_values,
            is_real.clone(),
            InteractionKind::Memory,
        ));
        self.send(AirInteraction::new(
            current_values,
            is_real,
            InteractionKind::Memory,
        ));
    }

    fn recursion_eval_memory_access_single<E: Into<Self::Expr> + Clone>(
        &mut self,
        timestamp: impl Into<Self::Expr>,
        addr: impl Into<Self::Expr>,
        memory_access: &impl MemoryCols<E, E>,
        is_real: impl Into<Self::Expr>,
    ) {
        let is_real: Self::Expr = is_real.into();
        let timestamp: Self::Expr = timestamp.into();
        let mem_access = memory_access.access();

        self.eval_memory_access_timestamp(timestamp.clone(), mem_access, is_real.clone());

        let addr = addr.into();
        let prev_timestamp = mem_access.prev_timestamp.clone().into();
        let prev_values = once(prev_timestamp)
            .chain(once(addr.clone()))
            .chain(once(memory_access.prev_value().clone().into()))
            .chain(repeat(Self::Expr::zero()).take(3))
            .collect();
        let current_values = once(timestamp)
            .chain(once(addr.clone()))
            .chain(once(memory_access.value().clone().into()))
            .chain(repeat(Self::Expr::zero()).take(3))
            .collect();

        self.receive(AirInteraction::new(
            prev_values,
            is_real.clone(),
            InteractionKind::Memory,
        ));
        self.send(AirInteraction::new(
            current_values,
            is_real,
            InteractionKind::Memory,
        ));
    }

    fn eval_memory_access_timestamp<E: Into<Self::Expr>>(
        &mut self,
        _timestamp: impl Into<Self::Expr>,
        _mem_access: &impl MemoryAccessTimestampCols<E>,
        _is_real: impl Into<Self::Expr>,
    ) {
        // TODO: check that mem_access.prev_clk < clk if is_real.
    }

    fn send_program<E: Into<Self::Expr>>(
        &mut self,
        instruction: InstructionCols<E>,
        is_real: impl Into<Self::Expr>,
    ) {
        let program_interaction_vals = instruction
            .into_iter()
            .map(|x| x.into())
            .collect::<Vec<_>>();
        // self.send(AirInteraction::new(
        //     program_interaction_vals,
        //     is_real.into(),
        //     InteractionKind::Program,
        // ));
    }

    // TODO: include opcode columns
    fn receive_program<E: Into<Self::Expr>>(
        &mut self,
        instruction: InstructionCols<E>,
        is_real: impl Into<Self::Expr>,
    ) {
        let program_interaction_vals = instruction
            .into_iter()
            .map(|x| x.into())
            .collect::<Vec<_>>();
        // self.receive(AirInteraction::new(
        //     program_interaction_vals,
        //     is_real.into(),
        //     InteractionKind::Program,
        // ));
    }
}
