use ff::derive::bitvec::mem;
use sp1_core::{
    air::{AirInteraction, BaseAirBuilder, SP1AirBuilder},
    cpu::air::memory,
    lookup::InteractionKind,
    memory::MemoryAccessCols,
};

use super::Block;

impl<AB: SP1AirBuilder> RecursionAirBuilder for AB {}

pub trait RecursionAirBuilder: BaseAirBuilder {
    fn eval_memory_access_timestamp(
        &mut self,
        mem_access: &MemoryAccessCols<impl Into<Self::Expr>>,
        clk: impl Into<Self::Expr>,
        is_real: impl Into<Self::Expr>,
    ) {
        // TODO: check that mem_access.prev_clk < clk if is_real.
    }

    /// This implementation is almost 1-1 with the implementation in core/src/air/builder.rs::eval_memory_access
    /// except that it uses the crate's MemoryAccessCols instead of the one from sp1_core.
    /// In particular, it excludes shard.
    fn eval_memory_access(
        &mut self,
        clk: impl Into<Self::Expr>,
        addr: impl Into<Self::Expr>,
        memory_access: &MemoryAccessCols<impl Into<Self::Expr>>,
        is_real: impl Into<Self::Expr>,
    ) {
        let is_real: Self::Expr = is_real.into();
        let clk: Self::Expr = clk.into();
        let mem_access = memory_access.access();

        self.eval_memory_access_timestamp(mem_access, clk, is_real);

        let addr = addr.into();
        let prev_clk = mem_access.prev_clk.clone().into();
        let prev_values = once(prev_clk)
            .chain(once(addr.clone()))
            .chain(memory_access.prev_value().clone().map(Into::into))
            .collect();
        let current_values = once(clk)
            .chain(once(addr.clone()))
            .chain(memory_access.value().clone().map(Into::into))
            .collect();

        // The previous values get sent with multiplicity * 1, for "read".
        self.send(AirInteraction::new(
            prev_values,
            do_check.clone(),
            InteractionKind::Memory,
        ));

        // The current values get "received", i.e. multiplicity = -1
        self.receive(AirInteraction::new(
            current_values,
            do_check.clone(),
            InteractionKind::Memory,
        ));
    }
}
