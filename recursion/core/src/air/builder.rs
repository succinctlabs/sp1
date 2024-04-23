use crate::memory::{MemoryAccessCols, MemoryAccessColsSingle};
use p3_field::AbstractField;
use sp1_core::{
    air::{AirInteraction, BaseAirBuilder, SP1AirBuilder},
    lookup::InteractionKind,
};

impl<AB: SP1AirBuilder> RecursionAirBuilder for AB {}

pub trait RecursionAirBuilder: BaseAirBuilder {
    fn recursion_eval_memory_access<E: Into<Self::Expr>>(
        &mut self,
        addr: impl Into<Self::Expr>,
        memory_access: &impl MemoryAccessCols<E>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        // TODO add timestamp checks once we have them implemented in recursion VM.
        let [prev_value_0, prev_value_1, prev_value_2, prev_value_3] = memory_access.prev_value().0;
        let [value_0, value_1, value_2, value_3] = memory_access.prev_value().0;
        let addr = addr.into();
        let multiplicity = multiplicity.into();

        self.receive(AirInteraction::new(
            vec![
                addr.clone(),
                memory_access.prev_timestamp().into(),
                prev_value_0.into(),
                prev_value_1.into(),
                prev_value_2.into(),
                prev_value_3.into(),
            ],
            multiplicity.clone(),
            InteractionKind::Memory,
        ));
        self.send(AirInteraction::new(
            vec![
                addr,
                memory_access.timestamp().into(),
                value_0.into(),
                value_1.into(),
                value_2.into(),
                value_3.into(),
            ],
            multiplicity,
            InteractionKind::Memory,
        ));
    }

    fn recursion_eval_memory_access_single<E: Into<Self::Expr>>(
        &mut self,
        addr: impl Into<Self::Expr>,
        memory_access: &impl MemoryAccessColsSingle<E>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let addr = addr.into();
        let multiplicity = multiplicity.into();

        self.receive(AirInteraction::new(
            vec![
                addr.clone(),
                memory_access.prev_timestamp().into(),
                memory_access.prev_value().into(),
                Self::Expr::zero(),
                Self::Expr::zero(),
                Self::Expr::zero(),
            ],
            multiplicity.clone(),
            InteractionKind::Memory,
        ));
        self.send(AirInteraction::new(
            vec![
                addr,
                memory_access.timestamp().into(),
                memory_access.value().into(),
                Self::Expr::zero(),
                Self::Expr::zero(),
                Self::Expr::zero(),
            ],
            multiplicity,
            InteractionKind::Memory,
        ));
    }
}
