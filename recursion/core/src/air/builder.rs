use p3_field::AbstractField;
use sp1_core::{
    air::{AirInteraction, BaseAirBuilder, SP1AirBuilder},
    lookup::InteractionKind,
};

use super::Block;

impl<AB: SP1AirBuilder> RecursionAirBuilder for AB {}

pub trait RecursionAirBuilder: BaseAirBuilder {
    fn eval_memory_read_write<
        EAddr,
        EPrevTimestamp,
        ETimestamp,
        EPrevValue,
        EValue,
        EMultiplicity,
    >(
        &mut self,
        prev_timestamp: EPrevTimestamp,
        timestamp: ETimestamp,
        addr: EAddr,
        prev_value: Block<EPrevValue>,
        value: Block<EValue>,
        multiplicity: EMultiplicity,
    ) where
        EAddr: Into<Self::Expr>,
        EPrevTimestamp: Into<Self::Expr>,
        ETimestamp: Into<Self::Expr>,
        EPrevValue: Into<Self::Expr>,
        EValue: Into<Self::Expr>,
        EMultiplicity: Into<Self::Expr>,
    {
        // TODO add timestamp checks once we have them implemented in recursion VM.
        let [prev_value_0, prev_value_1, prev_value_2, prev_value_3] = prev_value.0;
        let [value_0, value_1, value_2, value_3] = value.0;
        let addr = addr.into();
        let multiplicity = multiplicity.into();

        self.receive(AirInteraction::new(
            vec![
                addr.clone(),
                prev_timestamp.into(),
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
                timestamp.into(),
                value_0.into(),
                value_1.into(),
                value_2.into(),
                value_3.into(),
            ],
            multiplicity,
            InteractionKind::Memory,
        ));
    }

    fn eval_memory_read<EAddr, EPrevTimestamp, ETimestamp, EValue, EMultiplicity>(
        &mut self,
        prev_timestamp: EPrevTimestamp,
        timestamp: ETimestamp,
        addr: EAddr,
        value: EValue,
        multiplicity: EMultiplicity,
    ) where
        EAddr: Into<Self::Expr>,
        EPrevTimestamp: Into<Self::Expr>,
        ETimestamp: Into<Self::Expr>,
        EValue: Into<Block<Self::Expr>>,
        EMultiplicity: Into<Self::Expr>,
    {
        let addr = addr.into();
        let value = value.into();
        self.eval_memory_read_write(
            prev_timestamp.into(),
            timestamp.into(),
            addr,
            value.clone(),
            value,
            multiplicity,
        )
    }
}
