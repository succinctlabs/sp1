use std::iter::once;

use p3_air::VirtualPairCol;
use p3_field::Field;

use crate::{
    air::Word,
    lookup::{Interaction, InteractionKind},
};

pub struct MemoryInteraction<F: Field> {
    clk: VirtualPairCol<F>,
    addr: Word<VirtualPairCol<F>>,
    value: Word<VirtualPairCol<F>>,
    multiplicity: VirtualPairCol<F>,
    is_read: VirtualPairCol<F>,
}

impl<F: Field> MemoryInteraction<F> {
    pub fn new(
        clk: VirtualPairCol<F>,
        addr: Word<VirtualPairCol<F>>,
        value: Word<VirtualPairCol<F>>,
        multiplicity: VirtualPairCol<F>,
        is_read: VirtualPairCol<F>,
    ) -> Self {
        Self {
            clk,
            addr,
            value,
            multiplicity,
            is_read,
        }
    }
}

impl<F: Field> Into<Interaction<F>> for MemoryInteraction<F> {
    fn into(self) -> Interaction<F> {
        let values = once(self.clk)
            .chain(self.addr.0)
            .chain(self.value.0)
            .chain(once(self.is_read));
        Interaction::new(values.collect(), self.multiplicity, InteractionKind::Memory)
    }
}
