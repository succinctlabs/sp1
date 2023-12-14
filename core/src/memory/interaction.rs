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
    is_read: VirtualPairCol<F>,
    multiplicity: VirtualPairCol<F>,
}

pub enum IsRead<F: Field> {
    Bool(bool),
    Expr(VirtualPairCol<F>),
}

impl<F: Field> MemoryInteraction<F> {
    pub fn new(
        clk: VirtualPairCol<F>,
        addr: Word<VirtualPairCol<F>>,
        value: Word<VirtualPairCol<F>>,
        is_read: VirtualPairCol<F>,
        multiplicity: VirtualPairCol<F>,
    ) -> Self {
        Self {
            clk,
            addr,
            value,
            is_read,
            multiplicity,
        }
    }

    pub fn lookup_memory(
        clk: usize,
        addr: Word<usize>,
        value: Word<usize>,
        is_read: IsRead<F>,
        multiplicity: VirtualPairCol<F>,
    ) -> Self {
        let is_read_column = match is_read {
            IsRead::Bool(b) => VirtualPairCol::constant(F::from_bool(b)),
            IsRead::Expr(e) => e,
        };
        Self::new(
            VirtualPairCol::single_main(clk),
            addr.map(VirtualPairCol::single_main),
            value.map(VirtualPairCol::single_main),
            is_read_column,
            multiplicity,
        )
    }

    pub fn lookup_register(
        clk: usize,
        register: usize,
        value: Word<usize>,
        is_read: IsRead<F>,
        multiplicity: VirtualPairCol<F>,
    ) -> Self {
        let is_read_column = match is_read {
            IsRead::Bool(b) => VirtualPairCol::constant(F::from_bool(b)),
            IsRead::Expr(e) => e,
        };
        Self::new(
            VirtualPairCol::single_main(clk),
            // Our convention is that registers are stored at {register, 0xFF, 0xFF, 0xFF} address in memory.
            Word([
                VirtualPairCol::single_main(register),
                VirtualPairCol::constant(F::from_canonical_u32(0xFF)),
                VirtualPairCol::constant(F::from_canonical_u32(0xFF)),
                VirtualPairCol::constant(F::from_canonical_u32(0xFF)),
            ]),
            value.map(VirtualPairCol::single_main),
            is_read_column,
            multiplicity,
        )
    }
}

impl<F: Field> Into<Interaction<F>> for MemoryInteraction<F> {
    fn into(self) -> Interaction<F> {
        let values = once(self.clk)
            .chain(self.addr)
            .chain(self.value)
            .chain(once(self.is_read));
        Interaction::new(values.collect(), self.multiplicity, InteractionKind::Memory)
    }
}
