use std::iter::once;

use p3_air::VirtualPairCol;
use p3_field::Field;

use crate::{
    air::Word,
    lookup::{Interaction, InteractionKind},
    runtime::Opcode,
};

pub mod add;
pub mod bitwise;
pub mod lt;
pub mod shift;
pub mod sub;

#[derive(Debug, Clone, Copy)]
pub struct AluEvent {
    pub clk: u32,
    pub opcode: Opcode,
    pub a: u32,
    pub b: u32,
    pub c: u32,
}

impl AluEvent {
    pub fn new(clk: u32, opcode: Opcode, a: u32, b: u32, c: u32) -> Self {
        Self {
            clk,
            opcode,
            a,
            b,
            c,
        }
    }
}

pub struct AluInteraction<F: Field> {
    a: Word<VirtualPairCol<F>>,
    b: Word<VirtualPairCol<F>>,
    c: Word<VirtualPairCol<F>>,
    multipicities: VirtualPairCol<F>,
}

impl<F: Field> AluInteraction<F> {
    pub fn new(
        a: Word<VirtualPairCol<F>>,
        b: Word<VirtualPairCol<F>>,
        c: Word<VirtualPairCol<F>>,
        multipicities: VirtualPairCol<F>,
    ) -> Self {
        Self {
            a,
            b,
            c,
            multipicities,
        }
    }
}

impl<F: Field> Into<Interaction<F>> for AluInteraction<F> {
    fn into(self) -> Interaction<F> {
        let values = self.a.0.into_iter().chain(self.b.0).chain(self.c.0);
        Interaction::new(values.collect(), self.multipicities, InteractionKind::Alu)
    }
}

pub struct AluInteractionWithOpcode<F: Field> {
    opcode: VirtualPairCol<F>,
    a: Word<VirtualPairCol<F>>,
    b: Word<VirtualPairCol<F>>,
    c: Word<VirtualPairCol<F>>,
    multipicities: VirtualPairCol<F>,
}

impl<F: Field> AluInteractionWithOpcode<F> {
    pub fn new(
        opcode: VirtualPairCol<F>,
        a: Word<VirtualPairCol<F>>,
        b: Word<VirtualPairCol<F>>,
        c: Word<VirtualPairCol<F>>,
        multipicities: VirtualPairCol<F>,
    ) -> Self {
        Self {
            opcode,
            a,
            b,
            c,
            multipicities,
        }
    }
}

impl<F: Field> Into<Interaction<F>> for AluInteractionWithOpcode<F> {
    fn into(self) -> Interaction<F> {
        let values = once(self.opcode)
            .chain(self.a.0)
            .chain(self.b.0)
            .chain(self.c.0);
        Interaction::new(values.collect(), self.multipicities, InteractionKind::Alu)
    }
}
