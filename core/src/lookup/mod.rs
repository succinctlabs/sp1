use std::fmt::Debug;

use p3_air::VirtualPairCol;
use p3_field::Field;

use crate::air::Word;
mod builder;

pub use builder::InteractionBuilder;

/// An interaction for a lookup or a permutation argument.
pub struct Interaction<F: Field> {
    pub values: Vec<VirtualPairCol<F>>,
    pub multiplicity: VirtualPairCol<F>,
    pub kind: InteractionKind,
}

// TODO: add debug for VirtualPairCol so that we can derive Debug for Interaction.
impl<F: Field> Debug for Interaction<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interaction")
            .field("kind", &self.kind)
            .finish()
    }
}

/// The type of interaction for a lookup argument.
#[derive(Debug, Clone, Copy)]
pub enum InteractionKind {
    /// Interaction with the memory table, such as read and write.
    Memory = 1,
    /// Interaction with the program table, loading an instruction at a given pc address.
    Program = 2,
    /// Interaction with instruction oracle.
    Instruction = 3,
    /// Interaction with the ALU operations
    Alu = 4,
    /// Interaction with the byte lookup table for byte operations.
    Byte = 5,
    /// Requesting a range check for a given value and range.
    Range = 6,
}

impl<F: Field> Interaction<F> {
    pub fn new(
        values: Vec<VirtualPairCol<F>>,
        multiplicity: VirtualPairCol<F>,
        kind: InteractionKind,
    ) -> Self {
        Self {
            values,
            multiplicity,
            kind,
        }
    }

    pub fn argument_index(&self) -> usize {
        self.kind as usize
    }

    // TODO: move to the add chip
    pub fn add(
        res: Word<usize>,
        a: Word<usize>,
        b: Word<usize>,
        multiplicity: VirtualPairCol<F>,
    ) -> Self {
        Self {
            values: vec![
                VirtualPairCol::single_main(res.0[0]),
                VirtualPairCol::single_main(res.0[1]),
                VirtualPairCol::single_main(res.0[2]),
                VirtualPairCol::single_main(res.0[3]),
                VirtualPairCol::single_main(a.0[0]),
                VirtualPairCol::single_main(a.0[1]),
                VirtualPairCol::single_main(a.0[2]),
                VirtualPairCol::single_main(a.0[3]),
                VirtualPairCol::single_main(b.0[0]),
                VirtualPairCol::single_main(b.0[1]),
                VirtualPairCol::single_main(b.0[2]),
                VirtualPairCol::single_main(b.0[3]),
            ],
            multiplicity,
            kind: InteractionKind::Alu,
        }
    }
}
