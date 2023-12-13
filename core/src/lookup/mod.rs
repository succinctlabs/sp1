use p3_air::{PairCol, VirtualPairCol};
use p3_field::Field;

use crate::memory::MemOp;

pub mod log_derivative;

/// An interaction for a lookup or a permutation argument.
pub struct Interaction<F: Field> {
    values: Vec<VirtualPairCol<F>>,
    multiplicity: VirtualPairCol<F>,
    kind: InteractionKind,
}

/// The type of interaction for a lookup argument.
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

    pub fn read(clk: PairCol, addr: PairCol, value: PairCol, multiplicity: PairCol) -> Self {
        Self {
            values: vec![
                VirtualPairCol::single(clk),
                VirtualPairCol::single(addr),
                VirtualPairCol::constant(F::from_canonical_u8(MemOp::Read as u8)),
                VirtualPairCol::single(value),
            ],
            multiplicity: VirtualPairCol::new(vec![(multiplicity, F::one())], F::zero()),
            kind: InteractionKind::Memory,
        }
    }

    pub fn write(clk: PairCol, addr: PairCol, value: PairCol, multiplicity: PairCol) -> Self {
        Self {
            values: vec![
                VirtualPairCol::single(clk),
                VirtualPairCol::single(addr),
                VirtualPairCol::constant(F::from_canonical_u8(MemOp::Write as u8)),
                VirtualPairCol::single(value),
            ],
            multiplicity: VirtualPairCol::new(vec![(multiplicity, F::one())], F::zero()),
            kind: InteractionKind::Memory,
        }
    }
}
