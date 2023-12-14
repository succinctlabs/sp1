use p3_air::VirtualPairCol;
use p3_field::Field;

use crate::air::Word;

/// An interaction for a lookup or a permutation argument.
pub struct Interaction<F: Field> {
    pub values: Vec<VirtualPairCol<F>>,
    pub multiplicity: VirtualPairCol<F>,
    pub kind: InteractionKind,
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

pub enum IsRead<F: Field> {
    Bool(bool),
    Expr(VirtualPairCol<F>),
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
        Self {
            values: vec![
                VirtualPairCol::single_main(clk),
                // Our convention is that registers are stored at {register, 0xFF, 0xFF, 0xFF} address in memory.
                VirtualPairCol::single_main(register),
                VirtualPairCol::constant(F::from_canonical_u8(0xFF)),
                VirtualPairCol::constant(F::from_canonical_u8(0xFF)),
                VirtualPairCol::constant(F::from_canonical_u8(0xFF)),
                // Fields for the value being read
                VirtualPairCol::single_main(value.0[0]),
                VirtualPairCol::single_main(value.0[1]),
                VirtualPairCol::single_main(value.0[2]),
                VirtualPairCol::single_main(value.0[3]),
                // Read operation
                is_read_column,
            ],
            multiplicity,
            kind: InteractionKind::Memory,
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
        Self {
            values: vec![
                VirtualPairCol::single_main(clk),
                // Address
                VirtualPairCol::single_main(addr.0[0]),
                VirtualPairCol::single_main(addr.0[1]),
                VirtualPairCol::single_main(addr.0[2]),
                VirtualPairCol::single_main(addr.0[3]),
                // Fields for the value being read
                VirtualPairCol::single_main(value.0[0]),
                VirtualPairCol::single_main(value.0[1]),
                VirtualPairCol::single_main(value.0[2]),
                VirtualPairCol::single_main(value.0[3]),
                // Read operation
                is_read_column,
            ],
            multiplicity,
            kind: InteractionKind::Memory,
        }
    }

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
