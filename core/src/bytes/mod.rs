pub mod air;
mod event;
mod trace;

use core::borrow::BorrowMut;

use alloc::collections::BTreeMap;

pub use event::ByteLookupEvent;
use itertools::Itertools;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    bytes::{
        air::{ByteCols, NUM_BYTE_COLS},
        trace::NUM_ROWS,
    },
    runtime::Runtime,
    utils::Chip,
};

#[derive(Debug, Clone)]
pub struct ByteChip<F> {
    table_map: BTreeMap<ByteLookupEvent, (usize, usize)>,
    initial_trace: RowMajorMatrix<F>,
}

pub const NUM_BYTE_OPS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ByteOpcode {
    /// Bitwise AND.
    And = 0,
    /// Bitwise OR.
    Or = 1,
    /// Bitwise XOR.
    Xor = 2,
    /// Bit-shift Left.
    SLL = 3,
    /// Range check.
    Range = 5,
}

impl ByteOpcode {
    pub fn event(&self, a: u8, b: u8) -> ByteLookupEvent {
        match self {
            Self::And => ByteLookupEvent::new(*self, a, b, a & b),
            Self::Or => ByteLookupEvent::new(*self, a, b, a | b),
            Self::Xor => ByteLookupEvent::new(*self, a, b, a ^ b),
            Self::SLL => ByteLookupEvent::new(*self, a, b, a << b),
            Self::Range => ByteLookupEvent::new(*self, a, b, 0),
        }
    }

    pub fn get_all() -> Vec<Self> {
        let opcodes = vec![
            ByteOpcode::And,
            ByteOpcode::Or,
            ByteOpcode::Xor,
            ByteOpcode::SLL,
            ByteOpcode::Range,
        ];
        // Make sure we included all the enum variants.
        assert_eq!(opcodes.len(), NUM_BYTE_OPS);

        opcodes
    }
}

impl<F: Field> ByteChip<F> {
    pub fn update_trace(event: &ByteLookupEvent, col: &mut ByteCols<F>) {
        match event.opcode {
            ByteOpcode::And => {
                col.and = F::from_canonical_u8(event.c);
            }
            ByteOpcode::Or => {
                col.or = F::from_canonical_u8(event.c);
            }
            ByteOpcode::Xor => {
                col.xor = F::from_canonical_u8(event.c);
            }
            ByteOpcode::SLL => {
                col.sll = F::from_canonical_u8(event.c);
            }
            ByteOpcode::Range => {
                // Do nothing.
            }
        }
    }

    pub fn new() -> Self {
        // A map from a byte lookup to its corresponding row in the table and index in the array of
        // multiplicities.
        let mut table_map = BTreeMap::new();

        // The trace containing all values, with all multiplicities set to zero.
        let mut initial_trace =
            RowMajorMatrix::new(vec![F::zero(); NUM_ROWS * NUM_BYTE_COLS], NUM_BYTE_COLS);

        // Record all the necessary operations for each byte lookup.
        let opcodes = ByteOpcode::get_all();

        // Iterate over all options for pairs of bytes `a` and `b`.
        for (row_index, (a, b)) in (0..u8::MAX).cartesian_product(0..u8::MAX).enumerate() {
            let col: &mut ByteCols<F> = initial_trace.row_mut(row_index).borrow_mut();

            // Set the values of `a` and `b`.
            col.a = F::from_canonical_u8(a);
            col.b = F::from_canonical_u8(b);

            // Iterate over all operations for results and updating the table map.
            for (i, opcode) in opcodes.iter().enumerate() {
                let event = opcode.event(a, b);
                Self::update_trace(&event, col);
                table_map.insert(opcode.event(a, b), (row_index, i));
            }
        }

        Self {
            table_map,
            initial_trace,
        }
    }
}

impl<F: Field> Chip<F> for ByteChip<F> {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        self.generate_trace_from_events(&runtime.byte_lookups)
    }
}
