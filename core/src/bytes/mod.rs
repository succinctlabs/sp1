pub mod air;
mod event;
mod trace;
pub mod utils;

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
    runtime::{Opcode, Segment},
    utils::Chip,
};

use self::utils::shr_carry;

/// A chip for computing byte operations.
///
/// The chip contains a preprocessed table of all possible byte operations. Other chips can then
/// use lookups into this table to compute their own operations.
#[derive(Debug, Clone)]
pub struct ByteChip<F> {
    //// A map from a byte lookup to the corresponding row it appears in the table and the index of
    /// the result in the array of multiplicities.
    event_map: BTreeMap<ByteLookupEvent, (usize, usize)>,
    /// The trace containing the enumeration of all byte operations.
    ///
    /// The rows of the matrix loop over all pairs of bytes and record the results of all byte
    /// operations on them. Each result has an associated lookup multiplicity, which is the number
    /// of times that result was looked up in the program. The multiplicities are initialized at
    /// zero.
    initial_trace: RowMajorMatrix<F>,
}

pub const NUM_BYTE_OPS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ByteOpcode {
    /// Bitwise AND.
    AND = 0,
    /// Bitwise OR.
    OR = 1,
    /// Bitwise XOR.
    XOR = 2,
    /// Bit-shift Left.
    ///
    /// This operation shifts by the first three least significant bits of the second byte.
    SLL = 3,
    /// Range check.
    Range = 4,
    ShrCarry = 5,
    /// Byte less than unsigned.
    LTU = 6,
    /// The most significant bit of the given byte.
    MSB = 7,
}

impl ByteOpcode {
    pub fn get_all() -> Vec<Self> {
        let opcodes = vec![
            ByteOpcode::AND,
            ByteOpcode::OR,
            ByteOpcode::XOR,
            ByteOpcode::SLL,
            ByteOpcode::Range,
            ByteOpcode::ShrCarry,
            ByteOpcode::LTU,
            ByteOpcode::MSB,
        ];
        // Make sure we included all the enum variants.
        assert_eq!(opcodes.len(), NUM_BYTE_OPS);

        opcodes
    }

    pub fn to_field<F: Field>(self) -> F {
        F::from_canonical_u8(self as u8)
    }
}

impl<F: Field> ByteChip<F> {
    pub fn new() -> Self {
        // A map from a byte lookup to its corresponding row in the table and index in the array of
        // multiplicities.
        let mut event_map = BTreeMap::new();

        // The trace containing all values, with all multiplicities set to zero.
        let mut initial_trace =
            RowMajorMatrix::new(vec![F::zero(); NUM_ROWS * NUM_BYTE_COLS], NUM_BYTE_COLS);

        // Record all the necessary operations for each byte lookup.
        let opcodes = ByteOpcode::get_all();

        // Iterate over all options for pairs of bytes `a` and `b`.
        for (row_index, (b, c)) in (0..=u8::MAX).cartesian_product(0..=u8::MAX).enumerate() {
            let b = b as u8;
            let c = c as u8;
            let col: &mut ByteCols<F> = initial_trace.row_mut(row_index).borrow_mut();

            // Set the values of `a` and `b`.
            col.b = F::from_canonical_u8(b);
            col.c = F::from_canonical_u8(c);

            // Iterate over all operations for results and updating the table map.
            for (i, opcode) in opcodes.iter().enumerate() {
                let event = match opcode {
                    ByteOpcode::AND => {
                        let and = b & c;
                        col.and = F::from_canonical_u8(and);
                        ByteLookupEvent::new(*opcode, and, 0, b, c)
                    }
                    ByteOpcode::OR => {
                        let or = b | c;
                        col.or = F::from_canonical_u8(or);
                        ByteLookupEvent::new(*opcode, or, 0, b, c)
                    }
                    ByteOpcode::XOR => {
                        let xor = b ^ c;
                        col.xor = F::from_canonical_u8(xor);
                        ByteLookupEvent::new(*opcode, xor, 0, b, c)
                    }
                    ByteOpcode::SLL => {
                        let sll = b << (c & 7);
                        col.sll = F::from_canonical_u8(sll);
                        ByteLookupEvent::new(*opcode, sll, 0, b, c)
                    }
                    ByteOpcode::Range => ByteLookupEvent::new(*opcode, 0, 0, b, c),
                    ByteOpcode::ShrCarry => {
                        let (res, carry) = shr_carry(b, c);
                        col.shr = F::from_canonical_u8(res);
                        col.shr_carry = F::from_canonical_u8(carry);
                        ByteLookupEvent::new(*opcode, res, carry, b, c)
                    }
                    ByteOpcode::LTU => {
                        let ltu = b < c;
                        col.ltu = F::from_bool(ltu);
                        ByteLookupEvent::new(*opcode, ltu as u8, 0, b, c)
                    }
                    ByteOpcode::MSB => {
                        let msb = (b & 0b1000_0000) != 0;
                        col.msb = F::from_bool(msb);
                        ByteLookupEvent::new(*opcode, msb as u8, 0, b, 0)
                    }
                };
                event_map.insert(event, (row_index, i));
            }
        }

        Self {
            event_map,
            initial_trace,
        }
    }
}

impl<F: Field> Chip<F> for ByteChip<F> {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        self.generate_trace_from_events(&segment.byte_lookups)
    }

    fn name(&self) -> String {
        "Byte".to_string()
    }
}

impl From<Opcode> for ByteOpcode {
    fn from(value: Opcode) -> Self {
        match value {
            Opcode::AND => Self::AND,
            Opcode::OR => Self::OR,
            Opcode::XOR => Self::XOR,
            Opcode::SLL => Self::SLL,
            _ => panic!("Invalid opcode for ByteChip: {:?}", value),
        }
    }
}
