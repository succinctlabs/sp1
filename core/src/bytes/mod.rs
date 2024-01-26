pub mod air;
pub mod columns;
pub mod event;
pub mod opcode;
pub mod trace;
pub mod utils;

pub use opcode::*;

use alloc::collections::BTreeMap;
use core::borrow::BorrowMut;
pub use event::ByteLookupEvent;
use itertools::Itertools;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use self::columns::{ByteCols, NUM_BYTE_COLS};
use self::utils::shr_carry;
use crate::bytes::trace::NUM_ROWS;

/// The number of different byte operations.
pub const NUM_BYTE_OPS: usize = 9;

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

impl<F: Field> ByteChip<F> {
    pub fn new() -> Self {
        // A map from a byte lookup to its corresponding row in the table and index in the array of
        // multiplicities.
        let mut event_map = BTreeMap::new();

        // The trace containing all values, with all multiplicities set to zero.
        let mut initial_trace =
            RowMajorMatrix::new(vec![F::zero(); NUM_ROWS * NUM_BYTE_COLS], NUM_BYTE_COLS);

        // Record all the necessary operations for each byte lookup.
        let opcodes = ByteOpcode::all();

        // Iterate over all options for pairs of bytes `a` and `b`.
        for (row_index, (b, c)) in (0..=u8::MAX).cartesian_product(0..=u8::MAX).enumerate() {
            let b = b as u8;
            let c = c as u8;
            let col: &mut ByteCols<F> = initial_trace.row_mut(row_index).borrow_mut();

            // Set the values of `b` and `c`.
            col.b = F::from_canonical_u8(b);
            col.c = F::from_canonical_u8(c);

            // Iterate over all operations for results and updating the table map.
            for (i, opcode) in opcodes.iter().enumerate() {
                let event = match opcode {
                    ByteOpcode::AND => {
                        let and = b & c;
                        col.and = F::from_canonical_u8(and);
                        ByteLookupEvent::new(*opcode, and as u32, 0, b as u32, c as u32)
                    }
                    ByteOpcode::OR => {
                        let or = b | c;
                        col.or = F::from_canonical_u8(or);
                        ByteLookupEvent::new(*opcode, or as u32, 0, b as u32, c as u32)
                    }
                    ByteOpcode::XOR => {
                        let xor = b ^ c;
                        col.xor = F::from_canonical_u8(xor);
                        ByteLookupEvent::new(*opcode, xor as u32, 0, b as u32, c as u32)
                    }
                    ByteOpcode::SLL => {
                        let sll = b << (c & 7);
                        col.sll = F::from_canonical_u8(sll);
                        ByteLookupEvent::new(*opcode, sll as u32, 0, b as u32, c as u32)
                    }
                    ByteOpcode::U8Range => ByteLookupEvent::new(*opcode, 0, 0, b as u32, c as u32),
                    ByteOpcode::ShrCarry => {
                        let (res, carry) = shr_carry(b, c);
                        col.shr = F::from_canonical_u8(res);
                        col.shr_carry = F::from_canonical_u8(carry);
                        ByteLookupEvent::new(*opcode, res as u32, carry as u32, b as u32, c as u32)
                    }
                    ByteOpcode::LTU => {
                        let ltu = b < c;
                        col.ltu = F::from_bool(ltu);
                        ByteLookupEvent::new(*opcode, ltu as u32, 0, b as u32, c as u32)
                    }
                    ByteOpcode::MSB => {
                        let msb = (b & 0b1000_0000) != 0;
                        col.msb = F::from_bool(msb);
                        ByteLookupEvent::new(*opcode, msb as u32, 0, b as u32, 0 as u32)
                    }
                    ByteOpcode::U16Range => {
                        let v = ((b as u32) << 8) + c as u32;
                        col.value_u16 = F::from_canonical_u32(v);
                        ByteLookupEvent::new(*opcode, v, 0, 0, 0)
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
