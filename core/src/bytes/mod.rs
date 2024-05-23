pub mod air;
pub mod columns;
pub mod event;
pub mod opcode;
pub mod trace;
pub mod utils;

pub use event::ByteLookupEvent;
pub use opcode::*;

use alloc::collections::BTreeMap;
use core::borrow::BorrowMut;
use std::marker::PhantomData;

use itertools::Itertools;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use self::columns::{BytePreprocessedCols, NUM_BYTE_PREPROCESSED_COLS};
use self::utils::shr_carry;
use crate::bytes::trace::NUM_ROWS;

/// The number of different byte operations.
pub const NUM_BYTE_OPS: usize = 9;

/// A chip for computing byte operations.
///
/// The chip contains a preprocessed table of all possible byte operations. Other chips can then
/// use lookups into this table to compute their own operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct ByteChip<F>(PhantomData<F>);

impl<F: Field> ByteChip<F> {
    /// Creates the preprocessed byte trace and event map.
    ///
    /// This function returns a pair `(trace, map)`, where:
    ///  - `trace` is a matrix containing all possible byte operations.
    /// - `map` is a map from a byte lookup to the corresponding row it appears in the table and
    /// the index of the result in the array of multiplicities.
    #[must_use]
    pub fn trace_and_map(
        shard: u32,
    ) -> (RowMajorMatrix<F>, BTreeMap<ByteLookupEvent, (usize, usize)>) {
        // A map from a byte lookup to its corresponding row in the table and index in the array of
        // multiplicities.
        let mut event_map = BTreeMap::new();

        // The trace containing all values, with all multiplicities set to zero.
        let mut initial_trace = RowMajorMatrix::new(
            vec![F::zero(); NUM_ROWS * NUM_BYTE_PREPROCESSED_COLS],
            NUM_BYTE_PREPROCESSED_COLS,
        );

        // Record all the necessary operations for each byte lookup.
        let opcodes = ByteOpcode::all();

        // Iterate over all options for pairs of bytes `a` and `b`.
        for (row_index, (b, c)) in (0..=u8::MAX).cartesian_product(0..=u8::MAX).enumerate() {
            let b = b as u8;
            let c = c as u8;
            let col: &mut BytePreprocessedCols<F> = initial_trace.row_mut(row_index).borrow_mut();

            // Set the values of `b` and `c`.
            col.b = F::from_canonical_u8(b);
            col.c = F::from_canonical_u8(c);

            // Iterate over all operations for results and updating the table map.
            for (i, opcode) in opcodes.iter().enumerate() {
                let event = match opcode {
                    ByteOpcode::AND => {
                        let and = b & c;
                        col.and = F::from_canonical_u8(and);
                        ByteLookupEvent::new(
                            shard,
                            *opcode,
                            u32::from(and),
                            0,
                            u32::from(b),
                            u32::from(c),
                        )
                    }
                    ByteOpcode::OR => {
                        let or = b | c;
                        col.or = F::from_canonical_u8(or);
                        ByteLookupEvent::new(
                            shard,
                            *opcode,
                            u32::from(or),
                            0,
                            u32::from(b),
                            u32::from(c),
                        )
                    }
                    ByteOpcode::XOR => {
                        let xor = b ^ c;
                        col.xor = F::from_canonical_u8(xor);
                        ByteLookupEvent::new(
                            shard,
                            *opcode,
                            u32::from(xor),
                            0,
                            u32::from(b),
                            u32::from(c),
                        )
                    }
                    ByteOpcode::SLL => {
                        let sll = b << (c & 7);
                        col.sll = F::from_canonical_u8(sll);
                        ByteLookupEvent::new(
                            shard,
                            *opcode,
                            u32::from(sll),
                            0,
                            u32::from(b),
                            u32::from(c),
                        )
                    }
                    ByteOpcode::U8Range => {
                        ByteLookupEvent::new(shard, *opcode, 0, 0, u32::from(b), u32::from(c))
                    }
                    ByteOpcode::ShrCarry => {
                        let (res, carry) = shr_carry(b, c);
                        col.shr = F::from_canonical_u8(res);
                        col.shr_carry = F::from_canonical_u8(carry);
                        ByteLookupEvent::new(
                            shard,
                            *opcode,
                            u32::from(res),
                            u32::from(carry),
                            u32::from(b),
                            u32::from(c),
                        )
                    }
                    ByteOpcode::LTU => {
                        let ltu = b < c;
                        col.ltu = F::from_bool(ltu);
                        ByteLookupEvent::new(
                            shard,
                            *opcode,
                            u32::from(ltu),
                            0,
                            u32::from(b),
                            u32::from(c),
                        )
                    }
                    ByteOpcode::MSB => {
                        let msb = (b & 0b1000_0000) != 0;
                        col.msb = F::from_bool(msb);
                        ByteLookupEvent::new(
                            shard,
                            *opcode,
                            u32::from(msb),
                            0,
                            u32::from(b),
                            0 as u32,
                        )
                    }
                    ByteOpcode::U16Range => {
                        let v = (u32::from(b) << 8) + u32::from(c);
                        col.value_u16 = F::from_canonical_u32(v);
                        ByteLookupEvent::new(shard, *opcode, v, 0, 0, 0)
                    }
                };
                event_map.insert(event, (row_index, i));
            }
        }

        (initial_trace, event_map)
    }
}
