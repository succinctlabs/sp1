pub mod air;
pub mod columns;
// pub mod event;
// pub mod opcode;
pub mod trace;
pub mod utils;

use sp1_core_executor::{events::ByteLookupEvent, ByteOpcode};

use core::borrow::BorrowMut;
use std::marker::PhantomData;

use itertools::Itertools;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use self::{
    columns::{BytePreprocessedCols, NUM_BYTE_PREPROCESSED_COLS},
    utils::shr_carry,
};
use crate::{bytes::trace::NUM_ROWS, utils::zeroed_f_vec};

/// The number of different byte operations.
pub const NUM_BYTE_OPS: usize = 9;

/// A chip for computing byte operations.
///
/// The chip contains a preprocessed table of all possible byte operations. Other chips can then
/// use lookups into this table to compute their own operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct ByteChip<F>(PhantomData<F>);

impl<F: Field> ByteChip<F> {
    /// Creates the preprocessed byte trace.
    ///
    /// This function returns a `trace` which is a matrix containing all possible byte operations.
    pub fn trace() -> RowMajorMatrix<F> {
        // The trace containing all values, with all multiplicities set to zero.
        let mut initial_trace = RowMajorMatrix::new(
            zeroed_f_vec(NUM_ROWS * NUM_BYTE_PREPROCESSED_COLS),
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
            let shard = 0;
            for opcode in opcodes.iter() {
                match opcode {
                    ByteOpcode::AND => {
                        let and = b & c;
                        col.and = F::from_canonical_u8(and);
                        ByteLookupEvent::new(shard, *opcode, and as u16, 0, b, c)
                    }
                    ByteOpcode::OR => {
                        let or = b | c;
                        col.or = F::from_canonical_u8(or);
                        ByteLookupEvent::new(shard, *opcode, or as u16, 0, b, c)
                    }
                    ByteOpcode::XOR => {
                        let xor = b ^ c;
                        col.xor = F::from_canonical_u8(xor);
                        ByteLookupEvent::new(shard, *opcode, xor as u16, 0, b, c)
                    }
                    ByteOpcode::SLL => {
                        let sll = b << (c & 7);
                        col.sll = F::from_canonical_u8(sll);
                        ByteLookupEvent::new(shard, *opcode, sll as u16, 0, b, c)
                    }
                    ByteOpcode::U8Range => ByteLookupEvent::new(shard, *opcode, 0, 0, b, c),
                    ByteOpcode::ShrCarry => {
                        let (res, carry) = shr_carry(b, c);
                        col.shr = F::from_canonical_u8(res);
                        col.shr_carry = F::from_canonical_u8(carry);
                        ByteLookupEvent::new(shard, *opcode, res as u16, carry, b, c)
                    }
                    ByteOpcode::LTU => {
                        let ltu = b < c;
                        col.ltu = F::from_bool(ltu);
                        ByteLookupEvent::new(shard, *opcode, ltu as u16, 0, b, c)
                    }
                    ByteOpcode::MSB => {
                        let msb = (b & 0b1000_0000) != 0;
                        col.msb = F::from_bool(msb);
                        ByteLookupEvent::new(shard, *opcode, msb as u16, 0, b, 0)
                    }
                    ByteOpcode::U16Range => {
                        let v = ((b as u32) << 8) + c as u32;
                        col.value_u16 = F::from_canonical_u32(v);
                        ByteLookupEvent::new(shard, *opcode, v as u16, 0, 0, 0)
                    }
                };
            }
        }

        initial_trace
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use std::time::Instant;

    use super::*;

    #[test]
    pub fn test_trace_and_map() {
        let start = Instant::now();
        ByteChip::<BabyBear>::trace();
        println!("trace and map: {:?}", start.elapsed());
    }
}
