use p3_field::{AbstractField, Field};
use sp1_derive::AlignedBorrow;

use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};
use sp1_primitives::consts::WORD_SIZE;
use sp1_stark::{air::SP1AirBuilder, Word};

/// A set of columns needed to compute the and of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AndOperation<T> {
    /// The result of `x & y`.
    pub value: Word<T>,
}

impl<F: Field> AndOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, shard: u32, x: u32, y: u32) -> u32 {
        let expected = x & y;
        let x_bytes = x.to_le_bytes();
        let y_bytes = y.to_le_bytes();
        for i in 0..WORD_SIZE {
            let and = x_bytes[i] & y_bytes[i];
            self.value[i] = F::from_canonical_u8(and);

            let byte_event = ByteLookupEvent {
                shard,
                opcode: ByteOpcode::AND,
                a1: and as u16,
                a2: 0,
                b: x_bytes[i],
                c: y_bytes[i],
            };
            record.add_byte_lookup_event(byte_event);
        }
        expected
    }

    #[allow(unused_variables)]
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: AndOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        for i in 0..WORD_SIZE {
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::AND as u32),
                cols.value[i],
                a[i],
                b[i],
                is_real,
            );
        }
    }
}
