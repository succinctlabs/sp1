use p3_field::AbstractField;
use p3_field::Field;
use sp1_derive::AlignedBorrow;

use crate::air::SP1AirBuilder;
use crate::air::Word;
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteLookupEvent;
use crate::bytes::ByteOpcode;
use crate::disassembler::WORD_SIZE;

/// A set of columns needed to compute the xor of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct XorOperation<T> {
    /// The result of `x ^ y`.
    pub value: Word<T>,
}

impl<F: Field> XorOperation<F> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        shard: u32,
        channel: u8,
        x: u32,
        y: u32,
    ) -> u32 {
        let expected = x ^ y;
        let x_bytes = x.to_le_bytes();
        let y_bytes = y.to_le_bytes();
        for i in 0..WORD_SIZE {
            let xor = x_bytes[i] ^ y_bytes[i];
            self.value[i] = F::from_canonical_u8(xor);

            let byte_event = ByteLookupEvent {
                shard,
                channel,
                opcode: ByteOpcode::XOR,
                a1: xor as u16,
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
        cols: XorOperation<AB::Var>,
        shard: AB::Var,
        channel: impl Into<AB::Expr> + Clone,
        is_real: AB::Var,
    ) {
        for i in 0..WORD_SIZE {
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
                cols.value[i],
                a[i],
                b[i],
                shard,
                channel.clone(),
                is_real,
            );
        }
    }
}
