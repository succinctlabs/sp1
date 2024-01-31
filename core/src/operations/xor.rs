use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::AbstractField;
use p3_field::Field;
use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::bytes::ByteLookupEvent;
use crate::bytes::ByteOpcode;
use crate::disassembler::WORD_SIZE;
use crate::runtime::Segment;

/// A set of columns needed to compute the xor of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct XorOperation<T> {
    /// The result of `x ^ y`.
    pub value: Word<T>,
}

impl<F: Field> XorOperation<F> {
    pub fn populate(&mut self, segment: &mut Segment, x: u32, y: u32) -> u32 {
        let expected = x ^ y;
        let x_bytes = x.to_le_bytes();
        let y_bytes = y.to_le_bytes();
        for i in 0..WORD_SIZE {
            self.value[i] = F::from_canonical_u8(x_bytes[i] ^ y_bytes[i]);
            let xor = x_bytes[i] ^ y_bytes[i];
            self.value[i] = F::from_canonical_u8(xor);

            let byte_event = ByteLookupEvent {
                opcode: ByteOpcode::XOR,
                a1: xor as u32,
                a2: 0,
                b: x_bytes[i] as u32,
                c: y_bytes[i] as u32,
            };
            segment
                .byte_lookups
                .entry(byte_event)
                .and_modify(|j| *j += 1)
                .or_insert(1);
        }
        expected
    }

    #[allow(unused_variables)]
    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: XorOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        for i in 0..WORD_SIZE {
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
                cols.value[i],
                a[i],
                b[i],
                is_real,
            );
        }
    }
}
