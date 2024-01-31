use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_air::AirBuilder;
use p3_field::Field;
use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::bytes::ByteOpcode;
use crate::disassembler::WORD_SIZE;
use crate::runtime::Segment;
use p3_field::AbstractField;

/// A set of columns needed to compute the not of a word.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct NotOperation<T> {
    /// The result of `!x`.
    pub value: Word<T>,
}

impl<F: Field> NotOperation<F> {
    pub fn populate(&mut self, segment: &mut Segment, x: u32) -> u32 {
        let expected = !x;
        let x_bytes = x.to_le_bytes();
        for i in 0..WORD_SIZE {
            self.value[i] = F::from_canonical_u8(!x_bytes[i]);
        }
        segment.add_u8_range_checks(&x_bytes);
        expected
    }

    #[allow(unused_variables)]
    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        cols: NotOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        for i in (0..WORD_SIZE).step_by(2) {
            builder.send_byte_pair(
                AB::F::from_canonical_u32(ByteOpcode::U8Range as u32),
                AB::F::zero(),
                AB::F::zero(),
                a[i],
                a[i + 1],
                is_real,
            );
        }

        // For any byte b, b + !b = 0xFF.
        for i in 0..WORD_SIZE {
            builder
                .when(is_real)
                .assert_eq(cols.value[i] + a[i], AB::F::from_canonical_u8(u8::MAX));
        }

        // A dummy constraint to keep the degree 3.
        builder.assert_zero(a[0] * a[0] * a[0] - a[0] * a[0] * a[0]);
    }
}
