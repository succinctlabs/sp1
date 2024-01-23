//! Word range operation.
//!
//! This operation is used to check that each limb of a word is in the range [0, 255].
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;
use std::marker::PhantomData;
use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;

use crate::bytes::ByteOpcode;
use crate::runtime::Segment;
use p3_field::AbstractField;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct WordRangeOperation<T> {
    _phantom: PhantomData<T>,
}

impl<F: Field> WordRangeOperation<F> {
    pub fn populate(&mut self, segment: &mut Segment, a: u32) {
        let bytes = a.to_le_bytes();
        // Pass two bytes to range check at a time.
        for i in (0..bytes.len()).step_by(2) {
            segment.add_byte_range_checks(bytes[i], bytes[i + 1]);
        }
    }

    pub fn eval<AB: CurtaAirBuilder>(builder: &mut AB, a: Word<AB::Expr>, is_real: AB::Expr) {
        builder.assert_bool(is_real.clone());

        for i in (0..a.0.len()).step_by(2) {
            builder.send_byte_pair(
                AB::F::from_canonical_u32(ByteOpcode::Range as u32),
                AB::F::zero(),
                AB::F::zero(),
                a.0[i].clone(),
                a.0[i + 1].clone(),
                is_real.clone(),
            );
        }

        // Degree 3 constraint to avoid "OodEvaluationMismatch".
        builder.assert_zero(
            is_real.clone() * is_real.clone() * is_real.clone()
                - is_real.clone() * is_real.clone() * is_real.clone(),
        );
    }
}
