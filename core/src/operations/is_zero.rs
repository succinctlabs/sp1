//! An operation to check if the input is 0.
//!
//! This is guaranteed to return 1 if and only if the input is 0.
//!
//! The idea is to compute the inverse of each byte in the input word and store them in the trace.
//! Then we compute the product of each byte with its inverse. We get 1 if the input is nonzero, and
//! 0 if the input is zero. Assertions fail if the inverse is not correctly set.
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_air::AirBuilder;
use p3_field::AbstractField;
use p3_field::Field;
use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::bytes::ByteOpcode;
use crate::disassembler::WORD_SIZE;
use crate::runtime::Segment;

/// A set of columns needed to compute whether the given word is 0.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsZeroOperation<T> {
    /// The inverse of the input.
    pub inverse: T,

    /// Result indicating whether the input is 0. This equals `inverse * input == 0`.
    pub result: Word<T>,
}

impl<F: Field> IsZeroOperation<F> {
    pub fn populate(&mut self, segment: &mut Segment, a: u32) -> u32 {
        if a[i] == 0 {
            self.inverse[i] = F::zero();
            self.result = F::one();
        } else {
            self.inverse[i] = F::from_canonical_u64(u64::from(a[i])).inverse();
            self.result = F::zero();
        }
        let prod = self.inverse[i] * F::from_canonical_u8(a[i]);
        debug_assert!(prod == F::one() || prod == F::zero());
        (n == 0) as u32
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        a: AB::Var,
        cols: IsZeroOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        builder.assert_bool(is_real);
        let one: AB::Expr = AB::F::one().into();

        // 1. Input == 0 => is_zero = 1 regardless of the inverse.
        // 2. Input != 0
        //   2.1. inverse is correctly set => is_zero = 0.
        //   2.2. inverse is incorrect
        //     2.2.1 inverse is nonzero => is_zero isn't bool, it fails.
        //     2.2.2 inverse is 0 => is_zero is 1. But then we would assert that a = 0. And that
        //                           assert fails.

        // If the input is 0, then any product involving it is 0. If it is nonzero and its inverse
        // is correctly set, then the product is 1.
        let is_zero = one.clone() - cols.inverse * a;
        builder.when(is_real).assert_eq(is_zero, cols.result);
        builder.when(is_real).assert_bool(cols.result);

        // If the result is 1, then the input is 0.
        builder.when(is_real).when(cols.result).assert_zero(a);
    }
}
