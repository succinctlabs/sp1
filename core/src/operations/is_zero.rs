//! An operation to check if the input is 0.
//!
//! This is guaranteed to return 1 if and only if the input is 0.
//!
//! The idea is to compute the inverse of each byte in the input word and store them in the trace.
//! Then we compute the product of each byte with its inverse. We get 1 if the input is nonzero, and
//! 0 if the input is zero.
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_air::AirBuilder;
use p3_field::AbstractField;
use p3_field::Field;
use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::disassembler::WORD_SIZE;

/// A set of columns needed to compute the not of a word.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsZeroOperation<T> {
    /// The inverse of each byte in the input word.
    pub inverse: Word<T>,

    /// A boolean array indicating whether each byte in the input word is zero.
    ///
    /// This equals `inverse[0] * input[0] == 0`.
    pub is_zero_byte: Word<T>,

    /// A boolean array whose `i`th element is true if and only if the input word has exactly `i`
    /// zero bytes.
    pub zero_byte_count_flag: [T; WORD_SIZE + 1],

    /// A boolean flag indicating whether the word is zero.
    pub result: T,
}

impl<F: Field> IsZeroOperation<F> {
    pub fn populate(&mut self, x_u32: u32) -> u32 {
        let x = x_u32.to_le_bytes();
        let mut num_zero_bytes = 0;
        for i in 0..WORD_SIZE {
            if x[i] == 0 {
                self.inverse[i] = F::zero();
                num_zero_bytes += 1;
            } else {
                self.inverse[i] = F::from_canonical_u64(u64::from(x[i])).inverse();
            }
            self.is_zero_byte[i] = F::from_bool(x[i] == 0);
            let prod = self.inverse[i] * F::from_canonical_u8(x[i]);
            debug_assert!(prod == F::one() || prod == F::zero());
        }
        for n in 0..(WORD_SIZE + 1) {
            self.zero_byte_count_flag[n] = F::from_bool(n == num_zero_bytes);
        }
        // TODO: Range check the input word.
        let result: u32 = {
            if x_u32 == 0 {
                1
            } else {
                0
            }
        };
        self.result = F::from_canonical_u32(result);
        // TODO: Remove this before opening a PR.
        println!("(x = {:?}) => {:#?}", x, self);
        result
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        cols: IsZeroOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        builder.assert_bool(is_real);
        let mut builder_is_real = builder.when(is_real);
        let one: AB::Expr = AB::F::one().into();
        // Sanity checks including range checks and boolean checks.
        {
            builder_is_real.assert_bool(cols.result);
            // TODO: Range check the input word.
        }

        // Calculate whether each byte is 0.
        {
            // If a byte is 0, then any product involving the byte is 0. If a byte is nonzero and
            // its inverse is correctly set, then the product is 1.
            for i in 0..WORD_SIZE {
                let is_zero = one.clone() - cols.inverse[i] * a[i];
                builder_is_real.assert_eq(is_zero, cols.is_zero_byte[i]);
                builder_is_real.assert_bool(cols.is_zero_byte[i]);
            }
        }

        // Count the number of zero bytes.
        {
            let mut zero_byte_count: AB::Expr = AB::F::zero().into();
            for i in 0..WORD_SIZE {
                zero_byte_count = zero_byte_count + cols.is_zero_byte[i];
            }

            // zero_byte_count_flag must be a boolean array and the sum of its elements must be 1.
            let mut zero_byte_count_flag_sum: AB::Expr = AB::F::from_canonical_usize(0).into();
            for num_zero_bytes in 0..(WORD_SIZE + 1) {
                builder_is_real.assert_bool(cols.zero_byte_count_flag[num_zero_bytes]);
                zero_byte_count_flag_sum =
                    zero_byte_count_flag_sum + cols.zero_byte_count_flag[num_zero_bytes];
            }
            builder_is_real.assert_eq(zero_byte_count_flag_sum, one.clone());

            // Finally, zero_byte_count must match zero_byte_count_flag.
            for num_zero_bytes in 0..(WORD_SIZE + 1) {
                builder_is_real
                    .when(cols.zero_byte_count_flag[num_zero_bytes])
                    .assert_eq(
                        zero_byte_count.clone(),
                        AB::F::from_canonical_usize(num_zero_bytes),
                    );
            }
        }

        // If cols.result is true, then a is zero.
        {
            for i in 0..WORD_SIZE {
                builder_is_real.when(cols.result).assert_zero(a[i]);
            }
        }

        // If cols.result is false, then a is not zero.
        {
            let not_zero = one.clone() - cols.result;
            builder_is_real
                .when(not_zero)
                .assert_zero(cols.zero_byte_count_flag[WORD_SIZE]);
        }
    }
}
