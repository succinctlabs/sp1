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
use crate::disassembler::WORD_SIZE;

use super::IsZeroOperation;

/// A set of columns needed to compute whether the given word is 0.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsZeroWordOperation<T> {
    /// `IsZeroOperation` to check if each byte in the input word is zero.
    pub is_zero_byte: [IsZeroOperation<T>; WORD_SIZE],

    /// A boolean array whose `i`th element is true if and only if the input word has exactly `i`
    /// zero bytes.
    pub zero_byte_count_flag: [T; WORD_SIZE + 1],

    /// A boolean flag indicating whether the word is zero.
    pub result: T,
}

impl<F: Field> IsZeroWordOperation<F> {
    pub fn populate(&mut self, a_u32: u32) -> u32 {
        let a = a_u32.to_le_bytes();
        let mut num_zero_bytes = 0;
        for i in 0..WORD_SIZE {
            self.is_zero_byte[i].populate(a[i] as u32);
            if a[i] == 0 {
                num_zero_bytes += 1;
            }
        }
        for n in 0..(WORD_SIZE + 1) {
            self.zero_byte_count_flag[n] = F::from_bool(n == num_zero_bytes);
        }
        self.result = F::from_bool(a_u32 == 0);
        (a_u32 == 0) as u32
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        cols: IsZeroWordOperation<AB::Var>,
        is_real: AB::Var,
    ) {
        // Calculate whether each byte is 0.
        for i in 0..WORD_SIZE {
            IsZeroOperation::<AB::F>::eval(builder, a[i], cols.is_zero_byte[i], is_real);
        }

        // From here, we only assert when is_real is true.
        builder.assert_bool(is_real);
        let mut builder_is_real = builder.when(is_real);
        let one: AB::Expr = AB::F::one().into();

        // Count the number of zero bytes.
        {
            let mut zero_byte_count: AB::Expr = AB::F::zero().into();
            for i in 0..WORD_SIZE {
                zero_byte_count = zero_byte_count + cols.is_zero_byte[i].result;
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

        builder_is_real.assert_bool(cols.result);

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
