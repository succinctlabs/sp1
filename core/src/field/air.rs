use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::Field;
use p3_matrix::MatrixRowSlices;
use valida_derive::AlignedBorrow;

use crate::air::{CurtaAirBuilder, FieldAirBuilder, Word, WORD_SIZE};
use crate::bytes::ByteOpcode;

use super::FieldLTUChip;

pub const NUM_FIELD_COLS: usize = size_of::<FieldLTUCols<u8>>();

#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct FieldLTUCols<T> {
    /// The first field operand.
    pub b: T,

    /// The second field operand.
    pub c: T,

    /// The result of the `LT` operation on `a` and `b`
    pub lt: T,

    // The word representation of b
    pub b_word: Word<T>,

    // The word representation of c
    pub c_word: Word<T>,

    // Bitmap of which byte is the most signficant differing byte.
    // Either exactly one must be set or none are set.
    pub differing_byte: [T; WORD_SIZE],

    // The value of the most significant different byte.
    // Note that this needs to be "materialized" as a column (as opposed to being an expression of
    // b_word/c_word and differeing_byte) because it is used as an input to the byte ltu lookup,
    // which must have a degree at most 1.
    pub b_byte: T,
    pub c_byte: T,

    // TODO:  Support multiplicities > 1.  Right now there can be duplicate rows.
    // pub multiplicities: T,
    pub is_real: T,
}

impl<F: Field> BaseAir<F> for FieldLTUChip {
    fn width(&self) -> usize {
        NUM_FIELD_COLS
    }
}

impl<AB: CurtaAirBuilder> Air<AB> for FieldLTUChip {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &FieldLTUCols<AB::Var> = main.row_slice(0).borrow();

        // Dummy constraint for normalizing to degree 3.
        builder.assert_eq(local.b * local.b * local.b, local.b * local.b * local.b);

        // Verify that lt is a boolean.
        builder.assert_bool(local.lt);

        // Verify that the word representation of b and c are correct.
        builder.assert_eq(Word::reduce::<AB>(&local.b_word), local.b);
        builder.assert_eq(Word::reduce::<AB>(&local.c_word), local.c);

        // Check that each element in differeing_byte is a boolean.
        for i in 0..WORD_SIZE {
            builder.assert_bool(local.differing_byte[i]);
        }

        // Verify that at most one bit in different_byte is set.
        let bit_sum = local
            .differing_byte
            .iter()
            .fold(AB::Expr::zero(), |acc, x| acc + *x);
        builder.assert_eq(
            bit_sum.clone() * (bit_sum - AB::Expr::one()),
            AB::Expr::zero(),
        );

        for i in 0..WORD_SIZE {
            // Verify that all limbs greater than the differing byte are equal.
            for j in (i + 1)..WORD_SIZE {
                builder
                    .when(local.differing_byte[i])
                    .assert_eq(local.b_word[j], local.c_word[j]);
            }
        }

        // Find out the most significant byte to compare.
        // Note that if all the bytes are equal, then b_byte and c_byte will
        // equal to zero.  That is fine, since the byte ltu lookup will constraint
        // the lt column to be false, which is what we want.
        let mut b_byte = AB::Expr::zero();
        let mut c_byte = AB::Expr::zero();
        for i in 0..WORD_SIZE {
            b_byte += local.b_word[i] * local.differing_byte[i];
            c_byte += local.c_word[i] * local.differing_byte[i];
        }
        builder.assert_eq(b_byte, local.b_byte);
        builder.assert_eq(c_byte, local.c_byte);

        // Do the byte ltu lookup
        builder.send_byte(
            ByteOpcode::LTU.to_field::<AB::F>(),
            local.lt,
            local.b_byte,
            local.c_byte,
            local.is_real,
        );

        builder.receive_field_op(local.lt, local.b, local.c, local.is_real);
    }
}
