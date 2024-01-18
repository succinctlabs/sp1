use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use core::mem::transmute;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::Field;
use p3_matrix::MatrixRowSlices;
use p3_util::indices_arr;
use valida_derive::AlignedBorrow;

use crate::air::{CurtaAirBuilder, Word, WORD_SIZE};
use crate::bytes::ByteOpcode;

use super::FieldChip;

pub const NUM_FIELD_COLS: usize = size_of::<FieldCols<u8>>();
pub(crate) const FIELD_COL_MAP: FieldCols<usize> = make_col_map();

const fn make_col_map() -> FieldCols<usize> {
    let indices_arr = indices_arr::<NUM_FIELD_COLS>();
    unsafe { transmute::<[usize; NUM_FIELD_COLS], FieldCols<usize>>(indices_arr) }
}

#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct FieldCols<T> {
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

    pub b_byte: T,
    pub c_byte: T,

    // pub multiplicities: T,
    pub is_real: T,
}

impl<F: Field> BaseAir<F> for FieldChip {
    fn width(&self) -> usize {
        NUM_FIELD_COLS
    }
}

impl<AB: CurtaAirBuilder> Air<AB> for FieldChip {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &FieldCols<AB::Var> = main.row_slice(0).borrow();

        // Dummy constraint for normalizing to degree 3.
        builder.assert_eq(local.b * local.b * local.b, local.b * local.b * local.b);

        // Verify that lt is a boolean.
        builder.assert_bool(local.lt);

        // Verify that the word representation of b and c are correct.
        builder.assert_eq(Word::reduce::<AB>(&local.b_word), local.b);
        builder.assert_eq(Word::reduce::<AB>(&local.c_word), local.c);

        // Check the validity of the differing byte bitmap.
        for i in 0..WORD_SIZE {
            builder.assert_bool(local.differing_byte[i]);
        }

        let bitmap_sum = local
            .differing_byte
            .iter()
            .fold(AB::Expr::zero(), |acc, x| acc + *x);
        // Verify bitmap sum is 0 or 1
        builder.assert_eq(
            bitmap_sum.clone() * (bitmap_sum - AB::Expr::one()),
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

        // Byte to compare
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
    }
}
