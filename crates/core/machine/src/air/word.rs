use std::array;

use itertools::Itertools;
use p3_field::AbstractField;
use sp1_core_executor::ByteOpcode;
use sp1_primitives::consts::WORD_SIZE;
use sp1_stark::{air::ByteAirBuilder, Word};

pub trait WordAirBuilder: ByteAirBuilder {
    /// Asserts that the two words are equal.
    fn assert_word_eq(
        &mut self,
        left: Word<impl Into<Self::Expr>>,
        right: Word<impl Into<Self::Expr>>,
    ) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }

    /// Asserts that the word is zero.
    fn assert_word_zero(&mut self, word: Word<impl Into<Self::Expr>>) {
        for limb in word.0 {
            self.assert_zero(limb);
        }
    }

    /// Index an array of words using an index bitmap.
    fn index_word_array(
        &mut self,
        array: &[Word<impl Into<Self::Expr> + Clone>],
        index_bitmap: &[impl Into<Self::Expr> + Clone],
    ) -> Word<Self::Expr> {
        let mut result = Word::default();
        for i in 0..WORD_SIZE {
            result[i] = self.index_array(
                array.iter().map(|word| word[i].clone()).collect_vec().as_slice(),
                index_bitmap,
            );
        }
        result
    }

    /// Same as `if_else` above, but arguments are `Word` instead of individual expressions.
    fn select_word(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: Word<impl Into<Self::Expr> + Clone>,
        b: Word<impl Into<Self::Expr> + Clone>,
    ) -> Word<Self::Expr> {
        Word(array::from_fn(|i| self.if_else(condition.clone(), a[i].clone(), b[i].clone())))
    }

    /// Check that each limb of the given slice is a u8.
    fn slice_range_check_u8(
        &mut self,
        input: &[impl Into<Self::Expr> + Clone],
        mult: impl Into<Self::Expr> + Clone,
    ) {
        let mut index = 0;
        while index + 1 < input.len() {
            self.send_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                Self::Expr::zero(),
                input[index].clone(),
                input[index + 1].clone(),
                mult.clone(),
            );
            index += 2;
        }
        if index < input.len() {
            self.send_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                Self::Expr::zero(),
                input[index].clone(),
                Self::Expr::zero(),
                mult.clone(),
            );
        }
    }

    /// Check that each limb of the given slice is a u16.
    fn slice_range_check_u16(
        &mut self,
        input: &[impl Into<Self::Expr> + Copy],
        mult: impl Into<Self::Expr> + Clone,
    ) {
        input.iter().for_each(|limb| {
            self.send_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
                *limb,
                Self::Expr::zero(),
                Self::Expr::zero(),
                mult.clone(),
            );
        });
    }
}
