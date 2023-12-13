//! A chip that implements bitwise operations for XOR, XORI, OR, ORI, AND, and ANDI.

use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_matrix::MatrixRowSlices;
use valida_derive::AlignedBorrow;

use crate::air::Word;
use crate::alu::indices_arr;

#[derive(AlignedBorrow, Default)]
pub struct BitwiseCols<T> {
    pub a: Word<T>,
    pub b: Word<T>,
    pub c: Word<T>,

    pub b_bits: [[T; 8]; 4],
    pub c_bits: [[T; 8]; 4],

    pub is_xor: T,
    pub is_or: T,
    pub is_and: T,
}

pub const NUM_ADD_COLS: usize = size_of::<BitwiseCols<u8>>();
pub const ADD_COL_MAP: BitwiseCols<usize> = make_col_map();

const fn make_col_map() -> BitwiseCols<usize> {
    let indices_arr = indices_arr::<NUM_ADD_COLS>();
    unsafe { transmute::<[usize; NUM_ADD_COLS], BitwiseCols<usize>>(indices_arr) }
}

pub struct AddChip;

impl<F> BaseAir<F> for AddChip {
    fn width(&self) -> usize {
        NUM_ADD_COLS
    }
}

impl<F, AB> Air<AB> for AddChip
where
    F: PrimeField,
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &BitwiseCols<AB::Var> = main.row_slice(0).borrow();

        let two = AB::F::from_canonical_u32(2);

        // Check that the bits of the operands are correct.
        for i in 0..4 {
            let mut b_sum = AB::Expr::zero();
            let mut c_sum = AB::Expr::zero();
            let mut power = AB::F::one();
            for j in 0..8 {
                builder.assert_bool(local.b_bits[i][j]);
                builder.assert_bool(local.c_bits[i][j]);
                b_sum += local.b_bits[i][j] * power;
                c_sum += local.b_bits[i][j] * power;
                power *= two;
            }
            builder.assert_zero(b_sum - local.b[i]);
            builder.assert_zero(c_sum - local.c[i]);
        }

        // Constrain is_xor, is_or, and is_and to be bits and that only at most one is enabled.
        builder.assert_bool(local.is_xor);
        builder.assert_bool(local.is_or);
        builder.assert_bool(local.is_and);
        builder.assert_bool(local.is_xor + local.is_or + local.is_and);

        // Constrain the bitwise operation.
        for i in 0..4 {
            let mut xor = AB::Expr::zero();
            let mut or = AB::Expr::zero();
            let mut and = AB::Expr::zero();
            let mut power = AB::F::one();
            for j in 0..8 {
                xor += (local.b_bits[i][j] + local.c_bits[i][j]
                    - local.b_bits[i][j] * local.c_bits[i][j] * two)
                    * power;
                or += (local.b_bits[i][j] + local.c_bits[i][j]
                    - local.b_bits[i][j] * local.c_bits[i][j])
                    * power;
                and += local.b_bits[i][j] * local.c_bits[i][j] * power;
                power *= two;
            }
            builder.when(local.is_xor).assert_zero(xor - local.a[i]);
            builder.when(local.is_or).assert_zero(or - local.a[i]);
            builder.when(local.is_and).assert_zero(and - local.a[i]);
        }

        todo!()
    }
}
