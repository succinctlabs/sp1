//! A chip that implements addition for ADD and ADDI.

use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use valida_derive::AlignedBorrow;

use crate::air::Word;
use crate::alu::indices_arr;
use crate::Runtime;

use super::{AluEvent, Chip};

#[derive(AlignedBorrow, Default)]
pub struct AddCols<T> {
    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Trace.
    pub carry: [T; 3],
}

pub const NUM_ADD_COLS: usize = size_of::<AddCols<u8>>();
pub const ADD_COL_MAP: AddCols<usize> = make_col_map();

const fn make_col_map() -> AddCols<usize> {
    let indices_arr = indices_arr::<NUM_ADD_COLS>();
    unsafe { transmute::<[usize; NUM_ADD_COLS], AddCols<usize>>(indices_arr) }
}

pub struct AddChip {
    events: Vec<AluEvent>,
}

impl<F: PrimeField> Chip<F> for AddChip {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        let mut row = [F::zero(); NUM_ADD_COLS];
        self.events.par_iter().map(|event| {});
        todo!()
    }
}

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
        let local: &AddCols<AB::Var> = main.row_slice(0).borrow();

        let one = AB::F::one();
        let base = AB::F::from_canonical_u32(1 << 8);

        // For each limb, assert that difference between the carried result and the non-carried
        // result is either zero or the base.
        let overflow_0 = local.b[0] + local.c[0] - local.a[0];
        let overflow_1 = local.b[1] + local.c[1] - local.a[1] + local.carry[0];
        let overflow_2 = local.b[2] + local.c[2] - local.a[2] + local.carry[1];
        let overflow_3 = local.b[3] + local.c[3] - local.a[3] + local.carry[2];
        builder.assert_zero(overflow_0.clone() * (overflow_0.clone() - base));
        builder.assert_zero(overflow_1.clone() * (overflow_1.clone() - base));
        builder.assert_zero(overflow_2.clone() * (overflow_2.clone() - base));
        builder.assert_zero(overflow_3.clone() * (overflow_3.clone() - base));

        // If the carry is one, then the overflow must be the base.
        builder.assert_zero(local.carry[0] * (overflow_0.clone() - base.clone()));
        builder.assert_zero(local.carry[1] * (overflow_1.clone() - base.clone()));
        builder.assert_zero(local.carry[2] * (overflow_2.clone() - base.clone()));

        // If the carry is not one, then the overflow must be zero.
        builder.assert_zero((local.carry[0] - one) * overflow_0.clone());
        builder.assert_zero((local.carry[1] - one) * overflow_1.clone());
        builder.assert_zero((local.carry[2] - one) * overflow_2.clone());

        // Assert that the carry is either zero or one.
        builder.assert_bool(local.carry[0]);
        builder.assert_bool(local.carry[1]);
        builder.assert_bool(local.carry[2]);

        todo!()
    }
}
