use crate::air::CurtaAirBuilder;
use crate::operations::field::params::AffinePoint;
use p3_air::{Air, BaseAir};

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use super::ed_add::EdAddCols;
use p3_matrix::MatrixRowSlices;
use std::fmt::Debug;
use valida_derive::AlignedBorrow;

pub const NUM_ED_SCALAR_MUL_COLS: usize = size_of::<EdScalarMulCols<u8>>();

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdScalarMulCols<T> {
    pub cycle: T,
    pub bit: T,
    pub temp: AffinePoint<T>,
    pub result: AffinePoint<T>,
    pub result_plus_temp: EdAddCols<T>,
    pub temp_double: EdAddCols<T>,
    pub result_next: AffinePoint<T>, // TODO: we may not need this?
}

pub struct EdScalarMulChip;

impl<F> BaseAir<F> for EdScalarMulChip {
    fn width(&self) -> usize {
        NUM_ED_SCALAR_MUL_COLS
    }
}

impl<AB> Air<AB> for EdScalarMulChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let _: &EdScalarMulCols<AB::Var> = main.row_slice(0).borrow();
        let _: &EdScalarMulCols<AB::Var> = main.row_slice(1).borrow();
        todo!();
    }
}
