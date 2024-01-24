use crate::air::CurtaAirBuilder;
use crate::operations::field::fp_den::FpDenCols;
use crate::operations::field::fp_inner_product::FpInnerProductCols;
use crate::operations::field::fp_op::FpOpCols;
use crate::operations::field::fp_op::FpOperation;
use crate::operations::field::params::AffinePoint;
use crate::operations::field::params::FieldParameters;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_field::Field;
use std::fmt::Debug;
use valida_derive::AlignedBorrow;

/// A set of columns to compute `EdAdd` where a, b are field elements.
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed
/// or made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdAddCols<T> {
    pub p_ptr: T,
    // This is 8 elements, as it's 8 words for the 32 byte compressed point.
    pub p_access: [MemoryAccess<T>; 8],
    pub result: T,
    // This is 16 elements, 256 bits for each Edwards field element (2 * 256 / 32) = 16.
    pub result_access: [MemoryAccess<T>; 16],
    pub(crate) yy: FpOpCols<T>,
    pub(crate) u: FpOpCols<T>,
    pub(crate) dyy: FpOpCols<T>,
    pub(crate) v: FpOpCols<T>,
    pub(crate) u_div_v: FpOpCols<T>,
    pub(crate) x: FpOpCols<T>,
    pub(crate) neg_x: FpOpCols<T>,
}

impl<F: Field> EdAddCols<F> {
    pub fn populate<P: FieldParameters>(&mut self) {
        todo!();
    }
}

impl<V: Copy> EdAddCols<V> {
    #[allow(unused_variables)]
    pub fn eval<AB: CurtaAirBuilder<Var = V>, P: FieldParameters>(&self)
    where
        V: Into<AB::Expr>,
    {
        let x1 = p.x;
        let x2 = q.x;
        let y1 = p.y;
        let y2 = q.y;

        // self.yy.eval(builder, )

        // x3_numerator = x1 * y2 + x2 * y1.
        self.x3_numerator
            .eval::<AB, P>(builder, &[x1, x2], &[y2, y1]);

        // y3_numerator = y1 * y2 + x1 * x2.
        self.y3_numerator
            .eval::<AB, P>(builder, &[y1, x1], &[y2, x2]);

        // // f = x1 * x2 * y1 * y2.
        self.x1_mul_y1
            .eval::<AB, P>(builder, &x1, &y1, FpOperation::Mul);
        self.x2_mul_y2
            .eval::<AB, P>(builder, &x2, &y2, FpOperation::Mul);

        let x1_mul_y1 = self.x1_mul_y1.result;
        let x2_mul_y2 = self.x2_mul_y2.result;
        self.f
            .eval::<AB, P>(builder, &x1_mul_y1, &x2_mul_y2, FpOperation::Mul);

        // // d * f.
        let f = self.f.result;
        // let d_mul_f = self.fp_mul_const(&f, E::D);
        // TODO: put in E as a generic here
        // self.d_mul_f.eval::<AB, P>(builder, &f, E::D, FpOperation::Mul);

        let d_mul_f = self.d_mul_f.result;

        // // x3 = x3_numerator / (1 + d * f).
        self.x3_ins
            .eval::<AB, P>(builder, &self.x3_numerator.result, &d_mul_f, true);

        // // y3 = y3_numerator / (1 - d * f).
        self.y3_ins
            .eval::<AB, P>(builder, &self.y3_numerator.result, &d_mul_f, false);
    }
}
