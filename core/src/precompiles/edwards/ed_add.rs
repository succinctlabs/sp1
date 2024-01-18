use crate::air::CurtaAirBuilder;
use crate::operations::field::fp_den::FpDenCols;
use crate::operations::field::fp_inner_product::FpInnerProductCols;
use crate::operations::field::fp_op::FpOpCols;
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
    pub(crate) x3_numerator: FpInnerProductCols<T>,
    pub(crate) y3_numerator: FpInnerProductCols<T>,
    pub(crate) x1_mul_y1: FpOpCols<T>,
    pub(crate) x2_mul_y2: FpOpCols<T>,
    pub(crate) f: FpOpCols<T>,
    pub(crate) d_mul_f: FpOpCols<T>,
    pub(crate) x3_ins: FpDenCols<T>,
    pub(crate) y3_ins: FpDenCols<T>,
}

// impl<T> EdAddCols<T> {
//     pub fn result(&self) -> AffinePoint<T> {
//         AffinePoint {
//             x: self.x3_ins.result,
//             y: self.y3_ins.result,
//         }
//     }
// }

impl<F: Field> EdAddCols<F> {
    pub fn populate<P: FieldParameters>(&mut self) {
        todo!();
    }
}

impl<V: Copy> EdAddCols<V> {
    #[allow(unused_variables)]
    pub fn eval<AB: CurtaAirBuilder<Var = V>, P: FieldParameters>(
        &self,
        builder: &mut AB,
        p: &AffinePoint<AB::Var>,
        q: &AffinePoint<AB::Var>,
    ) where
        V: Into<AB::Expr>,
    {
        let x1 = p.x;
        let x2 = q.x;
        let y1 = p.y;
        let y2 = q.y;

        // x3_numerator = x1 * y2 + x2 * y1.
        self.x3_numerator
            .eval::<AB, P>(builder, &vec![x1, x2], &vec![y2, y1]);

        // y3_numerator = y1 * y2 + x1 * x2.
        self.y3_numerator
            .eval::<AB, P>(builder, &vec![y1, x1], &vec![y2, x2]);

        // TODO: fill in below

        // // f = x1 * x2 * y1 * y2.
        // let x1_mul_y1 = self.fp_mul(&x1, &y1);
        // let x2_mul_y2 = self.fp_mul(&x2, &y2);
        // let f = self.fp_mul(&x1_mul_y1, &x2_mul_y2);

        // // d * f.
        // let d_mul_f = self.fp_mul_const(&f, E::D);

        // // x3 = x3_numerator / (1 + d * f).
        // let x3_ins = self.fp_den(&x3_numerator, &d_mul_f, true);

        // // y3 = y3_numerator / (1 - d * f).
        // let y3_ins = self.fp_den(&y3_numerator, &d_mul_f, false);
    }
}
