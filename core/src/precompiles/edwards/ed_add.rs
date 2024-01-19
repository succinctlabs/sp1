use crate::air::CurtaAirBuilder;
use crate::cpu::air::MemoryAccessCols;
use crate::cpu::air::MemoryReadCols;
use crate::operations::field::fp_den::FpDenCols;
use crate::operations::field::fp_inner_product::FpInnerProductCols;
use crate::operations::field::fp_op::FpOpCols;
use crate::operations::field::fp_op::FpOperation;
use crate::operations::field::params::AffinePoint;
use crate::operations::field::params::FieldParameters;
use crate::operations::field::params::Limbs;
use crate::operations::field::params::NUM_LIMBS;
use crate::runtime::Runtime;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_field::Field;
use std::fmt::Debug;
use valida_derive::AlignedBorrow;

#[derive(Debug, Clone, Copy)]
pub struct EdAddEvent {
    pub clk: u32,
    pub p_ptr: u32,
    pub p: [u32; 26],
    pub q_ptr: u32,
    pub q: [u32; 16],
}

// NUM_LIMBS = 32 -> 32 / 4 = 8 Words
// 2 Limbs<> per affine point => 16 words

/// A set of columns to compute `EdAdd` where a, b are field elements.
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed
/// or made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdAddAssignCols<T> {
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: [MemoryAccessCols<T>; 16],
    pub q_access: [MemoryReadCols<T>; 16],
    pub(crate) x3_numerator: FpInnerProductCols<T>,
    pub(crate) y3_numerator: FpInnerProductCols<T>,
    pub(crate) x1_mul_y1: FpOpCols<T>,
    pub(crate) x2_mul_y2: FpOpCols<T>,
    pub(crate) f: FpOpCols<T>,
    pub(crate) d_mul_f: FpOpCols<T>,
    pub(crate) x3_ins: FpDenCols<T>,
    pub(crate) y3_ins: FpDenCols<T>,
}

impl<T: Copy> EdAddAssignCols<T> {
    pub fn result(&self) -> AffinePoint<T> {
        AffinePoint {
            x: self.x3_ins.result,
            y: self.y3_ins.result,
        }
    }

    pub fn limbs_from_read(cols: &[MemoryReadCols<T>]) -> Limbs<T> {
        let vec = cols
            .into_iter()
            .flat_map(|access| access.value.0)
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), NUM_LIMBS);

        // let sized = &vec.as_slice()[..NUM_LIMBS];
        // Limbs(sized);
        todo!();
    }

    pub fn limbs_from_access(cols: &[MemoryAccessCols<T>]) -> Limbs<T> {
        let vec = cols
            .into_iter()
            .flat_map(|access| access.prev_value.0)
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), NUM_LIMBS);

        // let sized = &vec.as_slice()[..NUM_LIMBS];
        // Limbs(sized);
        todo!();
    }
}

pub struct EdAddAssignChip<P: FieldParameters> {
    pub _phantom: std::marker::PhantomData<P>,
}

impl<P: FieldParameters> EdAddAssignChip<P> {
    pub fn execute(&mut runtime: Runtime) -> (u32, u32, u32) {
        // TODO: grab all of the data and push it to the segment
        // TODO: construct the EdAddEvent and push it to the segment
        // Include all of the data in the event, like the clk, base_ptr, etc.
    }
}

impl<F: Field, P: FieldParameters> Chip<F> for EdAddAssignChip<P> {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        for i in 0..segment.ed_add_events.len() {
            let mut event = segment.ed_add_events[i].clone();
            let p = &mut event.p;
            let q = &mut event.q;
            for j in 0..48usize {
                let mut row = [F::zero(); NUM_ED_ADD_COLS];
                let cols: &mut EdAddAssignCols<F> = unsafe { transmute(&mut row) };

                cols.segment = F::one();
                cols.clk = F::from_canonical_u32(event.clk);
                cols.q_ptr = F::from_canonical_u32(event.q_ptr);
                cols.p_ptr = F::from_canonical_u32(event.p_ptr);

                for i in 0..16 {
                    self.populate_access(&mut cols.p_access[i], p[i], event.p_records[i]);
                    self.populate_access(&mut cols.q_access[i], q[i], event.q_records[i]);
                }
            }
        }

        RowMajorMatrix::new(rows)
    }
}

impl<V: Copy> EdAddAssignCols<V> {
    #[allow(unused_variables)]
    pub fn eval<AB: CurtaAirBuilder<Var = V>, P: FieldParameters>(&self, builder: &mut AB)
    where
        V: Into<AB::Expr>,
    {
        let x1 = EdAddAssignCols::limbs_from_access(&self.p_access[0..32]);
        let x2 = EdAddAssignCols::limbs_from_read(&self.q_access[0..32]);
        let y1 = EdAddAssignCols::limbs_from_access(&self.p_access[32..64]);
        let y2 = EdAddAssignCols::limbs_from_read(&self.q_access[32..64]);

        // x3_numerator = x1 * y2 + x2 * y1.
        self.x3_numerator
            .eval::<AB, P>(builder, &vec![x1, x2], &vec![y2, y1]);

        // y3_numerator = y1 * y2 + x1 * x2.
        self.y3_numerator
            .eval::<AB, P>(builder, &vec![y1, x1], &vec![y2, x2]);

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

        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]
        // This is to ensure that p_access is updated with the new value.
        for i in 0..NUM_LIMBS {
            builder.assert_eq(self.x3_ins.result[i], self.p_access[i / 4].value[i % 4]);
            builder.assert_eq(self.y3_ins.result[i], self.p_access[8 + i / 4].value[i % 4]);
        }
    }
}
