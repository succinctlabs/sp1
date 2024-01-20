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
use crate::runtime::AccessPosition;
use crate::runtime::Register;
use crate::runtime::Runtime;
use crate::runtime::Segment;
use crate::utils::Chip;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use std::fmt::Debug;
use valida_derive::AlignedBorrow;

#[derive(Debug, Clone, Copy)]
pub struct EdAddEvent {
    pub clk: u32,
    pub p_ptr: u32,
    pub p: [u32; 16],
    pub q_ptr: u32,
    pub q: [u32; 16],
}

// NUM_LIMBS = 32 -> 32 / 4 = 8 Words
// 2 Limbs<> per affine point => 16 words

pub const NUM_ED_ADD_COLS: usize = size_of::<EdAddAssignCols<u8>>();

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
    pub fn execute(rt: &mut Runtime) -> (u32, u32, u32) {
        todo!()
        // TODO: grab all of the data and push it to the segment
        // TODO: construct the EdAddEvent and push it to the segment
        // Include all of the data in the event, like the clk, base_ptr, etc.

        // The number of cycles it takes to perform this precompile.
        // const NB_SHA_EXTEND_CYCLES: u32 = 48 * 20;

        // // Initialize the registers.
        let t0 = Register::X5;
        let a0 = Register::X10;
        let a1 = Register::X11;

        // // Temporarily set the clock to the number of cycles it takes to perform this precompile as
        // // reading `w_ptr` happens on this clock.
        // rt.clk += NB_SHA_EXTEND_CYCLES;

        // // Read `w_ptr` from register a0 or x5.
        let p_ptr = rt.register(a0);
        let q_ptr = rt.register(a1);
        // let w: [u32; 64] = (0..64)
        //     .map(|i| rt.word(w_ptr + i * 4))
        //     .collect::<Vec<_>>()
        //     .try_into()
        //     .unwrap();

        // // Set the CPU table values with some dummy values.
        // let (a, b, c) = (w_ptr, rt.rr(t0, AccessPosition::B), 0);
        // rt.rw(a0, a);

        // // We'll save the current record and restore it later so that the CPU event gets emitted
        // // correctly.
        // let t = rt.record;


        let p_read_records = Vec::new();
        for i in 0..16 {
            let p_access = rt.mr(p_ptr + i * 4, AccessPosition::Memory);
            p_read_records.push(rt.record.memory);
            rt.clk += 4;
        }

        let q_read_records = Vec::new();
        for i in 0..16 {
            let q_access = rt.mr(q_ptr + i * 4, AccessPosition::Memory);
            q_read_records.push(rt.record.memory);
            rt.clk += 4;
        }
        



        // // Set the clock back to the original value and begin executing the precompile.
        // rt.clk -= NB_SHA_EXTEND_CYCLES;
        // let clk_init = rt.clk;
        // let w_ptr_init = w_ptr;
        // let w_init = w.clone();
        // let mut w_i_minus_15_reads = Vec::new();
        // let mut w_i_minus_2_reads = Vec::new();
        // let mut w_i_minus_16_reads = Vec::new();
        // let mut w_i_minus_7_reads = Vec::new();
        // let mut w_i_writes = Vec::new();
        // for i in 16..64 {
        //     // Read w[i-15].
        //     let w_i_minus_15 = rt.mr(w_ptr + (i - 15) * 4, AccessPosition::Memory);
        //     w_i_minus_15_reads.push(rt.record.memory);
        //     rt.clk += 4;

        //     // Compute `s0`.
        //     let s0 =
        //         w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18) ^ (w_i_minus_15 >> 3);

        //     // Read w[i-2].
        //     let w_i_minus_2 = rt.mr(w_ptr + (i - 2) * 4, AccessPosition::Memory);
        //     w_i_minus_2_reads.push(rt.record.memory);
        //     rt.clk += 4;

        //     // Compute `s1`.
        //     let s1 =
        //         w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19) ^ (w_i_minus_2 >> 10);

        //     // Read w[i-16].
        //     let w_i_minus_16 = rt.mr(w_ptr + (i - 16) * 4, AccessPosition::Memory);
        //     w_i_minus_16_reads.push(rt.record.memory);
        //     rt.clk += 4;

        //     // Read w[i-7].
        //     let w_i_minus_7 = rt.mr(w_ptr + (i - 7) * 4, AccessPosition::Memory);
        //     w_i_minus_7_reads.push(rt.record.memory);
        //     rt.clk += 4;

        //     // Compute `w_i`.
        //     let w_i = s1
        //         .wrapping_add(w_i_minus_16)
        //         .wrapping_add(s0)
        //         .wrapping_add(w_i_minus_7);

        //     // Write w[i].
        //     rt.mr(w_ptr + i * 4, AccessPosition::Memory);
        //     rt.mw(w_ptr + i * 4, w_i, AccessPosition::Memory);
        //     w_i_writes.push(rt.record.memory);
        //     rt.clk += 4;
        // }

        // // Push the SHA extend event.
        // rt.segment.sha_extend_events.push(ShaExtendEvent {
        //     clk: clk_init,
        //     w_ptr: w_ptr_init,
        //     w: w_init,
        //     w_i_minus_15_reads: w_i_minus_15_reads.try_into().unwrap(),
        //     w_i_minus_2_reads: w_i_minus_2_reads.try_into().unwrap(),
        //     w_i_minus_16_reads: w_i_minus_16_reads.try_into().unwrap(),
        //     w_i_minus_7_reads: w_i_minus_7_reads.try_into().unwrap(),
        //     w_i_writes: w_i_writes.try_into().unwrap(),
        // });

        // // Restore the original record.
        // rt.record = t;

        // (a, b, c)
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
                let cols: &mut EdAddAssignCols<F> = unsafe { std::mem::transmute(&mut row) };

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

impl<F, P: FieldParameters> BaseAir<F> for EdAddAssignChip<P> {
    fn width(&self) -> usize {
        NUM_ED_ADD_COLS
    }
}

impl<AB, P: FieldParameters> Air<AB> for EdAddAssignChip<P>
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let _: &EdAddAssignCols<AB::Var> = main.row_slice(0).borrow();
        let _: &EdAddAssignCols<AB::Var> = main.row_slice(1).borrow();
        todo!();
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
