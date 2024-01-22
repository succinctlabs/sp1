use crate::air::CurtaAirBuilder;
use crate::cpu::cols::cpu_cols::MemoryAccessCols;
use crate::cpu::MemoryRecord;
use crate::operations::field::fp_den::FpDenCols;
use crate::operations::field::fp_inner_product::FpInnerProductCols;
use crate::operations::field::fp_op::FpOpCols;
use crate::operations::field::fp_op::FpOperation;
use crate::operations::field::params::AffinePoint;
use crate::operations::field::params::Ed25519BaseField;
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
use num::BigUint;
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
    pub p_memory_records: [MemoryRecord; 16],
    pub q_memory_records: [MemoryRecord; 16],
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
    pub q_access: [MemoryAccessCols<T>; 16],
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

    // pub fn limbs_from_read(cols: &[MemoryReadCols<T>]) -> Limbs<T> {
    //     let vec = cols
    //         .into_iter()
    //         .flat_map(|access| access.value.0)
    //         .collect::<Vec<_>>();
    //     assert_eq!(vec.len(), NUM_LIMBS);

    //     // let sized = &vec.as_slice()[..NUM_LIMBS];
    //     // Limbs(sized);
    //     todo!();
    // }

    pub fn limbs_from_access(cols: &[MemoryAccessCols<T>]) -> Limbs<T> {
        let vec = cols
            .iter()
            .flat_map(|access| access.prev_value.0)
            .collect::<Vec<_>>();
        assert_eq!(vec.len(), NUM_LIMBS);

        // let sized = &vec.as_slice()[..NUM_LIMBS];
        // Limbs(sized);
        todo!();
    }
}

pub struct EdAddAssignChip {}

impl EdAddAssignChip {
    const D: [u16; 32] = [
        30883, 4953, 19914, 30187, 55467, 16705, 2637, 112, 59544, 30585, 16505, 36039, 65139,
        11119, 27886, 20995, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    fn d_biguint() -> BigUint {
        let mut modulus = BigUint::from(0_u32);
        for (i, limb) in Self::D.iter().enumerate() {
            modulus += BigUint::from(*limb) << (16 * i);
        }
        modulus
    }

    pub fn execute(rt: &mut Runtime) -> (u32, u32, u32) {
        // Initialize the registers.
        let t0 = Register::X5;
        let a0 = Register::X10;
        let a1 = Register::X11;

        let opcode = rt.rr(t0, AccessPosition::A);
        let p_ptr = rt.rr(a0, AccessPosition::B);
        let q_ptr = rt.rr(a1, AccessPosition::C);

        // Preserve record for cpu event. It just has p/q + opcode reads.
        let record = rt.record;

        rt.clk += 4;

        let mut p = [0; 16];
        for i in 0..16 {
            // p[i] = rt.mr(p_ptr + (i as u32) * 4, AccessPosition::Memory);
            // p_read_records[i] = rt.record.memory.unwrap();
            // rt.clk += 4;
            p[i] = rt.word(p_ptr + (i as u32) * 4);
        }

        let mut q = [0; 16];
        let mut q_memory_records = [MemoryRecord::default(); 16];
        for i in 0..16 {
            q[i] = rt.mr(q_ptr + (i as u32) * 4, AccessPosition::Memory);
            q_memory_records[i] = rt.record.memory.unwrap();
            rt.clk += 4;
        }

        let p_x = BigUint::from_slice(&p[0..8]);
        let p_y = BigUint::from_slice(&p[8..16]);
        let q_x = BigUint::from_slice(&q[0..8]);
        let q_y = BigUint::from_slice(&q[8..16]);

        let x3_numerator = p_x.clone() * q_y.clone() + q_x.clone() * p_y.clone();
        let y3_numerator = p_y.clone() * q_y.clone() + p_x.clone() * q_x.clone();
        let f = p_x * q_x * p_y * q_y;
        let d_bigint = BigUint::from_bytes_le(&Ed25519BaseField::MODULUS);
        let d_mul_f = f * d_bigint;
        let one_bigint = BigUint::from(1_u32);
        let one_plus_d_mul_f = one_bigint + d_mul_f;
        let x3 = x3_numerator / (one_plus_d_mul_f.clone());
        let y3 = y3_numerator / one_plus_d_mul_f;

        let x3_limbs = x3.to_bytes_le();
        let y3_limbs = y3.to_bytes_le();

        // Create p memory records that read the values of p and write the values of x3 and y3.
        let mut p_memory_records = [MemoryRecord::default(); 16];

        for i in 0..8 {
            let u32_array: [u8; 4] = x3_limbs[i * 4..(i + 1) * 4].try_into().unwrap();
            let u32_value: u32 = unsafe { std::mem::transmute(u32_array) };
            rt.mw(p_ptr + (i as u32) * 4, u32_value, AccessPosition::Memory);
            p_memory_records[i] = rt.record.memory.unwrap();
            rt.clk += 4;
        }
        for i in 0..8 {
            let u32_array: [u8; 4] = y3_limbs[i * 4..(i + 1) * 4].try_into().unwrap();
            let u32_value: u32 = unsafe { std::mem::transmute(u32_array) };
            rt.mw(
                p_ptr + (i as u32 + 8) * 4,
                u32_value,
                AccessPosition::Memory,
            );
            p_memory_records[8 + i] = rt.record.memory.unwrap();
            rt.clk += 4;
        }

        rt.segment.ed_add_events.push(EdAddEvent {
            clk: rt.clk,
            p_ptr,
            p,
            q_ptr,
            q,
            p_memory_records,
            q_memory_records,
        });

        // Restore record
        rt.record = record;
        (p_ptr, opcode, q_ptr)
    }
}

impl<F: Field> Chip<F> for EdAddAssignChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let mut new_field_events = Vec::new();

        for i in 0..segment.ed_add_events.len() {
            let event = segment.ed_add_events[i];
            let mut row = [F::zero(); NUM_ED_ADD_COLS];
            let cols: &mut EdAddAssignCols<F> = unsafe { std::mem::transmute(&mut row) };
            cols.clk = F::from_canonical_u32(event.clk);
            cols.p_ptr = F::from_canonical_u32(event.p_ptr);
            cols.q_ptr = F::from_canonical_u32(event.q_ptr);
            for i in 0..16 {
                let q_record = MemoryRecord {
                    value: event.q[i],
                    segment: segment.index,
                    timestamp: event.clk + 4 * (i as u32 + 1),
                };
                self.populate_access(
                    &mut cols.q_access[i],
                    q_record,
                    Some(event.q_memory_records[i]),
                    &mut new_field_events,
                );
            }
            let p = &event.p;
            let q = &event.q;
            let p_x = BigUint::from_slice(&p[0..8]);
            let p_y = BigUint::from_slice(&p[8..16]);
            let q_x = BigUint::from_slice(&q[0..8]);
            let q_y = BigUint::from_slice(&q[8..16]);
            let x3_numerator = cols.x3_numerator.populate::<Ed25519BaseField>(
                &vec![p_x.clone(), q_x.clone()],
                &vec![p_y.clone(), q_y.clone()],
            );
            let y3_numerator = cols.y3_numerator.populate::<Ed25519BaseField>(
                &vec![p_y.clone(), p_x.clone()],
                &vec![q_y.clone(), q_x.clone()],
            );
            let x1_mul_y1 =
                cols.x1_mul_y1
                    .populate::<Ed25519BaseField>(&p_x, &p_y, FpOperation::Mul);
            let x2_mul_y2 =
                cols.x2_mul_y2
                    .populate::<Ed25519BaseField>(&q_x, &q_y, FpOperation::Mul);
            let f = cols
                .f
                .populate::<Ed25519BaseField>(&x1_mul_y1, &x2_mul_y2, FpOperation::Mul);

            let d = BigUint::from_bytes_le(&Ed25519BaseField::MODULUS);
            let d_mul_f = cols
                .d_mul_f
                .populate::<Ed25519BaseField>(&f, &d, FpOperation::Mul);

            let x3_ins = cols
                .x3_ins
                .populate::<Ed25519BaseField>(&x3_numerator, &d_mul_f, true);
            let y3_ins = cols
                .y3_ins
                .populate::<Ed25519BaseField>(&y3_numerator, &d_mul_f, false);

            let x3_limbs = x3_ins.to_bytes_le();
            let y3_limbs = y3_ins.to_bytes_le();
            for i in 0..8 {
                // let p_record = MemoryRecord {
                //     value: event.p[i],
                //     segment: segment.index,
                //     timestamp: event.clk + 4 * (i as u32 + 1),
                // };
                // self.populate_access(
                //     &mut cols.p_access[i],
                //     p_record,
                //     Some(event.p_memory_records[i]),
                //     &mut new_field_events,
                // );
                let x3_array: [u8; 4] = x3_limbs[i * 4..(i + 1) * 4].try_into().unwrap();
                let x3_value: u32 = unsafe { std::mem::transmute(x3_array) };
                let x3_write_record = MemoryRecord {
                    value: x3_value,
                    segment: segment.index,
                    timestamp: event.clk + 4 * (i as u32 + 17),
                };
                self.populate_access(
                    &mut cols.p_access[i],
                    x3_write_record,
                    Some(event.p_memory_records[i]),
                    &mut new_field_events,
                );
                let y3_array: [u8; 4] = y3_limbs[i * 4..(i + 1) * 4].try_into().unwrap();
                let y3_value: u32 = unsafe { std::mem::transmute(y3_array) };
                let y3_write_record = MemoryRecord {
                    value: y3_value,
                    segment: segment.index,
                    timestamp: event.clk + 4 * (i as u32 + 25),
                };
                self.populate_access(
                    &mut cols.p_access[8 + i],
                    y3_write_record,
                    Some(event.p_memory_records[8 + i]),
                    &mut new_field_events,
                );
            }

            rows.push(row);
        }
        segment.field_events.extend(new_field_events);

        // for i in 0..segment.ed_add_events.len() {
        //     let mut event = segment.ed_add_events[i].clone();
        //     let p = &mut event.p;
        //     let q = &mut event.q;
        //     for j in 0..48usize {
        //         let mut row = [F::zero(); NUM_ED_ADD_COLS];
        //         let cols: &mut EdAddAssignCols<F> = unsafe { std::mem::transmute(&mut row) };

        //         cols.clk = F::from_canonical_u32(event.clk);
        //         cols.q_ptr = F::from_canonical_u32(event.q_ptr);
        //         cols.p_ptr = F::from_canonical_u32(event.p_ptr);
        //         // let p_x = BigUint::from_limbs(...);
        //         // let p_y = BigUint::from_limbs(...);
        //         // let q_x = BigUint::from_limbs(...);
        //         // let q_y = BigUint::from_limbs(...);
        //         // cols.x3_numerator.populate(p_x, p_y);

        //         // for i in 0..16 {
        //         //     self.populate_access(&mut cols.p_access[i], p[i], event.p_records[i]);
        //         //     self.populate_access(&mut cols.q_access[i], q[i], event.q_records[i]);
        //         // }
        //     }
        // }

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_ED_ADD_COLS,
        )
    }
}

impl<F> BaseAir<F> for EdAddAssignChip {
    fn width(&self) -> usize {
        NUM_ED_ADD_COLS
    }
}

impl<AB> Air<AB> for EdAddAssignChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row: &EdAddAssignCols<AB::Var> = main.row_slice(0).borrow();

        let x1 = EdAddAssignCols::limbs_from_access(&row.p_access[0..8]);
        let x2 = EdAddAssignCols::limbs_from_access(&row.q_access[0..8]);
        // let x2 = EdAddAssignCols::limbs_from_read(&self.q_access[0..32]);
        let y1 = EdAddAssignCols::limbs_from_access(&row.p_access[8..16]);
        let y2 = EdAddAssignCols::limbs_from_access(&row.q_access[8..16]);
        // let y2 = EdAddAssignCols::limbs_from_read(&self.q_access[32..64]);

        // x3_numerator = x1 * y2 + x2 * y1.
        row.x3_numerator
            .eval::<AB, Ed25519BaseField>(builder, &[x1, x2], &[y2, y1]);

        // y3_numerator = y1 * y2 + x1 * x2.
        row.y3_numerator
            .eval::<AB, Ed25519BaseField>(builder, &[y1, x1], &[y2, x2]);

        // // f = x1 * x2 * y1 * y2.
        row.x1_mul_y1
            .eval::<AB, Ed25519BaseField>(builder, &x1, &y1, FpOperation::Mul);
        row.x2_mul_y2
            .eval::<AB, Ed25519BaseField>(builder, &x2, &y2, FpOperation::Mul);

        let x1_mul_y1 = row.x1_mul_y1.result;
        let x2_mul_y2 = row.x2_mul_y2.result;
        row.f
            .eval::<AB, Ed25519BaseField>(builder, &x1_mul_y1, &x2_mul_y2, FpOperation::Mul);

        // // d * f.
        let f = row.f.result;
        // TODO: put in E::D as a generic here
        // 37095705934669439343138083508754565189542113879843219016388785533085940283555
        // let d_const = Ed25519BaseField::to_limbs_field(&EdAddAssignChip::d_biguint());
        // row.d_mul_f
        //     .eval::<AB, Ed25519BaseField>(builder, &f, &d_const, FpOperation::Mul);
        let d_mul_f = row.d_mul_f.result;

        // // x3 = x3_numerator / (1 + d * f).
        row.x3_ins
            .eval::<AB, Ed25519BaseField>(builder, &row.x3_numerator.result, &d_mul_f, true);

        // // y3 = y3_numerator / (1 - d * f).
        row.y3_ins
            .eval::<AB, Ed25519BaseField>(builder, &row.y3_numerator.result, &d_mul_f, false);

        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]
        // This is to ensure that p_access is updated with the new value.
        for i in 0..NUM_LIMBS {
            builder.assert_eq(row.x3_ins.result[i], row.p_access[i / 4].value[i % 4]);
            builder.assert_eq(row.y3_ins.result[i], row.p_access[8 + i / 4].value[i % 4]);
        }
    }
}

// impl<V: Copy + Field> EdAddAssignCols<V> {
//     #[allow(unused_variables)]
//     pub fn eval<AB: CurtaAirBuilder<Var = V>>(&self, builder: &mut AB)
//     where
//         V: Into<AB::Expr>,
//     {
//     }
// }
