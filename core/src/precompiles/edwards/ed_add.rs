use crate::air::CurtaAirBuilder;
use crate::air::Word;
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
use num::Zero;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
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
    pub q_ptr_record: MemoryRecord,
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
    pub is_real: T,
    pub segment: T,
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub q_ptr_access: MemoryAccessCols<T>,
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

    pub fn limbs_from_access(cols: &[MemoryAccessCols<T>]) -> Limbs<T> {
        let vec = cols
            .iter()
            .flat_map(|access| access.prev_value.0)
            .collect::<Vec<T>>();
        assert_eq!(vec.len(), NUM_LIMBS);

        let sized = vec
            .try_into()
            .unwrap_or_else(|_| panic!("failed to convert to limbs"));
        Limbs(sized)
    }
}

pub struct EdAddAssignChip {}

impl EdAddAssignChip {
    const D: [u16; 32] = [
        30883, 4953, 19914, 30187, 55467, 16705, 2637, 112, 59544, 30585, 16505, 36039, 65139,
        11119, 27886, 20995, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    pub fn new() -> Self {
        Self {}
    }

    fn d_biguint() -> BigUint {
        let mut modulus = BigUint::from(0_u32);
        for (i, limb) in Self::D.iter().enumerate() {
            modulus += BigUint::from(*limb) << (16 * i);
        }
        modulus
    }

    const NB_ED_ADD_CYCLES: u32 = 8;

    pub fn execute(rt: &mut Runtime) -> (u32, u32, u32) {
        // Initialize the registers.
        let t0 = Register::X5;
        let a0 = Register::X10;
        let a1 = Register::X11;

        // We have to forward the clk because the memory access in the CPU table should end at that clk cycle
        rt.clk += Self::NB_ED_ADD_CYCLES;

        // These reads are happening in the CPU table
        // So we have to make sure that it's set up properly for the ecall

        let opcode = rt.rr(t0, AccessPosition::B);
        let p_ptr = rt.register(a0);
        rt.rw(a0, p_ptr);

        // Preserve record for cpu event. It just has p/q + opcode reads.
        let record = rt.record;

        rt.clk -= Self::NB_ED_ADD_CYCLES;

        let q_ptr = rt.rr(a1, AccessPosition::C);
        rt.mw(a1 as u32, q_ptr, AccessPosition::C);
        let q_ptr_record = *rt.record.c.as_ref().unwrap();

        let mut p = [0; 16];
        for (i, item) in p.iter_mut().enumerate() {
            *item = rt.word(p_ptr + (i as u32) * 4);
        }

        let mut q = [0; 16];
        let mut q_memory_records = [MemoryRecord::default(); 16];
        for i in 0..16 {
            q[i] = rt.mr(q_ptr + (i as u32) * 4, AccessPosition::Memory);
            q_memory_records[i] = *rt.record.memory.as_ref().unwrap();
        }
        rt.clk += 4;

        let p_bytes: [u8; 64] = unsafe { std::mem::transmute(p) };
        let q_bytes: [u8; 64] = unsafe { std::mem::transmute(q) };

        let p_x = BigUint::from_bytes_le(&p_bytes[0..32]);
        let p_y = BigUint::from_bytes_le(&p_bytes[32..64]);
        let q_x = BigUint::from_bytes_le(&q_bytes[0..32]);
        let q_y = BigUint::from_bytes_le(&q_bytes[32..64]);

        let modulus = Ed25519BaseField::modulus();
        let x3_numerator = (&p_x * &q_y + &q_x * &p_y) % &modulus;
        let y3_numerator = (&p_y * &q_y + &p_x * &q_x) % &modulus;
        let f = (p_x * q_x * p_y * q_y) % &modulus;
        let d_bigint = EdAddAssignChip::d_biguint();
        let d_mul_f = (f * d_bigint) % &modulus;
        // x3_denominator = 1 / (1 + d * f)
        let x3_denominator = ((1u32 + &d_mul_f) % &modulus).modpow(&(&modulus - 2u32), &modulus);
        // y3_denominator = 1 / (1 - d * f)
        let y3_denominator =
            ((1u32 + &modulus - &d_mul_f) % &modulus).modpow(&(&modulus - 2u32), &modulus);
        let x3 = (&x3_numerator * &x3_denominator) % &modulus;
        let y3 = (&y3_numerator * &y3_denominator) % &modulus;

        let mut x3_limbs = [0; 32];
        let mut y3_limbs = [0; 32];
        let x3_le = x3.to_bytes_le();
        x3_limbs[0..x3_le.len()].copy_from_slice(x3_le.as_slice());
        let y3_le = y3.to_bytes_le();
        y3_limbs[0..y3_le.len()].copy_from_slice(y3_le.as_slice());

        // Create p memory records that read the values of p and write the values of x3 and y3.
        let mut p_memory_records = [MemoryRecord::default(); 16];

        for i in 0..8 {
            let u32_array: [u8; 4] = x3_limbs[i * 4..(i + 1) * 4].try_into().unwrap();

            let u32_value = u32::from_le_bytes(u32_array);
            rt.mr(p_ptr + (i as u32) * 4, AccessPosition::Memory);
            rt.mw(p_ptr + (i as u32) * 4, u32_value, AccessPosition::Memory);
            p_memory_records[i] = *rt.record.memory.as_ref().unwrap();
        }
        // panic!();
        for i in 0..8 {
            let u32_array: [u8; 4] = y3_limbs[i * 4..(i + 1) * 4].try_into().unwrap();
            let u32_value = u32::from_le_bytes(u32_array);
            rt.mr(p_ptr + (i as u32 + 8) * 4, AccessPosition::Memory);
            rt.mw(
                p_ptr + (i as u32 + 8) * 4,
                u32_value,
                AccessPosition::Memory,
            );
            p_memory_records[8 + i] = *rt.record.memory.as_ref().unwrap();
        }
        rt.clk += 4;

        rt.segment.ed_add_events.push(EdAddEvent {
            clk: rt.clk - Self::NB_ED_ADD_CYCLES,
            p_ptr,
            p,
            q_ptr,
            q,
            q_ptr_record,
            p_memory_records,
            q_memory_records,
        });

        // Restore record
        rt.record = record;
        (p_ptr, opcode, 0)
    }
}

impl<F: Field> Chip<F> for EdAddAssignChip {
    fn name(&self) -> String {
        "EdAddAssign".to_string()
    }

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let mut new_field_events = Vec::new();

        for i in 0..segment.ed_add_events.len() {
            let event = segment.ed_add_events[i];
            let mut row = [F::zero(); NUM_ED_ADD_COLS];
            let cols: &mut EdAddAssignCols<F> = unsafe { std::mem::transmute(&mut row) };
            cols.is_real = F::one();
            cols.segment = F::from_canonical_u32(segment.index);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.p_ptr = F::from_canonical_u32(event.p_ptr);
            cols.q_ptr = F::from_canonical_u32(event.q_ptr);
            for i in 0..16 {
                let q_record = MemoryRecord {
                    value: event.q[i],
                    segment: segment.index,
                    timestamp: event.clk,
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
                &vec![q_y.clone(), p_y.clone()],
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

            let d = EdAddAssignChip::d_biguint();
            let d_mul_f = cols
                .d_mul_f
                .populate::<Ed25519BaseField>(&f, &d, FpOperation::Mul);

            let x3_ins = cols
                .x3_ins
                .populate::<Ed25519BaseField>(&x3_numerator, &d_mul_f, true);
            let y3_ins = cols
                .y3_ins
                .populate::<Ed25519BaseField>(&y3_numerator, &d_mul_f, false);

            let mut x3_limbs = x3_ins.to_bytes_le();
            x3_limbs.resize(NUM_LIMBS, 0u8);
            let mut y3_limbs = y3_ins.to_bytes_le();
            y3_limbs.resize(NUM_LIMBS, 0u8);
            for i in 0..8 {
                let x3_array: [u8; 4] = x3_limbs[i * 4..(i + 1) * 4].try_into().unwrap();
                // let x3_value: u32 = unsafe { std::mem::transmute(x3_array) };
                let x3_value = u32::from_le_bytes(x3_array);
                let x3_write_record = MemoryRecord {
                    value: x3_value,
                    segment: segment.index,
                    timestamp: event.clk + 4,
                };
                self.populate_access(
                    &mut cols.p_access[i],
                    x3_write_record,
                    Some(event.p_memory_records[i]),
                    &mut new_field_events,
                );
                let y3_array: [u8; 4] = y3_limbs[i * 4..(i + 1) * 4].try_into().unwrap();
                // let y3_value: u32 = unsafe { std::mem::transmute(y3_array) };
                let y3_value = u32::from_le_bytes(y3_array);
                let y3_write_record = MemoryRecord {
                    value: y3_value,
                    segment: segment.index,
                    timestamp: event.clk + 4,
                };
                self.populate_access(
                    &mut cols.p_access[8 + i],
                    y3_write_record,
                    Some(event.p_memory_records[8 + i]),
                    &mut new_field_events,
                );
            }
            let q_ptr_record = MemoryRecord {
                value: event.q_ptr,
                segment: segment.index,
                timestamp: event.clk + 1,
            };
            self.populate_access(
                &mut cols.q_ptr_access,
                q_ptr_record,
                Some(event.q_ptr_record),
                &mut new_field_events,
            );

            rows.push(row);
        }
        segment.field_events.extend(new_field_events);

        let nb_rows = rows.len();
        let mut padded_nb_rows = nb_rows.next_power_of_two();
        if padded_nb_rows == 2 || padded_nb_rows == 1 {
            padded_nb_rows = 4;
        }

        if padded_nb_rows > nb_rows {
            let mut row = [F::zero(); NUM_ED_ADD_COLS];
            let cols: &mut EdAddAssignCols<F> = unsafe { std::mem::transmute(&mut row) };
            let zero = BigUint::zero();
            let x1_mul_y1 =
                cols.x1_mul_y1
                    .populate::<Ed25519BaseField>(&zero, &zero, FpOperation::Mul);
            let x2_mul_y2 =
                cols.x2_mul_y2
                    .populate::<Ed25519BaseField>(&zero, &zero, FpOperation::Mul);
            let f = cols
                .f
                .populate::<Ed25519BaseField>(&x1_mul_y1, &x2_mul_y2, FpOperation::Mul);
            let d = EdAddAssignChip::d_biguint();
            let d_mul_f = cols
                .d_mul_f
                .populate::<Ed25519BaseField>(&f, &d, FpOperation::Mul);
            let x3_numerator = cols.x3_numerator.populate::<Ed25519BaseField>(
                &vec![zero.clone(), zero.clone()],
                &vec![zero.clone(), zero.clone()],
            );
            let y3_numerator = cols.y3_numerator.populate::<Ed25519BaseField>(
                &vec![zero.clone(), zero.clone()],
                &vec![zero.clone(), zero.clone()],
            );
            let x3_ins = cols
                .x3_ins
                .populate::<Ed25519BaseField>(&x3_numerator, &d_mul_f, true);
            let y3_ins = cols
                .y3_ins
                .populate::<Ed25519BaseField>(&y3_numerator, &d_mul_f, false);
            let mut x3_limbs = x3_ins.to_bytes_le();
            x3_limbs.resize(NUM_LIMBS, 0u8);
            let mut y3_limbs = y3_ins.to_bytes_le();
            y3_limbs.resize(NUM_LIMBS, 0u8);

            for i in 0..8 {
                let x3_array: [u8; 4] = x3_limbs[i * 4..(i + 1) * 4].try_into().unwrap();
                cols.p_access[i].value = Word(x3_array.map(F::from_canonical_u8));
            }
            for i in 0..8 {
                let y3_array: [u8; 4] = y3_limbs[i * 4..(i + 1) * 4].try_into().unwrap();
                cols.p_access[8 + i].value = Word(y3_array.map(F::from_canonical_u8));
            }

            for _ in nb_rows..padded_nb_rows {
                rows.push(row);
            }
        }

        // Convert the trace to a row major matrix.
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
        let y1 = EdAddAssignCols::limbs_from_access(&row.p_access[8..16]);
        let y2 = EdAddAssignCols::limbs_from_access(&row.q_access[8..16]);

        // x3_numerator = x1 * y2 + x2 * y1.
        row.x3_numerator
            .eval::<AB, Ed25519BaseField>(builder, &[x1, x2], &[y2, y1]);

        // y3_numerator = y1 * y2 + x1 * x2.
        row.y3_numerator
            .eval::<AB, Ed25519BaseField>(builder, &[y1, x1], &[y2, x2]);

        // f = x1 * x2 * y1 * y2.
        row.x1_mul_y1
            .eval::<AB, Ed25519BaseField>(builder, &x1, &y1, FpOperation::Mul);
        row.x2_mul_y2
            .eval::<AB, Ed25519BaseField>(builder, &x2, &y2, FpOperation::Mul);

        let x1_mul_y1 = row.x1_mul_y1.result;
        let x2_mul_y2 = row.x2_mul_y2.result;
        row.f
            .eval::<AB, Ed25519BaseField>(builder, &x1_mul_y1, &x2_mul_y2, FpOperation::Mul);

        // d * f.
        let f = row.f.result;
        let d_biguint = EdAddAssignChip::d_biguint();
        let d_const = Ed25519BaseField::to_limbs_field::<AB::F>(&d_biguint);
        let d_const_expr = Limbs::<AB::Expr>(d_const.0.map(|x| x.into()));
        row.d_mul_f
            .eval_expr::<AB, Ed25519BaseField>(builder, &f, &d_const_expr, FpOperation::Mul);

        let d_mul_f = row.d_mul_f.result;

        // x3 = x3_numerator / (1 + d * f).
        row.x3_ins
            .eval::<AB, Ed25519BaseField>(builder, &row.x3_numerator.result, &d_mul_f, true);

        // y3 = y3_numerator / (1 - d * f).
        row.y3_ins
            .eval::<AB, Ed25519BaseField>(builder, &row.y3_numerator.result, &d_mul_f, false);

        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]
        // This is to ensure that p_access is updated with the new value.
        for i in 0..NUM_LIMBS {
            builder.assert_eq(row.x3_ins.result[i], row.p_access[i / 4].value[i % 4]);
            builder.assert_eq(row.y3_ins.result[i], row.p_access[8 + i / 4].value[i % 4]);
        }

        for i in 0..16 {
            builder.constraint_memory_access(
                row.segment,
                row.clk, // clk + 0 -> Memory
                row.q_ptr + AB::F::from_canonical_u32(i * 4),
                row.q_access[i as usize],
                row.is_real,
            );
            builder.constraint_memory_access(
                row.segment,
                row.clk + AB::F::from_canonical_u32(4), // clk + 4 -> Memory
                row.p_ptr + AB::F::from_canonical_u32(i * 4),
                row.p_access[i as usize],
                row.is_real,
            );
        }
        builder.constraint_memory_access(
            row.segment,
            row.clk + AB::F::from_canonical_u32(AccessPosition::C as u32), // clk + 0 -> C
            AB::F::from_canonical_u32(11),
            row.q_ptr_access,
            row.is_real,
        );
    }
}
