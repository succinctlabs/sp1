use crate::air::CurtaAirBuilder;
use crate::cpu::cols::cpu_cols::MemoryAccessCols;
use crate::cpu::MemoryReadRecord;
use crate::cpu::MemoryWriteRecord;
use crate::operations::field::fp_den::FpDenCols;
use crate::operations::field::fp_inner_product::FpInnerProductCols;
use crate::operations::field::fp_op::FpOpCols;
use crate::operations::field::fp_op::FpOperation;
use crate::operations::field::params::Limbs;
use crate::operations::field::params::NUM_LIMBS;
use crate::precompiles::PrecompileRuntime;
use crate::runtime::Segment;
use crate::utils::ec::field::FieldParameters;
use crate::utils::ec::AffinePoint;
use crate::utils::ec::EllipticCurve;
use crate::utils::Chip;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use num::BigUint;
use num::Zero;
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use std::fmt::Debug;
use std::marker::PhantomData;
use valida_derive::AlignedBorrow;

#[derive(Debug, Clone, Copy)]
pub struct EdAddEvent {
    pub clk: u32,
    pub p_ptr: u32,
    pub p: [u32; 16],
    pub q_ptr: u32,
    pub q: [u32; 16],
    pub q_ptr_record: MemoryReadRecord,
    pub p_memory_records: [MemoryWriteRecord; 16],
    pub q_memory_records: [MemoryReadRecord; 16],
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

pub struct EdAddAssignChip<E> {
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve> EdAddAssignChip<E> {
    pub const NUM_CYCLES: u32 = 8;

    const D: [u16; 32] = [
        30883, 4953, 19914, 30187, 55467, 16705, 2637, 112, 59544, 30585, 16505, 36039, 65139,
        11119, 27886, 20995, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    fn d_biguint() -> BigUint {
        let mut modulus = BigUint::from(0_u32);
        for (i, limb) in Self::D.iter().enumerate() {
            modulus += BigUint::from(*limb) << (16 * i);
        }
        modulus
    }

    pub fn execute(rt: &mut PrecompileRuntime) -> u32 {
        let a0 = crate::runtime::Register::X10;
        let a1 = crate::runtime::Register::X11;

        let start_clk = rt.clk;

        // TODO: these will have to be be constrained, but can do it later.
        let p_ptr = rt.register_unsafe(a0);
        if p_ptr % 4 != 0 {
            panic!();
        }

        let (q_ptr_record, q_ptr) = rt.mr(a1 as u32);
        if q_ptr % 4 != 0 {
            panic!();
        }

        let p: [u32; 16] = rt.slice_unsafe(p_ptr, 16).try_into().unwrap();
        let (q_memory_records_vec, q_vec) = rt.mr_slice(q_ptr, 16);
        let q_memory_records = q_memory_records_vec.try_into().unwrap();
        let q: [u32; 16] = q_vec.try_into().unwrap();
        // When we write to p, we want the clk to be incremented.
        rt.clk += 4;

        let p_affine = AffinePoint::<E>::from_words_le(&p);
        let q_affine = AffinePoint::<E>::from_words_le(&q);
        let result_affine = p_affine + q_affine;
        let result_words = result_affine.to_words_le();

        let p_memory_records = rt.mw_slice(p_ptr, &result_words).try_into().unwrap();

        rt.clk += 4;

        rt.segment_mut().ed_add_events.push(EdAddEvent {
            clk: start_clk,
            p_ptr,
            p,
            q_ptr,
            q,
            q_ptr_record,
            p_memory_records,
            q_memory_records,
        });

        p_ptr
    }
}

impl<F: Field, E: EllipticCurve> Chip<F> for EdAddAssignChip<E> {
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
                cols.q_access[i].populate_read(event.q_memory_records[i], &mut new_field_events);
            }
            let p = &event.p;
            let q = &event.q;
            let p_x = BigUint::from_slice(&p[0..8]);
            let p_y = BigUint::from_slice(&p[8..16]);
            let q_x = BigUint::from_slice(&q[0..8]);
            let q_y = BigUint::from_slice(&q[8..16]);
            let x3_numerator = cols
                .x3_numerator
                .populate::<E::BaseField>(&[p_x.clone(), q_x.clone()], &[q_y.clone(), p_y.clone()]);
            let y3_numerator = cols
                .y3_numerator
                .populate::<E::BaseField>(&[p_y.clone(), p_x.clone()], &[q_y.clone(), q_x.clone()]);
            let x1_mul_y1 = cols
                .x1_mul_y1
                .populate::<E::BaseField>(&p_x, &p_y, FpOperation::Mul);
            let x2_mul_y2 = cols
                .x2_mul_y2
                .populate::<E::BaseField>(&q_x, &q_y, FpOperation::Mul);
            let f = cols
                .f
                .populate::<E::BaseField>(&x1_mul_y1, &x2_mul_y2, FpOperation::Mul);

            let d = Self::d_biguint();
            let d_mul_f = cols
                .d_mul_f
                .populate::<E::BaseField>(&f, &d, FpOperation::Mul);

            let x3_ins = cols
                .x3_ins
                .populate::<E::BaseField>(&x3_numerator, &d_mul_f, true);
            let y3_ins = cols
                .y3_ins
                .populate::<E::BaseField>(&y3_numerator, &d_mul_f, false);

            let mut x3_limbs = x3_ins.to_bytes_le();
            x3_limbs.resize(NUM_LIMBS, 0u8);
            let mut y3_limbs = y3_ins.to_bytes_le();
            y3_limbs.resize(NUM_LIMBS, 0u8);
            for i in 0..16 {
                cols.p_access[i].populate_write(event.p_memory_records[i], &mut new_field_events);
            }
            cols.q_ptr_access
                .populate_read(event.q_ptr_record, &mut new_field_events);
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
            let x1_mul_y1 = cols
                .x1_mul_y1
                .populate::<E::BaseField>(&zero, &zero, FpOperation::Mul);
            let x2_mul_y2 = cols
                .x2_mul_y2
                .populate::<E::BaseField>(&zero, &zero, FpOperation::Mul);
            let f = cols
                .f
                .populate::<E::BaseField>(&x1_mul_y1, &x2_mul_y2, FpOperation::Mul);
            let d = Self::d_biguint();
            let d_mul_f = cols
                .d_mul_f
                .populate::<E::BaseField>(&f, &d, FpOperation::Mul);
            let x3_numerator = cols.x3_numerator.populate::<E::BaseField>(
                &[zero.clone(), zero.clone()],
                &[zero.clone(), zero.clone()],
            );
            let y3_numerator = cols.y3_numerator.populate::<E::BaseField>(
                &[zero.clone(), zero.clone()],
                &[zero.clone(), zero.clone()],
            );
            let x3_ins = cols
                .x3_ins
                .populate::<E::BaseField>(&x3_numerator, &d_mul_f, true);
            let y3_ins = cols
                .y3_ins
                .populate::<E::BaseField>(&y3_numerator, &d_mul_f, false);
            let mut x3_limbs = x3_ins.to_bytes_le();
            x3_limbs.resize(NUM_LIMBS, 0u8);
            let mut y3_limbs = y3_ins.to_bytes_le();
            y3_limbs.resize(NUM_LIMBS, 0u8);

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

impl<F, E: EllipticCurve> BaseAir<F> for EdAddAssignChip<E> {
    fn width(&self) -> usize {
        NUM_ED_ADD_COLS
    }
}

impl<AB, E: EllipticCurve> Air<AB> for EdAddAssignChip<E>
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
            .eval::<AB, E::BaseField>(builder, &[x1, x2], &[y2, y1]);

        // y3_numerator = y1 * y2 + x1 * x2.
        row.y3_numerator
            .eval::<AB, E::BaseField>(builder, &[y1, x1], &[y2, x2]);

        // f = x1 * x2 * y1 * y2.
        row.x1_mul_y1
            .eval::<AB, E::BaseField>(builder, &x1, &y1, FpOperation::Mul);
        row.x2_mul_y2
            .eval::<AB, E::BaseField>(builder, &x2, &y2, FpOperation::Mul);

        let x1_mul_y1 = row.x1_mul_y1.result;
        let x2_mul_y2 = row.x2_mul_y2.result;
        row.f
            .eval::<AB, E::BaseField>(builder, &x1_mul_y1, &x2_mul_y2, FpOperation::Mul);

        // d * f.
        let f = row.f.result;
        let d_biguint = Self::d_biguint();
        let d_const = E::BaseField::to_limbs_field::<AB::F>(&d_biguint);
        let d_const_expr = Limbs::<AB::Expr>(d_const.0.map(|x| x.into()));
        row.d_mul_f
            .eval_expr::<AB, E::BaseField>(builder, &f, &d_const_expr, FpOperation::Mul);

        let d_mul_f = row.d_mul_f.result;

        // x3 = x3_numerator / (1 + d * f).
        row.x3_ins
            .eval::<AB, E::BaseField>(builder, &row.x3_numerator.result, &d_mul_f, true);

        // y3 = y3_numerator / (1 - d * f).
        row.y3_ins
            .eval::<AB, E::BaseField>(builder, &row.y3_numerator.result, &d_mul_f, false);

        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]
        // This is to ensure that p_access is updated with the new value.
        for i in 0..NUM_LIMBS {
            builder
                .when(row.is_real)
                .assert_eq(row.x3_ins.result[i], row.p_access[i / 4].value[i % 4]);
            builder
                .when(row.is_real)
                .assert_eq(row.y3_ins.result[i], row.p_access[8 + i / 4].value[i % 4]);
        }

        builder.constraint_memory_access(
            row.segment,
            row.clk, // clk + 0 -> C
            AB::F::from_canonical_u32(11),
            row.q_ptr_access,
            row.is_real,
        );
        for i in 0..16 {
            builder.constraint_memory_access(
                row.segment,
                row.clk, // clk + 0 -> Memory
                row.q_ptr + AB::F::from_canonical_u32(i * 4),
                row.q_access[i as usize],
                row.is_real,
            );
        }
        for i in 0..16 {
            builder.constraint_memory_access(
                row.segment,
                row.clk + AB::F::from_canonical_u32(4), // clk + 4 -> Memory
                row.p_ptr + AB::F::from_canonical_u32(i * 4),
                row.p_access[i as usize],
                row.is_real,
            );
        }
    }
}
