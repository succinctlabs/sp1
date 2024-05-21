use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use std::fmt::Debug;
use std::marker::PhantomData;

use num::BigUint;
use num::Zero;

use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::IntoParallelRefIterator;
use p3_maybe_rayon::prelude::ParallelIterator;
use sp1_derive::AlignedBorrow;

use super::{NUM_LIMBS, WORDS_CURVE_POINT};
use crate::air::BaseAirBuilder;
use crate::air::MachineAir;
use crate::air::SP1AirBuilder;
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteLookupEvent;
use crate::memory::value_as_limbs;
use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;
use crate::operations::field::field_den::FieldDenCols;
use crate::operations::field::field_inner_product::FieldInnerProductCols;
use crate::operations::field::field_op::FieldOpCols;
use crate::operations::field::field_op::FieldOperation;
use crate::operations::field::params::FieldParameters;
use crate::runtime::ExecutionRecord;
use crate::runtime::Program;
use crate::runtime::Syscall;
use crate::runtime::SyscallCode;
use crate::syscall::precompiles::create_ec_add_event;
use crate::syscall::precompiles::SyscallContext;
use crate::utils::ec::edwards::ed25519::Ed25519BaseField;
use crate::utils::ec::edwards::EdwardsParameters;
use crate::utils::ec::AffinePoint;
use crate::utils::ec::EllipticCurve;
use crate::utils::limbs_from_prev_access;
use crate::utils::pad_rows;

pub const NUM_ED_ADD_COLS: usize = size_of::<EdAddAssignCols<u8>>();

/// A set of columns to compute `EdAdd` where a, b are field elements.
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed
/// or made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdAddAssignCols<T> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: [MemoryWriteCols<T>; WORDS_CURVE_POINT],
    pub q_access: [MemoryReadCols<T>; WORDS_CURVE_POINT],
    pub(crate) x3_numerator: FieldInnerProductCols<T, Ed25519BaseField>,
    pub(crate) y3_numerator: FieldInnerProductCols<T, Ed25519BaseField>,
    pub(crate) x1_mul_y1: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) x2_mul_y2: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) f: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) d_mul_f: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) x3_ins: FieldDenCols<T, Ed25519BaseField>,
    pub(crate) y3_ins: FieldDenCols<T, Ed25519BaseField>,
}

#[derive(Default)]
pub struct EdAddAssignChip<E> {
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve + EdwardsParameters> EdAddAssignChip<E> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
    fn populate_field_ops<F: PrimeField32>(
        record: &mut impl ByteRecord,
        shard: u32,
        cols: &mut EdAddAssignCols<F>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
    ) {
        let x3_numerator = cols.x3_numerator.populate(
            record,
            shard,
            &[p_x.clone(), q_x.clone()],
            &[q_y.clone(), p_y.clone()],
        );
        let y3_numerator = cols.y3_numerator.populate(
            record,
            shard,
            &[p_y.clone(), p_x.clone()],
            &[q_y.clone(), q_x.clone()],
        );
        let x1_mul_y1 = cols
            .x1_mul_y1
            .populate(record, shard, &p_x, &p_y, FieldOperation::Mul);
        let x2_mul_y2 = cols
            .x2_mul_y2
            .populate(record, shard, &q_x, &q_y, FieldOperation::Mul);
        let f = cols
            .f
            .populate(record, shard, &x1_mul_y1, &x2_mul_y2, FieldOperation::Mul);

        let d = E::d_biguint();
        let d_mul_f = cols
            .d_mul_f
            .populate(record, shard, &f, &d, FieldOperation::Mul);

        cols.x3_ins
            .populate(record, shard, &x3_numerator, &d_mul_f, true);
        cols.y3_ins
            .populate(record, shard, &y3_numerator, &d_mul_f, false);
    }
}

impl<E: EllipticCurve + EdwardsParameters> Syscall for EdAddAssignChip<E> {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_ec_add_event::<E>(rt, arg1, arg2);
        rt.record_mut().ed_add_events.push(event);
        None
    }
}

impl<F: PrimeField32, E: EllipticCurve + EdwardsParameters> MachineAir<F> for EdAddAssignChip<E> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "EdAddAssign".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let (mut rows, new_byte_lookup_events): (
            Vec<[F; NUM_ED_ADD_COLS]>,
            Vec<Vec<ByteLookupEvent>>,
        ) = input
            .ed_add_events
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_ED_ADD_COLS];
                let cols: &mut EdAddAssignCols<F> = row.as_mut_slice().borrow_mut();

                // Decode affine points.
                let p = &event.p;
                let q = &event.q;
                let p = AffinePoint::<E>::from_words_le(p);
                let (p_x, p_y) = (p.x, p.y);
                let q = AffinePoint::<E>::from_words_le(q);
                let (q_x, q_y) = (q.x, q.y);

                // Populate basic columns.
                cols.is_real = F::one();
                cols.shard = F::from_canonical_u32(event.shard);
                cols.clk = F::from_canonical_u32(event.clk);
                cols.p_ptr = F::from_canonical_u32(event.p_ptr);
                cols.q_ptr = F::from_canonical_u32(event.q_ptr);

                let mut new_byte_lookup_events = Vec::new();
                Self::populate_field_ops(
                    &mut new_byte_lookup_events,
                    event.shard,
                    cols,
                    p_x,
                    p_y,
                    q_x,
                    q_y,
                );

                // Populate the memory access columns.
                for i in 0..WORDS_CURVE_POINT {
                    cols.q_access[i]
                        .populate(event.q_memory_records[i], &mut new_byte_lookup_events);
                }
                for i in 0..WORDS_CURVE_POINT {
                    cols.p_access[i]
                        .populate(event.p_memory_records[i], &mut new_byte_lookup_events);
                }

                (row, new_byte_lookup_events)
            })
            .unzip();

        for byte_lookup_events in new_byte_lookup_events {
            output.add_byte_lookup_events(byte_lookup_events);
        }

        pad_rows(&mut rows, || {
            let mut row = [F::zero(); NUM_ED_ADD_COLS];
            let cols: &mut EdAddAssignCols<F> = row.as_mut_slice().borrow_mut();
            let zero = BigUint::zero();
            Self::populate_field_ops(
                &mut vec![],
                0,
                cols,
                zero.clone(),
                zero.clone(),
                zero.clone(),
                zero,
            );
            row
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_ED_ADD_COLS,
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.ed_add_events.is_empty()
    }
}

impl<F, E: EllipticCurve + EdwardsParameters> BaseAir<F> for EdAddAssignChip<E> {
    fn width(&self) -> usize {
        NUM_ED_ADD_COLS
    }
}

impl<AB, E: EllipticCurve + EdwardsParameters> Air<AB> for EdAddAssignChip<E>
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0);
        let row: &EdAddAssignCols<AB::Var> = (*row).borrow();

        let x1 = limbs_from_prev_access(&row.p_access[0..8]);
        let x2 = limbs_from_prev_access(&row.q_access[0..8]);
        let y1 = limbs_from_prev_access(&row.p_access[8..16]);
        let y2 = limbs_from_prev_access(&row.q_access[8..16]);

        // x3_numerator = x1 * y2 + x2 * y1.
        row.x3_numerator
            .eval(builder, &[x1, x2], &[y2, y1], row.shard, row.is_real);

        // y3_numerator = y1 * y2 + x1 * x2.
        row.y3_numerator
            .eval(builder, &[y1, x1], &[y2, x2], row.shard, row.is_real);

        // f = x1 * x2 * y1 * y2.
        row.x1_mul_y1.eval(
            builder,
            &x1,
            &y1,
            FieldOperation::Mul,
            row.shard,
            row.is_real,
        );
        row.x2_mul_y2.eval(
            builder,
            &x2,
            &y2,
            FieldOperation::Mul,
            row.shard,
            row.is_real,
        );

        let x1_mul_y1 = row.x1_mul_y1.result;
        let x2_mul_y2 = row.x2_mul_y2.result;
        row.f.eval(
            builder,
            &x1_mul_y1,
            &x2_mul_y2,
            FieldOperation::Mul,
            row.shard,
            row.is_real,
        );

        // d * f.
        let f = row.f.result;
        let d_biguint = E::d_biguint();
        let d_const = E::BaseField::to_limbs_field::<AB::Expr, _>(&d_biguint);
        row.d_mul_f.eval(
            builder,
            &f,
            &d_const,
            FieldOperation::Mul,
            row.shard,
            row.is_real,
        );

        let d_mul_f = row.d_mul_f.result;

        // x3 = x3_numerator / (1 + d * f).
        row.x3_ins.eval(
            builder,
            &row.x3_numerator.result,
            &d_mul_f,
            true,
            row.shard,
            row.is_real,
        );

        // y3 = y3_numerator / (1 - d * f).
        row.y3_ins.eval(
            builder,
            &row.y3_numerator.result,
            &d_mul_f,
            false,
            row.shard,
            row.is_real,
        );

        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]
        // This is to ensure that p_access is updated with the new value.
        let p_access_vec = value_as_limbs(&row.p_access);
        builder
            .when(row.is_real)
            .assert_all_eq(row.x3_ins.result, p_access_vec[0..NUM_LIMBS].to_vec());
        builder.when(row.is_real).assert_all_eq(
            row.y3_ins.result,
            p_access_vec[NUM_LIMBS..NUM_LIMBS * 2].to_vec(),
        );

        builder.eval_memory_access_slice(
            row.shard,
            row.clk.into(),
            row.q_ptr,
            &row.q_access,
            row.is_real,
        );

        builder.eval_memory_access_slice(
            row.shard,
            row.clk + AB::F::from_canonical_u32(1),
            row.p_ptr,
            &row.p_access,
            row.is_real,
        );

        builder.receive_syscall(
            row.shard,
            row.clk,
            AB::F::from_canonical_u32(SyscallCode::ED_ADD.syscall_id()),
            row.p_ptr,
            row.q_ptr,
            row.is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::utils;
    use crate::utils::tests::{ED25519_ELF, ED_ADD_ELF};
    use crate::Program;

    #[test]
    fn test_ed_add_simple() {
        utils::setup_logger();
        let program = Program::from(ED_ADD_ELF);
        utils::run_test(program).unwrap();
    }

    #[test]
    fn test_ed25519_program() {
        utils::setup_logger();
        let program = Program::from(ED25519_ELF);
        utils::run_test(program).unwrap();
    }
}
