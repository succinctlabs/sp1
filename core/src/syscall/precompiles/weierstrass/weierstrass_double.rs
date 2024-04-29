use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use std::fmt::Debug;
use std::marker::PhantomData;

use generic_array::GenericArray;
use num::BigUint;
use num::Zero;
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::ParallelIterator;
use p3_maybe_rayon::prelude::ParallelSlice;
use sp1_derive::AlignedBorrow;

use crate::air::MachineAir;
use crate::air::SP1AirBuilder;
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteLookupEvent;
use crate::memory::MemoryCols;
use crate::memory::MemoryWriteCols;
use crate::operations::field::field_op::FieldOpCols;
use crate::operations::field::field_op::FieldOperation;
use crate::operations::field::params::{FieldParameters, NumWords};
use crate::operations::field::params::{Limbs, NumLimbs};
use crate::runtime::ExecutionRecord;
use crate::runtime::Program;
use crate::runtime::Syscall;
use crate::runtime::SyscallCode;
use crate::stark::MachineRecord;
use crate::syscall::precompiles::create_ec_double_event;
use crate::syscall::precompiles::SyscallContext;
use crate::utils::ec::weierstrass::WeierstrassParameters;
use crate::utils::ec::AffinePoint;
use crate::utils::ec::CurveType;
use crate::utils::ec::EllipticCurve;
use crate::utils::limbs_from_prev_access;
use crate::utils::pad_rows;

pub const fn num_weierstrass_double_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<WeierstrassDoubleAssignCols<u8, P>>()
}

/// A set of columns to double a point on a Weierstrass curve.
///
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed or
/// made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassDoubleAssignCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub p_ptr: T,
    pub p_access: GenericArray<MemoryWriteCols<T>, P::WordsCurvePoint>,
    pub(crate) slope_denominator: FieldOpCols<T, P>,
    pub(crate) slope_numerator: FieldOpCols<T, P>,
    pub(crate) slope: FieldOpCols<T, P>,
    pub(crate) p_x_squared: FieldOpCols<T, P>,
    pub(crate) p_x_squared_times_3: FieldOpCols<T, P>,
    pub(crate) slope_squared: FieldOpCols<T, P>,
    pub(crate) p_x_plus_p_x: FieldOpCols<T, P>,
    pub(crate) x3_ins: FieldOpCols<T, P>,
    pub(crate) p_x_minus_x: FieldOpCols<T, P>,
    pub(crate) y3_ins: FieldOpCols<T, P>,
    pub(crate) slope_times_p_x_minus_x: FieldOpCols<T, P>,
}

#[derive(Default)]
pub struct WeierstrassDoubleAssignChip<E> {
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve + WeierstrassParameters> Syscall for WeierstrassDoubleAssignChip<E> {
    fn execute(&self, rt: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_ec_double_event::<E>(rt, arg1, arg2);
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => rt.record_mut().secp256k1_double_events.push(event),
            CurveType::Bn254 => rt.record_mut().bn254_double_events.push(event),
            CurveType::Bls12381 => rt.record_mut().bls12381_double_events.push(event),
            _ => panic!("Unsupported curve"),
        }
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        0
    }
}

impl<E: EllipticCurve + WeierstrassParameters> WeierstrassDoubleAssignChip<E> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    fn populate_field_ops<F: PrimeField32>(
        blu_events: &mut Vec<ByteLookupEvent>,
        shard: u32,
        cols: &mut WeierstrassDoubleAssignCols<F, E::BaseField>,
        p_x: BigUint,
        p_y: BigUint,
    ) {
        // This populates necessary field operations to double a point on a Weierstrass curve.

        let a = E::a_int();

        // slope = slope_numerator / slope_denominator.
        let slope = {
            // slope_numerator = a + (p.x * p.x) * 3.
            let slope_numerator = {
                let p_x_squared =
                    cols.p_x_squared
                        .populate(blu_events, shard, &p_x, &p_x, FieldOperation::Mul);
                let p_x_squared_times_3 = cols.p_x_squared_times_3.populate(
                    blu_events,
                    shard,
                    &p_x_squared,
                    &BigUint::from(3u32),
                    FieldOperation::Mul,
                );
                cols.slope_numerator.populate(
                    blu_events,
                    shard,
                    &a,
                    &p_x_squared_times_3,
                    FieldOperation::Add,
                )
            };

            // slope_denominator = 2 * y.
            let slope_denominator = cols.slope_denominator.populate(
                blu_events,
                shard,
                &BigUint::from(2u32),
                &p_y,
                FieldOperation::Mul,
            );

            cols.slope.populate(
                blu_events,
                shard,
                &slope_numerator,
                &slope_denominator,
                FieldOperation::Div,
            )
        };

        // x = slope * slope - (p.x + p.x).
        let x = {
            let slope_squared =
                cols.slope_squared
                    .populate(blu_events, shard, &slope, &slope, FieldOperation::Mul);
            let p_x_plus_p_x =
                cols.p_x_plus_p_x
                    .populate(blu_events, shard, &p_x, &p_x, FieldOperation::Add);
            cols.x3_ins.populate(
                blu_events,
                shard,
                &slope_squared,
                &p_x_plus_p_x,
                FieldOperation::Sub,
            )
        };

        // y = slope * (p.x - x) - p.y.
        {
            let p_x_minus_x =
                cols.p_x_minus_x
                    .populate(blu_events, shard, &p_x, &x, FieldOperation::Sub);
            let slope_times_p_x_minus_x = cols.slope_times_p_x_minus_x.populate(
                blu_events,
                shard,
                &slope,
                &p_x_minus_x,
                FieldOperation::Mul,
            );
            cols.y3_ins.populate(
                blu_events,
                shard,
                &slope_times_p_x_minus_x,
                &p_y,
                FieldOperation::Sub,
            );
        }
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> MachineAir<F>
    for WeierstrassDoubleAssignChip<E>
where
    [(); num_weierstrass_double_cols::<E::BaseField>()]:,
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1DoubleAssign".to_string(),
            CurveType::Bn254 => "Bn254DoubleAssign".to_string(),
            CurveType::Bls12381 => "Bls12381DoubleAssign".to_string(),
            _ => panic!("Unsupported curve"),
        }
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // collects the events based on the curve type.
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => &input.secp256k1_double_events,
            CurveType::Bn254 => &input.bn254_double_events,
            CurveType::Bls12381 => &input.bls12381_double_events,
            _ => panic!("Unsupported curve"),
        };

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows_and_records = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut record = ExecutionRecord::default();
                let mut new_byte_lookup_events = Vec::new();

                let rows = events
                    .iter()
                    .map(|event| {
                        let mut row = [F::zero(); num_weierstrass_double_cols::<E::BaseField>()];
                        let cols: &mut WeierstrassDoubleAssignCols<F, E::BaseField> =
                            row.as_mut_slice().borrow_mut();

                        // Decode affine points.
                        let p = &event.p;
                        let p = AffinePoint::<E>::from_words_le(p);
                        let (p_x, p_y) = (p.x, p.y);

                        // Populate basic columns.
                        cols.is_real = F::one();
                        cols.shard = F::from_canonical_u32(event.shard);
                        cols.clk = F::from_canonical_u32(event.clk);
                        cols.p_ptr = F::from_canonical_u32(event.p_ptr);

                        Self::populate_field_ops(
                            &mut new_byte_lookup_events,
                            event.shard,
                            cols,
                            p_x,
                            p_y,
                        );

                        // Populate the memory access columns.
                        for i in 0..cols.p_access.len() {
                            cols.p_access[i]
                                .populate(event.p_memory_records[i], &mut new_byte_lookup_events);
                        }
                        row
                    })
                    .collect::<Vec<_>>();
                record.add_byte_lookup_events(new_byte_lookup_events);
                (rows, record)
            })
            .collect::<Vec<_>>();

        // Generate the trace rows for each event.
        let mut rows = Vec::new();
        for mut row_and_record in rows_and_records {
            rows.extend(row_and_record.0);
            output.append(&mut row_and_record.1);
        }

        pad_rows(&mut rows, || {
            let mut row = [F::zero(); num_weierstrass_double_cols::<E::BaseField>()];
            let cols: &mut WeierstrassDoubleAssignCols<F, E::BaseField> =
                row.as_mut_slice().borrow_mut();
            let zero = BigUint::zero();
            Self::populate_field_ops(&mut vec![], 0, cols, zero.clone(), zero.clone());
            row
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            num_weierstrass_double_cols::<E::BaseField>(),
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => !shard.secp256k1_double_events.is_empty(),
            CurveType::Bn254 => !shard.bn254_double_events.is_empty(),
            CurveType::Bls12381 => !shard.bls12381_double_events.is_empty(),
            _ => panic!("Unsupported curve"),
        }
    }
}

impl<F, E: EllipticCurve + WeierstrassParameters> BaseAir<F> for WeierstrassDoubleAssignChip<E> {
    fn width(&self) -> usize {
        num_weierstrass_double_cols::<E::BaseField>()
    }
}

impl<AB, E: EllipticCurve + WeierstrassParameters> Air<AB> for WeierstrassDoubleAssignChip<E>
where
    AB: SP1AirBuilder,
    Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0);
        let row: &WeierstrassDoubleAssignCols<AB::Var, E::BaseField> = (*row).borrow();

        let num_words_field_element = E::BaseField::NB_LIMBS / 4;
        let p_x = limbs_from_prev_access(&row.p_access[0..num_words_field_element]);
        let p_y = limbs_from_prev_access(&row.p_access[num_words_field_element..]);

        // a in the Weierstrass form: y^2 = x^3 + a * x + b.
        // TODO: U32 can't be hardcoded here?
        let a = E::BaseField::to_limbs_field::<AB::Expr, _>(&E::a_int());

        // slope = slope_numerator / slope_denominator.
        let slope = {
            // slope_numerator = a + (p.x * p.x) * 3.
            {
                row.p_x_squared.eval(
                    builder,
                    &p_x,
                    &p_x,
                    FieldOperation::Mul,
                    row.shard,
                    row.is_real,
                );

                row.p_x_squared_times_3.eval(
                    builder,
                    &row.p_x_squared.result,
                    &E::BaseField::to_limbs_field::<AB::Expr, _>(&BigUint::from(3u32)),
                    FieldOperation::Mul,
                    row.shard,
                    row.is_real,
                );

                row.slope_numerator.eval(
                    builder,
                    &a,
                    &row.p_x_squared_times_3.result,
                    FieldOperation::Add,
                    row.shard,
                    row.is_real,
                );
            };

            // slope_denominator = 2 * y.
            row.slope_denominator.eval(
                builder,
                &E::BaseField::to_limbs_field::<AB::Expr, _>(&BigUint::from(2u32)),
                &p_y,
                FieldOperation::Mul,
                row.shard,
                row.is_real,
            );

            row.slope.eval(
                builder,
                &row.slope_numerator.result,
                &row.slope_denominator.result,
                FieldOperation::Div,
                row.shard,
                row.is_real,
            );

            &row.slope.result
        };

        // x = slope * slope - (p.x + p.x).
        let x = {
            row.slope_squared.eval(
                builder,
                slope,
                slope,
                FieldOperation::Mul,
                row.shard,
                row.is_real,
            );
            row.p_x_plus_p_x.eval(
                builder,
                &p_x,
                &p_x,
                FieldOperation::Add,
                row.shard,
                row.is_real,
            );
            row.x3_ins.eval(
                builder,
                &row.slope_squared.result,
                &row.p_x_plus_p_x.result,
                FieldOperation::Sub,
                row.shard,
                row.is_real,
            );
            &row.x3_ins.result
        };

        // y = slope * (p.x - x) - p.y.
        {
            row.p_x_minus_x.eval(
                builder,
                &p_x,
                x,
                FieldOperation::Sub,
                row.shard,
                row.is_real,
            );
            row.slope_times_p_x_minus_x.eval(
                builder,
                slope,
                &row.p_x_minus_x.result,
                FieldOperation::Mul,
                row.shard,
                row.is_real,
            );
            row.y3_ins.eval(
                builder,
                &row.slope_times_p_x_minus_x.result,
                &p_y,
                FieldOperation::Sub,
                row.shard,
                row.is_real,
            );
        }

        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]. This is to
        // ensure that p_access is updated with the new value.
        for i in 0..E::BaseField::NB_LIMBS {
            builder
                .when(row.is_real)
                .assert_eq(row.x3_ins.result[i], row.p_access[i / 4].value()[i % 4]);
            builder.when(row.is_real).assert_eq(
                row.y3_ins.result[i],
                row.p_access[num_words_field_element + i / 4].value()[i % 4],
            );
        }

        builder.eval_memory_access_slice(
            row.shard,
            row.clk.into(),
            row.p_ptr,
            &row.p_access,
            row.is_real,
        );

        // Fetch the syscall id for the curve type.
        let syscall_id_felt = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                AB::F::from_canonical_u32(SyscallCode::SECP256K1_DOUBLE.syscall_id())
            }
            CurveType::Bn254 => AB::F::from_canonical_u32(SyscallCode::BN254_DOUBLE.syscall_id()),
            CurveType::Bls12381 => {
                AB::F::from_canonical_u32(SyscallCode::BLS12381_DOUBLE.syscall_id())
            }
            _ => panic!("Unsupported curve"),
        };

        builder.receive_syscall(
            row.shard,
            row.clk,
            syscall_id_felt,
            row.p_ptr,
            AB::Expr::zero(),
            row.is_real,
        );
    }
}

#[cfg(test)]
pub mod tests {

    use crate::{
        runtime::Program,
        utils::{
            run_test, setup_logger,
            tests::{BLS12381_DOUBLE_ELF, BN254_DOUBLE_ELF, SECP256K1_DOUBLE_ELF},
        },
    };

    #[test]
    fn test_secp256k1_double_simple() {
        setup_logger();
        let program = Program::from(SECP256K1_DOUBLE_ELF);
        run_test(program).unwrap();
    }

    #[test]
    fn test_bn254_double_simple() {
        setup_logger();
        let program = Program::from(BN254_DOUBLE_ELF);
        run_test(program).unwrap();
    }

    #[test]
    fn test_bls12381_double_simple() {
        setup_logger();
        let program = Program::from(BLS12381_DOUBLE_ELF);
        run_test(program).unwrap();
    }
}
