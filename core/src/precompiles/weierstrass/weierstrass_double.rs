use crate::air::CurtaAirBuilder;
use crate::memory::MemoryCols;
use crate::memory::MemoryWriteCols;
use crate::operations::field::fp_op::FpOpCols;
use crate::operations::field::fp_op::FpOperation;
use crate::operations::field::params::NUM_LIMBS;
use crate::precompiles::create_ec_double_event;
use crate::precompiles::limbs_from_biguint;
use crate::precompiles::PrecompileRuntime;
use crate::runtime::Segment;
use crate::utils::ec::weierstrass::WeierstrassParameters;
use crate::utils::ec::AffinePoint;
use crate::utils::ec::EllipticCurve;
use crate::utils::ec::NUM_WORDS_EC_POINT;
use crate::utils::ec::NUM_WORDS_FIELD_ELEMENT;
use crate::utils::limbs_from_prev_access;
use crate::utils::pad_rows;
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

pub const NUM_WEIERSTRASS_DOUBLE_COLS: usize = size_of::<WeierstrassDoubleAssignCols<u8>>();

/// A set of columns to double a point on a Weierstrass curve.
///
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed or
/// made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassDoubleAssignCols<T> {
    pub is_real: T,
    pub segment: T,
    pub clk: T,
    pub p_ptr: T,
    pub p_access: [MemoryWriteCols<T>; NUM_WORDS_EC_POINT],
    pub(crate) slope_denominator: FpOpCols<T>,
    pub(crate) slope_numerator: FpOpCols<T>,
    pub(crate) slope: FpOpCols<T>,
    pub(crate) p_x_squared: FpOpCols<T>,
    pub(crate) p_x_squared_times_3: FpOpCols<T>,
    pub(crate) slope_squared: FpOpCols<T>,
    pub(crate) p_x_plus_p_x: FpOpCols<T>,
    pub(crate) x3_ins: FpOpCols<T>,
    pub(crate) p_x_minus_x: FpOpCols<T>,
    pub(crate) y3_ins: FpOpCols<T>,
    pub(crate) slope_times_p_x_minus_x: FpOpCols<T>,
}

pub struct WeierstrassDoubleAssignChip<E, WP> {
    _marker: PhantomData<(E, WP)>,
}

impl<E: EllipticCurve, WP: WeierstrassParameters> WeierstrassDoubleAssignChip<E, WP> {
    pub const NUM_CYCLES: u32 = 8;

    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub fn execute(rt: &mut PrecompileRuntime) -> u32 {
        let event = create_ec_double_event::<E>(rt);
        rt.segment_mut().weierstrass_double_events.push(event);
        event.p_ptr + 1
    }

    fn populate_fp_ops<F: Field>(
        cols: &mut WeierstrassDoubleAssignCols<F>,
        p_x: BigUint,
        p_y: BigUint,
    ) {
        // This populates necessary field operations to double a point on a Weierstrass curve.

        let a = WP::a_int();

        // slope = slope_numerator / slope_denominator.
        let slope = {
            // slope_numerator = a + (p.x * p.x) * 3.
            let slope_numerator = {
                let p_x_squared =
                    cols.p_x_squared
                        .populate::<E::BaseField>(&p_x, &p_x, FpOperation::Mul);
                let p_x_squared_times_3 = cols.p_x_squared_times_3.populate::<E::BaseField>(
                    &p_x_squared,
                    &BigUint::from(3u32),
                    FpOperation::Mul,
                );
                cols.slope_numerator.populate::<E::BaseField>(
                    &a,
                    &p_x_squared_times_3,
                    FpOperation::Add,
                )
            };

            // slope_denominator = 2 * y.
            let slope_denominator = cols.slope_denominator.populate::<E::BaseField>(
                &BigUint::from(2u32),
                &p_y,
                FpOperation::Mul,
            );

            cols.slope.populate::<E::BaseField>(
                &slope_numerator,
                &slope_denominator,
                FpOperation::Div,
            )
        };

        // x = slope * slope - (p.x + p.x).
        let x = {
            let slope_squared =
                cols.slope_squared
                    .populate::<E::BaseField>(&slope, &slope, FpOperation::Mul);
            let p_x_plus_p_x =
                cols.p_x_plus_p_x
                    .populate::<E::BaseField>(&p_x, &p_x, FpOperation::Add);
            cols.x3_ins
                .populate::<E::BaseField>(&slope_squared, &p_x_plus_p_x, FpOperation::Sub)
        };

        // y = slope * (p.x - x) - p.y.
        {
            let p_x_minus_x = cols
                .p_x_minus_x
                .populate::<E::BaseField>(&p_x, &x, FpOperation::Sub);
            let slope_times_p_x_minus_x = cols.slope_times_p_x_minus_x.populate::<E::BaseField>(
                &slope,
                &p_x_minus_x,
                FpOperation::Mul,
            );
            cols.y3_ins
                .populate::<E::BaseField>(&slope_times_p_x_minus_x, &p_y, FpOperation::Sub);
        }
    }
}

impl<F: Field, E: EllipticCurve, WP: WeierstrassParameters> Chip<F>
    for WeierstrassDoubleAssignChip<E, WP>
{
    fn name(&self) -> String {
        "WeierstrassDoubleAssign".to_string()
    }

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let mut new_field_events = Vec::new();

        for i in 0..segment.weierstrass_double_events.len() {
            let event = segment.weierstrass_double_events[i];
            let mut row = [F::zero(); NUM_WEIERSTRASS_DOUBLE_COLS];
            let cols: &mut WeierstrassDoubleAssignCols<F> = row.as_mut_slice().borrow_mut();

            // Decode affine points.
            let p = &event.p;
            let p = AffinePoint::<E>::from_words_le(p);
            let (p_x, p_y) = (p.x, p.y);

            // Populate basic columns.
            cols.is_real = F::one();
            cols.segment = F::from_canonical_u32(segment.index);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.p_ptr = F::from_canonical_u32(event.p_ptr);

            Self::populate_fp_ops(cols, p_x, p_y);

            // Populate the memory access columns.
            for i in 0..NUM_WORDS_EC_POINT {
                cols.p_access[i].populate(event.p_memory_records[i], &mut new_field_events);
            }

            rows.push(row);
        }
        segment.field_events.extend(new_field_events);

        pad_rows(&mut rows, || {
            let mut row = [F::zero(); NUM_WEIERSTRASS_DOUBLE_COLS];
            let cols: &mut WeierstrassDoubleAssignCols<F> = row.as_mut_slice().borrow_mut();
            let zero = BigUint::zero();
            Self::populate_fp_ops(cols, zero.clone(), zero.clone());
            row
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_WEIERSTRASS_DOUBLE_COLS,
        )
    }
}

impl<F, E: EllipticCurve, WP: WeierstrassParameters> BaseAir<F>
    for WeierstrassDoubleAssignChip<E, WP>
{
    fn width(&self) -> usize {
        NUM_WEIERSTRASS_DOUBLE_COLS
    }
}

impl<AB, E: EllipticCurve, WP: WeierstrassParameters> Air<AB> for WeierstrassDoubleAssignChip<E, WP>
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row: &WeierstrassDoubleAssignCols<AB::Var> = main.row_slice(0).borrow();

        let p_x = limbs_from_prev_access(&row.p_access[0..NUM_WORDS_FIELD_ELEMENT]);
        let p_y = limbs_from_prev_access(&row.p_access[NUM_WORDS_FIELD_ELEMENT..]);

        // a in the Weierstrass form: y^2 = x^3 + a * x + b.
        let a = limbs_from_biguint::<AB, E::BaseField>(&WP::a_int());

        // slope = slope_numerator / slope_denominator.
        let slope = {
            // slope_numerator = a + (p.x * p.x) * 3.
            {
                row.p_x_squared.eval::<AB, E::BaseField, _, _>(
                    builder,
                    &p_x,
                    &p_x,
                    FpOperation::Mul,
                );

                row.p_x_squared_times_3.eval::<AB, E::BaseField, _, _>(
                    builder,
                    &row.p_x_squared.result,
                    &limbs_from_biguint::<AB, E::BaseField>(&BigUint::from(3u32)),
                    FpOperation::Mul,
                );

                row.slope_numerator.eval::<AB, E::BaseField, _, _>(
                    builder,
                    &a,
                    &row.p_x_squared_times_3.result,
                    FpOperation::Add,
                );
            };

            // slope_denominator = 2 * y.
            row.slope_denominator.eval::<AB, E::BaseField, _, _>(
                builder,
                &limbs_from_biguint::<AB, E::BaseField>(&BigUint::from(2u32)),
                &p_y,
                FpOperation::Mul,
            );

            row.slope.eval::<AB, E::BaseField, _, _>(
                builder,
                &row.slope_numerator.result,
                &row.slope_denominator.result,
                FpOperation::Div,
            );

            row.slope.result
        };

        // x = slope * slope - (p.x + p.x).
        let x = {
            row.slope_squared.eval::<AB, E::BaseField, _, _>(
                builder,
                &slope,
                &slope,
                FpOperation::Mul,
            );
            row.p_x_plus_p_x
                .eval::<AB, E::BaseField, _, _>(builder, &p_x, &p_x, FpOperation::Add);
            row.x3_ins.eval::<AB, E::BaseField, _, _>(
                builder,
                &row.slope_squared.result,
                &row.p_x_plus_p_x.result,
                FpOperation::Sub,
            );
            row.x3_ins.result
        };

        // y = slope * (p.x - x) - p.y.
        {
            row.p_x_minus_x
                .eval::<AB, E::BaseField, _, _>(builder, &p_x, &x, FpOperation::Sub);
            row.slope_times_p_x_minus_x.eval::<AB, E::BaseField, _, _>(
                builder,
                &slope,
                &row.p_x_minus_x.result,
                FpOperation::Mul,
            );
            row.y3_ins.eval::<AB, E::BaseField, _, _>(
                builder,
                &row.slope_times_p_x_minus_x.result,
                &p_y,
                FpOperation::Sub,
            );
        }

        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]. This is to
        // ensure that p_access is updated with the new value.
        for i in 0..NUM_LIMBS {
            builder
                .when(row.is_real)
                .assert_eq(row.x3_ins.result[i], row.p_access[i / 4].value()[i % 4]);
            builder.when(row.is_real).assert_eq(
                row.y3_ins.result[i],
                row.p_access[NUM_WORDS_FIELD_ELEMENT + i / 4].value()[i % 4],
            );
        }

        builder.constraint_memory_access_slice(
            row.segment,
            row.clk + AB::F::from_canonical_u32(4), // clk + 4 -> Memory
            row.p_ptr,
            &row.p_access,
            row.is_real,
        );
    }
}

#[cfg(test)]
pub mod tests {

    use crate::{
        runtime::Program,
        utils::{prove, setup_logger, tests::SECP256K1_DOUBLE_ELF},
    };

    #[test]
    fn test_secp256k1_double_simple() {
        setup_logger();
        let program = Program::from(SECP256K1_DOUBLE_ELF);
        prove(program);
    }
}
