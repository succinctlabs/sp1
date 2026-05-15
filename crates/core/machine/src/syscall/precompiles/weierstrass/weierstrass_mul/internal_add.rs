use super::interactions::{internal_add_call, internal_memory_rw};
use crate::{
    air::SP1CoreAirBuilder,
    operations::field::{field_op::FieldOpCols, range::FieldLtCols},
};
use core::{borrow::Borrow, mem::size_of};
use num::{BigUint, One};
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, FieldOperation},
    ExecutionRecord, Program, SyscallCode,
};
use sp1_curves::{
    params::{FieldParameters, Limbs, NumLimbs, NumWords},
    weierstrass::WeierstrassParameters,
    CurveType, EllipticCurve,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::{InteractionScope, MachineAir};
use sp1_primitives::polynomial::Polynomial;
use std::{fmt::Debug, marker::PhantomData, mem::MaybeUninit};
use typenum::Unsigned;

pub const fn num_weierstrass_mul_internal_add_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<WeierstrassMulInternalAddCols<u8, P>>()
}

/// Columns for the Internal Add chip used inside the EC scalar-multiplication chain.
///
/// Mirrors [`crate::syscall::precompiles::weierstrass::weierstrass_add::WeierstrassAddAssignCols`]
/// minus the main-memory access, syscall-receive, and mprotect machinery, which are
/// replaced by the internal memory and syscall bus interactions defined in
/// [`super::interactions`]. The output coordinates `ort_x = x3_ins.result` and
/// `ort_y = y3_ins.result` already live in the field-op cols; `ird` is forwarded
/// unchanged from the receive to the send (i.e., `ord = ird`, no extra column).
///
/// This chip handles every add *except* the very first one — the first add lives on
/// the controller, since the running total is the EC identity at that point and the
/// affine add formula doesn't apply. The `first_add_marker * inverse_fam = 1` check
/// below forces `first_add_marker != 0`, so the controller's `(clock, c, Add, 0)`
/// receive can't be aliased onto this chip.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassMulInternalAddCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub clk_high: T,
    pub clk_low: T,
    /// The internal step counter for this add's *receive*. The corresponding send
    /// is at `c + 1` on the memory bus.
    pub c: T,
    /// Prefix bit-sum `S_{i-1}` carried on the opcode bus. The constraint
    /// `first_add_marker * inverse_fam = 1` forces this non-zero, so this chip can
    /// only consume non-first adds.
    pub first_add_marker: T,
    /// Multiplicative inverse of `first_add_marker`, used to prove non-zeroness.
    pub inverse_fam: T,
    /// Input doubler (x-coordinate). Forwarded unchanged on the send tuple.
    pub ird_x: Limbs<T, <P as NumLimbs>::Limbs>,
    /// Input doubler (y-coordinate). Forwarded unchanged on the send tuple.
    pub ird_y: Limbs<T, <P as NumLimbs>::Limbs>,
    /// Input running total (x-coordinate). Replaced by `ort = x3_ins.result` on the send.
    pub irt_x: Limbs<T, <P as NumLimbs>::Limbs>,
    /// Input running total (y-coordinate). Replaced by `ort = y3_ins.result` on the send.
    pub irt_y: Limbs<T, <P as NumLimbs>::Limbs>,
    pub slope_numerator: FieldOpCols<T, P>,
    pub slope_denominator: FieldOpCols<T, P>,
    pub inverse_check: FieldOpCols<T, P>,
    pub slope: FieldOpCols<T, P>,
    pub slope_squared: FieldOpCols<T, P>,
    pub p_x_plus_q_x: FieldOpCols<T, P>,
    pub x3_ins: FieldOpCols<T, P>,
    pub p_x_minus_x: FieldOpCols<T, P>,
    pub y3_ins: FieldOpCols<T, P>,
    pub slope_times_p_x_minus_x: FieldOpCols<T, P>,
    pub x3_range: FieldLtCols<T, P>,
    pub y3_range: FieldLtCols<T, P>,
}

/// A chip that constrains a single non-first `add` step inside the EC scalar-multiplication
/// chain. The first add is folded into the controller chip; this chip handles every
/// subsequent add (those with `first_add_marker != 0`).
#[derive(Default)]
pub struct WeierstrassMulInternalAddChip<E> {
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve + WeierstrassParameters> WeierstrassMulInternalAddChip<E> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }

    /// Populates the field-operation columns for one internal-add step:
    /// `ort = ird + irt` (with `ord = ird` forwarded unchanged elsewhere). Mirrors
    /// [`WeierstrassAddAssignChip::populate_field_ops`] verbatim, with `p = ird` and
    /// `q = irt`.
    fn populate_field_ops<F: PrimeField32>(
        blu_events: &mut Vec<ByteLookupEvent>,
        cols: &mut WeierstrassMulInternalAddCols<F, E::BaseField>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
    ) {
        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            let slope_numerator =
                cols.slope_numerator.populate(blu_events, &q_y, &p_y, FieldOperation::Sub);
            let slope_denominator =
                cols.slope_denominator.populate(blu_events, &q_x, &p_x, FieldOperation::Sub);
            cols.inverse_check.populate(
                blu_events,
                &BigUint::one(),
                &slope_denominator,
                FieldOperation::Div,
            );
            cols.slope.populate(
                blu_events,
                &slope_numerator,
                &slope_denominator,
                FieldOperation::Div,
            )
        };

        // x = slope * slope - (p.x + q.x).
        let x = {
            let slope_squared =
                cols.slope_squared.populate(blu_events, &slope, &slope, FieldOperation::Mul);
            let p_x_plus_q_x =
                cols.p_x_plus_q_x.populate(blu_events, &p_x, &q_x, FieldOperation::Add);
            let x3 = cols.x3_ins.populate(
                blu_events,
                &slope_squared,
                &p_x_plus_q_x,
                FieldOperation::Sub,
            );
            cols.x3_range.populate(blu_events, &x3, &E::BaseField::modulus());
            x3
        };

        // y = slope * (p.x - x) - p.y.
        {
            let p_x_minus_x = cols.p_x_minus_x.populate(blu_events, &p_x, &x, FieldOperation::Sub);
            let slope_times_p_x_minus_x = cols.slope_times_p_x_minus_x.populate(
                blu_events,
                &slope,
                &p_x_minus_x,
                FieldOperation::Mul,
            );
            let y3 = cols.y3_ins.populate(
                blu_events,
                &slope_times_p_x_minus_x,
                &p_y,
                FieldOperation::Sub,
            );
            cols.y3_range.populate(blu_events, &y3, &E::BaseField::modulus());
        }
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> MachineAir<F>
    for WeierstrassMulInternalAddChip<E>
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1MulInternalAdd",
            _ => panic!("Unsupported curve for WeierstrassMulInternalAddChip"),
        }
    }

    fn num_rows(&self, _input: &Self::Record) -> Option<usize> {
        // TODO: at most 255 rows per `SECP256K1_MUL` event (one per non-first add step).
        todo!()
    }

    fn generate_dependencies(&self, _input: &Self::Record, _output: &mut Self::Record) {
        // TODO: iterate the non-first adds inside each `Secp256k1Mul` precompile event
        // and call `populate_field_ops` per step to harvest the byte-lookup events.
    }

    fn generate_trace_into(
        &self,
        _input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        _buffer: &mut [MaybeUninit<F>],
    ) {
        todo!()
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => {
                    !shard.get_precompile_events(SyscallCode::SECP256K1_MUL).is_empty()
                }
                _ => false,
            }
        }
    }
}

impl<F, E: EllipticCurve + WeierstrassParameters> BaseAir<F> for WeierstrassMulInternalAddChip<E> {
    fn width(&self) -> usize {
        num_weierstrass_mul_internal_add_cols::<E::BaseField>()
    }
}

impl<AB, E: EllipticCurve + WeierstrassParameters> Air<AB> for WeierstrassMulInternalAddChip<E>
where
    AB: SP1CoreAirBuilder,
    Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &WeierstrassMulInternalAddCols<AB::Var, E::BaseField> = (*local).borrow();

        builder.assert_bool(local.is_real);

        // Non-first-add discriminator: `first_add_marker * inverse_fam = 1`, gated by
        // `is_real`. The first-add receive on the controller hardcodes a marker of `0`,
        // so this constraint is exactly what stops it from being aliased onto this chip.
        let marker: AB::Expr = local.first_add_marker.into();
        let inv_fam: AB::Expr = local.inverse_fam.into();
        builder.when(local.is_real).assert_eq(marker * inv_fam, AB::Expr::one());

        // EC add formula (mirrors `WeierstrassAddAssignChip::eval`), with `p = ird` and
        // `q = irt`. The result `(x3, y3)` is `ort = ird + irt`. `inverse_check` proves
        // `(q.x - p.x)` is invertible (i.e. non-zero), so the chip rejects the
        // `ird = ±irt` degeneracies on which the affine add formula would otherwise
        // compute garbage. `FieldOpCols::eval` accepts column references directly via
        // `Limbs<AB::Var, _>: Into<Polynomial<AB::Expr>>`, so no `to_expr` step is needed.
        //
        //   slope = (q.y - p.y) / (q.x - p.x)
        //   x3    = slope^2 - (p.x + q.x)
        //   y3    = slope * (p.x - x3) - p.y
        let slope = {
            local.slope_numerator.eval(
                builder,
                &local.irt_y,
                &local.ird_y,
                FieldOperation::Sub,
                local.is_real,
            );
            local.slope_denominator.eval(
                builder,
                &local.irt_x,
                &local.ird_x,
                FieldOperation::Sub,
                local.is_real,
            );

            let mut coeff_1 = Vec::new();
            coeff_1.resize(<E::BaseField as NumLimbs>::Limbs::USIZE, AB::Expr::zero());
            coeff_1[0] = AB::Expr::one();
            let one_polynomial = Polynomial::from_coefficients(&coeff_1);

            local.inverse_check.eval(
                builder,
                &one_polynomial,
                &local.slope_denominator.result,
                FieldOperation::Div,
                local.is_real,
            );

            local.slope.eval(
                builder,
                &local.slope_numerator.result,
                &local.slope_denominator.result,
                FieldOperation::Div,
                local.is_real,
            );

            &local.slope.result
        };

        let x = {
            local.slope_squared.eval(builder, slope, slope, FieldOperation::Mul, local.is_real);
            local.p_x_plus_q_x.eval(
                builder,
                &local.ird_x,
                &local.irt_x,
                FieldOperation::Add,
                local.is_real,
            );
            local.x3_ins.eval(
                builder,
                &local.slope_squared.result,
                &local.p_x_plus_q_x.result,
                FieldOperation::Sub,
                local.is_real,
            );
            &local.x3_ins.result
        };

        {
            local.p_x_minus_x.eval(builder, &local.ird_x, x, FieldOperation::Sub, local.is_real);
            local.slope_times_p_x_minus_x.eval(
                builder,
                slope,
                &local.p_x_minus_x.result,
                FieldOperation::Mul,
                local.is_real,
            );
            local.y3_ins.eval(
                builder,
                &local.slope_times_p_x_minus_x.result,
                &local.ird_y,
                FieldOperation::Sub,
                local.is_real,
            );
        }

        let modulus = E::BaseField::to_limbs_field::<AB::Expr, AB::F>(&E::BaseField::modulus());
        local.x3_range.eval(builder, &local.x3_ins.result, &modulus, local.is_real);
        local.y3_range.eval(builder, &local.y3_ins.result, &modulus, local.is_real);

        // Internal memory bus: receive `(clock, c, ird, irt)` and send
        // `(clock, c+1, ord = ird, ort = (x3, y3))` with `ord` forwarded unchanged.
        builder.receive(
            internal_memory_rw::<AB, E::BaseField>(
                local.clk_high,
                local.clk_low,
                local.c,
                local.ird_x,
                local.ird_y,
                local.irt_x,
                local.irt_y,
                local.is_real,
            ),
            InteractionScope::Local,
        );
        builder.send(
            internal_memory_rw::<AB, E::BaseField>(
                local.clk_high,
                local.clk_low,
                local.c.into() + AB::Expr::one(),
                local.ird_x,
                local.ird_y,
                local.x3_ins.result,
                local.y3_ins.result,
                local.is_real,
            ),
            InteractionScope::Local,
        );

        // Internal opcode bus: receive an `Add` dispatch tuple from the controller.
        builder.receive(
            internal_add_call::<AB>(
                local.clk_high,
                local.clk_low,
                local.c,
                local.first_add_marker,
                local.is_real,
            ),
            InteractionScope::Local,
        );
    }
}
