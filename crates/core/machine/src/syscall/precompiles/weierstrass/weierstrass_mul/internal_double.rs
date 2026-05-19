use super::{
    event_words_to_biguint, event_words_to_limbs,
    interactions::{internal_double_call, internal_memory_rw},
};
use crate::{
    air::SP1CoreAirBuilder,
    operations::field::{field_op::FieldOpCols, range::FieldLtCols},
    utils::zeroed_f_vec,
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use num::{BigUint, One};
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{
        ByteLookupEvent, ECMulInternalDoubleEvent, EllipticCurveMulEvent, FieldOperation,
        PrecompileEvent,
    },
    ExecutionRecord, Program, SyscallCode,
};
use sp1_curves::{
    params::{FieldParameters, Limbs, NumLimbs, NumWords},
    weierstrass::WeierstrassParameters,
    CurveType, EllipticCurve,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::{InteractionScope, MachineAir};
use std::{fmt::Debug, marker::PhantomData, mem::MaybeUninit};

pub const fn num_weierstrass_mul_internal_double_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<WeierstrassMulInternalDoubleCols<u8, P>>()
}

/// Number of internal-double events the controller emits for a single ECMUL precompile
/// event: `n - 1` where `n` is the scalar bit-length (the last double is always
/// skipped — see the controller's loop). Trapped user-mode events emit zero — not
/// yet handled here; see the TODO in `generate_trace_into`.
fn internal_double_count(event: &EllipticCurveMulEvent) -> usize {
    let nb_bits = event.exp_memory_records.len() * 64;
    nb_bits.saturating_sub(1)
}

/// Columns for the Internal Double chip used inside the EC scalar-multiplication chain.
///
/// Mirrors [`crate::syscall::precompiles::weierstrass::weierstrass_double::WeierstrassDoubleAssignCols`]
/// minus the main-memory access, syscall-receive, and mprotect machinery, which are
/// replaced by the internal memory and syscall bus interactions defined in
/// [`super::interactions`]. The output coordinates `ord_x = x3_ins.result` and
/// `ord_y = y3_ins.result` already live in the field-op cols; `irt` is forwarded
/// unchanged from the receive to the send.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassMulInternalDoubleCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub clk_high: T,
    pub clk_low: T,
    /// The internal step counter for this double's *receive*. The corresponding send
    /// is at `c + 1` on the memory bus.
    pub c: T,
    /// Input doubler (x-coordinate) carried in from the memory bus.
    pub ird_x: Limbs<T, <P as NumLimbs>::Limbs>,
    /// Input doubler (y-coordinate) carried in from the memory bus.
    pub ird_y: Limbs<T, <P as NumLimbs>::Limbs>,
    /// Input running total (x-coordinate). Forwarded unchanged on the send tuple.
    pub irt_x: Limbs<T, <P as NumLimbs>::Limbs>,
    /// Input running total (y-coordinate). Forwarded unchanged on the send tuple.
    pub irt_y: Limbs<T, <P as NumLimbs>::Limbs>,
    pub slope_denominator: FieldOpCols<T, P>,
    pub slope_numerator: FieldOpCols<T, P>,
    pub slope: FieldOpCols<T, P>,
    pub p_x_squared: FieldOpCols<T, P>,
    pub p_x_squared_times_3: FieldOpCols<T, P>,
    pub slope_squared: FieldOpCols<T, P>,
    pub p_x_plus_p_x: FieldOpCols<T, P>,
    pub x3_ins: FieldOpCols<T, P>,
    pub p_x_minus_x: FieldOpCols<T, P>,
    pub y3_ins: FieldOpCols<T, P>,
    pub slope_times_p_x_minus_x: FieldOpCols<T, P>,
    pub x3_range: FieldLtCols<T, P>,
    pub y3_range: FieldLtCols<T, P>,
}

/// A chip that constrains a single `double` step inside the EC scalar-multiplication chain.
#[derive(Default)]
pub struct WeierstrassMulInternalDoubleChip<E> {
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve + WeierstrassParameters> WeierstrassMulInternalDoubleChip<E> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }

    /// Fills in one internal-double row from an `ECMulInternalDoubleEvent` and the
    /// parent `EllipticCurveMulEvent`'s clock. Leaves out the syscall / main-memory /
    /// mprotect bookkeeping — this chip only sees the internal memory and opcode
    /// buses, which are driven by `(c, ird, irt)` plus the field-op witness columns.
    pub fn populate_row<F: PrimeField32>(
        event: &ECMulInternalDoubleEvent,
        clk: u64,
        cols: &mut WeierstrassMulInternalDoubleCols<F, E::BaseField>,
        new_byte_lookup_events: &mut Vec<ByteLookupEvent>,
    ) {
        cols.is_real = F::one();
        cols.clk_high = F::from_canonical_u32((clk >> 24) as u32);
        cols.clk_low = F::from_canonical_u32((clk & 0xFFFFFF) as u32);
        cols.c = F::from_canonical_u16(event.c);

        let half = event.ird.len() / 2;
        cols.ird_x = event_words_to_limbs(&event.ird[..half]);
        cols.ird_y = event_words_to_limbs(&event.ird[half..]);
        cols.irt_x = event_words_to_limbs(&event.irt[..half]);
        cols.irt_y = event_words_to_limbs(&event.irt[half..]);

        // `populate_field_ops` mirrors `WeierstrassDoubleAssignChip::populate_field_ops`
        // and only consumes the doubler (`p = ird`); `irt` is forwarded unchanged.
        Self::populate_field_ops(
            new_byte_lookup_events,
            cols,
            event_words_to_biguint(&event.ird[..half]),
            event_words_to_biguint(&event.ird[half..]),
        );
    }

    /// Populates the field-operation columns for one internal-double step:
    /// `ord = 2 * ird` (with `irt` forwarded unchanged elsewhere). Mirrors
    /// [`WeierstrassDoubleAssignChip::populate_field_ops`] verbatim.
    fn populate_field_ops<F: PrimeField32>(
        blu_events: &mut Vec<ByteLookupEvent>,
        cols: &mut WeierstrassMulInternalDoubleCols<F, E::BaseField>,
        p_x: BigUint,
        p_y: BigUint,
    ) {
        let a = E::a_int();
        let slope = {
            // slope_numerator = a + (p.x * p.x) * 3.
            let slope_numerator = {
                let p_x_squared =
                    cols.p_x_squared.populate(blu_events, &p_x, &p_x, FieldOperation::Mul);
                let p_x_squared_times_3 = cols.p_x_squared_times_3.populate(
                    blu_events,
                    &p_x_squared,
                    &BigUint::from(3u32),
                    FieldOperation::Mul,
                );
                cols.slope_numerator.populate(
                    blu_events,
                    &a,
                    &p_x_squared_times_3,
                    FieldOperation::Add,
                )
            };

            // slope_denominator = 2 * y.
            let slope_denominator = cols.slope_denominator.populate(
                blu_events,
                &BigUint::from(2u32),
                &p_y,
                FieldOperation::Mul,
            );

            cols.slope.populate(
                blu_events,
                &slope_numerator,
                &slope_denominator,
                FieldOperation::Div,
            )
        };

        // x = slope * slope - (p.x + p.x).
        let x = {
            let slope_squared =
                cols.slope_squared.populate(blu_events, &slope, &slope, FieldOperation::Mul);
            let p_x_plus_p_x =
                cols.p_x_plus_p_x.populate(blu_events, &p_x, &p_x, FieldOperation::Add);
            let x3 = cols.x3_ins.populate(
                blu_events,
                &slope_squared,
                &p_x_plus_p_x,
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
    for WeierstrassMulInternalDoubleChip<E>
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1MulInternalDouble",
            _ => panic!("Unsupported curve for WeierstrassMulInternalDoubleChip"),
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        // `nb_bits - 1` doubles per ECMUL event (last double is skipped). Trapped
        // events are not yet accounted for — see TODO in `generate_trace_into`.
        let nb_rows: usize = match E::CURVE_TYPE {
            CurveType::Secp256k1 => input
                .get_precompile_events(SyscallCode::SECP256K1_MUL)
                .iter()
                .map(|(_, op)| match op {
                    PrecompileEvent::Secp256k1Mul(event) => internal_double_count(event),
                    _ => 0,
                })
                .sum(),
            _ => panic!("Unsupported curve"),
        };
        Some(nb_rows.next_multiple_of(32).max(16))
    }

    fn generate_dependencies(&self, _input: &Self::Record, _output: &mut Self::Record) {
        // See the matching comment in `WeierstrassMulInternalAddChip`: the
        // byte-lookup events are produced inside `generate_trace_into` as the
        // channel drains, because the events only exist once the controller has
        // sent them.
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let padded_nb_rows =
            <WeierstrassMulInternalDoubleChip<E> as MachineAir<F>>::num_rows(self, input).unwrap();
        let num_cols =
            <WeierstrassMulInternalDoubleChip<E> as BaseAir<F>>::width(self);

        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => input.get_precompile_events(SyscallCode::SECP256K1_MUL),
            _ => panic!("Unsupported curve"),
        };

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * num_cols) };

        // Dummy row for padding. `populate_field_ops` requires `p_y != 0` (it
        // computes `slope = (a + 3*p_x^2) / (2*p_y)`), so use `(p_x, p_y) = (1, 1)`.
        let mut dummy_row = zeroed_f_vec::<F>(num_cols);
        {
            let cols: &mut WeierstrassMulInternalDoubleCols<F, E::BaseField> =
                dummy_row.as_mut_slice().borrow_mut();
            let one = BigUint::one();
            Self::populate_field_ops(&mut vec![], cols, one.clone(), one);
        }

        // Drain the controller's internal-double channel in ECMUL-event order.
        //
        // TODO: trapped user-mode rows produce zero internal events; the current
        // count assumes every ECMUL event contributes `nb_bits - 1` doubles, which
        // will deadlock on `recv()` if a user-mode event traps.
        let rx_arc = input.channels.ecmul_internal_double_channel.1.clone();
        let rx = rx_arc.lock().expect("internal double channel mutex poisoned");

        let mut row_idx = 0usize;
        let mut blu = Vec::new();
        for (_, op) in events.iter() {
            let event = match op {
                PrecompileEvent::Secp256k1Mul(e) => e,
                _ => continue,
            };
            let n = internal_double_count(event);
            for _ in 0..n {
                let internal_event =
                    rx.recv().expect("internal double channel disconnected before drain");
                let row =
                    &mut values[row_idx * num_cols..(row_idx + 1) * num_cols];
                let cols: &mut WeierstrassMulInternalDoubleCols<F, E::BaseField> =
                    row.borrow_mut();
                Self::populate_row(&internal_event, event.clk, cols, &mut blu);
                row_idx += 1;
            }
        }

        for i in row_idx..padded_nb_rows {
            let row = &mut values[i * num_cols..(i + 1) * num_cols];
            row.copy_from_slice(&dummy_row);
        }
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

impl<F, E: EllipticCurve + WeierstrassParameters> BaseAir<F>
    for WeierstrassMulInternalDoubleChip<E>
{
    fn width(&self) -> usize {
        num_weierstrass_mul_internal_double_cols::<E::BaseField>()
    }
}

impl<AB, E: EllipticCurve + WeierstrassParameters> Air<AB> for WeierstrassMulInternalDoubleChip<E>
where
    AB: SP1CoreAirBuilder,
    Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &WeierstrassMulInternalDoubleCols<AB::Var, E::BaseField> = (*local).borrow();

        builder.assert_bool(local.is_real);

        // EC double formula (mirrors `WeierstrassDoubleAssignChip::eval`):
        //   slope = (a + 3 * p.x^2) / (2 * p.y)
        //   x3    = slope^2 - 2 * p.x
        //   y3    = slope * (p.x - x3) - p.y
        //
        // `FieldOpCols::eval` accepts `&(impl Into<Polynomial<AB::Expr>>)` and
        // `Limbs<AB::Var, _>: Into<Polynomial<AB::Expr>>`, so we pass the `ird` /
        // `irt` columns directly without a `to_expr` step.
        let a = E::BaseField::to_limbs_field::<AB::Expr, _>(&E::a_int());
        let slope = {
            local.p_x_squared.eval(
                builder,
                &local.ird_x,
                &local.ird_x,
                FieldOperation::Mul,
                local.is_real,
            );
            local.p_x_squared_times_3.eval(
                builder,
                &local.p_x_squared.result,
                &E::BaseField::to_limbs_field::<AB::Expr, _>(&BigUint::from(3u32)),
                FieldOperation::Mul,
                local.is_real,
            );
            local.slope_numerator.eval(
                builder,
                &a,
                &local.p_x_squared_times_3.result,
                FieldOperation::Add,
                local.is_real,
            );
            local.slope_denominator.eval(
                builder,
                &E::BaseField::to_limbs_field::<AB::Expr, _>(&BigUint::from(2u32)),
                &local.ird_y,
                FieldOperation::Mul,
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
            local.p_x_plus_p_x.eval(
                builder,
                &local.ird_x,
                &local.ird_x,
                FieldOperation::Add,
                local.is_real,
            );
            local.x3_ins.eval(
                builder,
                &local.slope_squared.result,
                &local.p_x_plus_p_x.result,
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

        // Internal memory bus: receive `(clock, c, ird, irt)`, send `(clock, c+1,
        // ord = (x3, y3), irt)` with `irt` forwarded unchanged. Columns are passed
        // straight in; the helper handles `Var → Expr`.
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
                local.x3_ins.result,
                local.y3_ins.result,
                local.irt_x,
                local.irt_y,
                local.is_real,
            ),
            InteractionScope::Local,
        );

        // Internal opcode bus: receive a `Double` dispatch tuple from the controller.
        builder.receive(
            internal_double_call::<AB>(local.clk_high, local.clk_low, local.c, local.is_real),
            InteractionScope::Local,
        );
    }
}
