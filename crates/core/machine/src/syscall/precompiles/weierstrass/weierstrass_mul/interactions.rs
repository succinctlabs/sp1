//! Custom interactions used by the EC scalar-multiplication chip family.
//!
//! The two internal buses are exposed as methods on the [`EcMulAirBuilder`] extension
//! trait so the controller and the internal Add / Double chips can do
//! `builder.send_ec_mul_internal_memory_event(...)` etc. without re-listing every
//! column at each send/receive site:
//!
//! - `EcMulMemory` carries the chain state `(clock, c, running_doubler, running_total)`.
//! - `EcMulOpcode` carries the per-step dispatch `(clock, c, op, first_add_marker)`.
//!
//! All sends/receives are on the `InteractionScope::Local` scope (these are
//! intra-chip-family buses). Multiplicities passed in here are taken at face value —
//! callers are responsible for gating them by `is_real * is_not_trap` (or equivalent)
//! where applicable.

use num::BigUint;
use slop_algebra::AbstractField;
use sp1_curves::params::FieldParameters;
use sp1_curves::{
    params::{Limbs, NumLimbs},
    EllipticCurve,
};
use sp1_hypercube::air::{InteractionScope, SP1AirBuilder};
use sp1_hypercube::{air::AirInteraction, InteractionKind};
use typenum::Unsigned;

/// Discriminator on the internal opcode bus identifying which internal chip should
/// consume a tuple. Picked as distinct small non-zero field elements so a malicious
/// prover cannot alias an `Add` send onto a `Double` receive by shuffling tuples that
/// happen to share their other coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EcMulOp {
    Add = 1,
    Double = 2,
}

impl EcMulOp {
    pub fn as_expr<F: AbstractField>(self) -> F {
        F::from_canonical_u8(self as u8)
    }
}

/// Marker value carried on `EcMulOpcode` tuples for `Double` steps. Adds carry the
/// prefix bit-sum `S_{i-1}` instead, which is `0` only at the very first set bit.
pub const DOUBLE_MARKER: u8 = 1;

/// Outputs an invalid point to represent the identity for the internal memory bus.
///
/// TODO: make sure this point is always invalid for general Weierstrass curves.
pub fn ec_identity<E, AB>() -> [Limbs<AB::Expr, <E::BaseField as NumLimbs>::Limbs>; 2]
where
    E: EllipticCurve,
    AB: slop_air::AirBuilder,
{
    let zero = || E::BaseField::to_limbs_field::<AB::Expr, AB::F>(&BigUint::from(0u32));
    [zero(), zero()]
}

/// Extension trait providing `send_*` / `receive_*` helpers for the EC scalar-mul
/// internal buses. Implemented for every `SP1AirBuilder` via a blanket impl, so any
/// chip eval method that has `AB: SP1AirBuilder` automatically gets these methods.
///
/// Each scalar and each limb element is accepted as `impl Into<Self::Expr>`, so
/// callers can pass column vars, expressions, or pre-converted `Limbs<Self::Expr, _>`
/// interchangeably and the four limb args may even have different element types.
pub trait EcMulAirBuilder: SP1AirBuilder {
    /// Send a tuple on the internal memory bus `EcMulMemory`:
    /// `(clk_high, clk_low, c, doubler.x, doubler.y, total.x, total.y)`.
    #[allow(clippy::too_many_arguments)]
    fn send_ec_mul_internal_memory_event<P: NumLimbs>(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        doubler_x: Limbs<impl Into<Self::Expr>, P::Limbs>,
        doubler_y: Limbs<impl Into<Self::Expr>, P::Limbs>,
        total_x: Limbs<impl Into<Self::Expr>, P::Limbs>,
        total_y: Limbs<impl Into<Self::Expr>, P::Limbs>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.send(
            ec_mul_internal_memory_tuple::<Self, P>(
                clk_high,
                clk_low,
                c,
                doubler_x,
                doubler_y,
                total_x,
                total_y,
                multiplicity,
            ),
            InteractionScope::Local,
        );
    }

    /// Receive a tuple on the internal memory bus `EcMulMemory`. See
    /// [`Self::send_ec_mul_internal_memory_event`].
    #[allow(clippy::too_many_arguments)]
    fn receive_ec_mul_internal_memory_event<P: NumLimbs>(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        doubler_x: Limbs<impl Into<Self::Expr>, P::Limbs>,
        doubler_y: Limbs<impl Into<Self::Expr>, P::Limbs>,
        total_x: Limbs<impl Into<Self::Expr>, P::Limbs>,
        total_y: Limbs<impl Into<Self::Expr>, P::Limbs>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.receive(
            ec_mul_internal_memory_tuple::<Self, P>(
                clk_high,
                clk_low,
                c,
                doubler_x,
                doubler_y,
                total_x,
                total_y,
                multiplicity,
            ),
            InteractionScope::Local,
        );
    }

    /// Send a tuple on the internal opcode bus `EcMulOpcode` for an `Add` step:
    /// `(clk_high, clk_low, c, EcMulOp::Add, first_add_marker)`.
    ///
    /// `first_add_marker` is the prefix bit-sum `S_{i-1}` (always an affine LC of the
    /// controller's bit columns, never its own column):
    ///   - `0` for the first add — consumed by the controller's first-add receive.
    ///   - non-zero for every subsequent add — consumed by the Internal Add chip,
    ///     which enforces non-zeroness via `first_add_marker * inverse_fam = 1`.
    fn send_ec_mul_internal_add_call(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        first_add_marker: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.send(
            ec_mul_internal_add_tuple::<Self>(clk_high, clk_low, c, first_add_marker, multiplicity),
            InteractionScope::Local,
        );
    }

    /// Receive a tuple on the internal opcode bus `EcMulOpcode` for an `Add` step.
    /// See [`Self::send_ec_mul_internal_add_call`].
    fn receive_ec_mul_internal_add_call(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        first_add_marker: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.receive(
            ec_mul_internal_add_tuple::<Self>(clk_high, clk_low, c, first_add_marker, multiplicity),
            InteractionScope::Local,
        );
    }

    /// Send a tuple on the internal opcode bus `EcMulOpcode` for a `Double` step:
    /// `(clk_high, clk_low, c, EcMulOp::Double, DOUBLE_MARKER)`.
    fn send_ec_mul_internal_double_call(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.send(
            ec_mul_internal_double_tuple::<Self>(clk_high, clk_low, c, multiplicity),
            InteractionScope::Local,
        );
    }

    /// Receive a tuple on the internal opcode bus `EcMulOpcode` for a `Double` step.
    /// See [`Self::send_ec_mul_internal_double_call`].
    fn receive_ec_mul_internal_double_call(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.receive(
            ec_mul_internal_double_tuple::<Self>(clk_high, clk_low, c, multiplicity),
            InteractionScope::Local,
        );
    }
}

impl<AB: SP1AirBuilder> EcMulAirBuilder for AB {}

#[allow(clippy::too_many_arguments)]
fn ec_mul_internal_memory_tuple<AB, P>(
    clk_high: impl Into<AB::Expr>,
    clk_low: impl Into<AB::Expr>,
    c: impl Into<AB::Expr>,
    doubler_x: Limbs<impl Into<AB::Expr>, P::Limbs>,
    doubler_y: Limbs<impl Into<AB::Expr>, P::Limbs>,
    total_x: Limbs<impl Into<AB::Expr>, P::Limbs>,
    total_y: Limbs<impl Into<AB::Expr>, P::Limbs>,
    multiplicity: impl Into<AB::Expr>,
) -> AirInteraction<AB::Expr>
where
    AB: SP1AirBuilder,
    P: NumLimbs,
{
    let mut values = Vec::with_capacity(3 + 4 * P::Limbs::USIZE);
    values.push(clk_high.into());
    values.push(clk_low.into());
    values.push(c.into());
    values.extend(doubler_x.0.into_iter().map(Into::into));
    values.extend(doubler_y.0.into_iter().map(Into::into));
    values.extend(total_x.0.into_iter().map(Into::into));
    values.extend(total_y.0.into_iter().map(Into::into));
    AirInteraction::new(values, multiplicity.into(), InteractionKind::EcMulMemory)
}

fn ec_mul_internal_add_tuple<AB>(
    clk_high: impl Into<AB::Expr>,
    clk_low: impl Into<AB::Expr>,
    c: impl Into<AB::Expr>,
    first_add_marker: impl Into<AB::Expr>,
    multiplicity: impl Into<AB::Expr>,
) -> AirInteraction<AB::Expr>
where
    AB: SP1AirBuilder,
{
    let values = vec![
        clk_high.into(),
        clk_low.into(),
        c.into(),
        EcMulOp::Add.as_expr::<AB::Expr>(),
        first_add_marker.into(),
    ];
    AirInteraction::new(values, multiplicity.into(), InteractionKind::EcMulOpcode)
}

fn ec_mul_internal_double_tuple<AB>(
    clk_high: impl Into<AB::Expr>,
    clk_low: impl Into<AB::Expr>,
    c: impl Into<AB::Expr>,
    multiplicity: impl Into<AB::Expr>,
) -> AirInteraction<AB::Expr>
where
    AB: SP1AirBuilder,
{
    let values = vec![
        clk_high.into(),
        clk_low.into(),
        c.into(),
        EcMulOp::Double.as_expr::<AB::Expr>(),
        AB::Expr::from_canonical_u8(DOUBLE_MARKER),
    ];
    AirInteraction::new(values, multiplicity.into(), InteractionKind::EcMulOpcode)
}
