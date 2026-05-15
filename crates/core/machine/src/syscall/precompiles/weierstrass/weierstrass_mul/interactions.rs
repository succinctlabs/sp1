//! Custom interactions used by the EC scalar-multiplication chip family.
//!
//! These helpers package the two internal buses so the controller and the internal
//! Add / Double chips can construct the right tuples without re-listing every column
//! at each send/receive site:
//!
//! - `EcMulMemory` carries the chain state `(clock, c, running_doubler, running_total)`.
//! - `EcMulOpcode` carries the per-step dispatch `(clock, c, op, first_add_marker)`.
//!
//! Multiplicities passed in here are taken at face value — callers are responsible
//! for gating them by `is_real * is_not_trap` (or equivalent) where applicable.

use num::BigUint;
use slop_air::AirBuilder;
use slop_algebra::AbstractField;
use sp1_curves::params::FieldParameters;
use sp1_curves::{
    params::{Limbs, NumLimbs},
    EllipticCurve,
};
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

/// Outputs an invalid point to represent the identity for the internal memory bus
///
/// TODO: make sure this point is always invalid for general Weierstrass curves
pub fn ec_identity<E, AB>() -> [Limbs<AB::Expr, <E::BaseField as NumLimbs>::Limbs>; 2]
where
    E: EllipticCurve,
    AB: slop_air::AirBuilder,
{
    let zero = || E::BaseField::to_limbs_field::<AB::Expr, AB::F>(&BigUint::from(0u32));
    [zero(), zero()]
}

/// Build a tuple on the internal memory bus `EcMulMemory`:
/// `(clk_high, clk_low, c, doubler.x, doubler.y, total.x, total.y)`.
///
/// Used identically for sends and receives — the caller passes the result to
/// `builder.send(...)` or `builder.receive(...)`. Each scalar and each limb
/// element is accepted as `impl Into<AB::Expr>`, so callers can pass column
/// vars, expressions, or pre-converted `Limbs<AB::Expr, _>` interchangeably and
/// the four limb args may even have different element types.
#[allow(clippy::too_many_arguments)]
pub fn internal_memory_rw<AB, P>(
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
    AB: AirBuilder,
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

/// Build a tuple on the internal opcode bus `EcMulOpcode` for a `Double` step:
/// `(clk_high, clk_low, c, EcMulOp::Double, DOUBLE_MARKER)`.
pub fn internal_double_call<AB>(
    clk_high: impl Into<AB::Expr>,
    clk_low: impl Into<AB::Expr>,
    c: impl Into<AB::Expr>,
    multiplicity: impl Into<AB::Expr>,
) -> AirInteraction<AB::Expr>
where
    AB: AirBuilder,
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

/// Build a tuple on the internal opcode bus `EcMulOpcode` for an `Add` step:
/// `(clk_high, clk_low, c, EcMulOp::Add, first_add_marker)`.
///
/// `first_add_marker` is the prefix bit-sum `S_{i-1}` (always an affine LC of the
/// controller's bit columns, never its own column):
///   - `0` for the first add — consumed by the controller's first-add receive.
///   - non-zero for every subsequent add — consumed by the Internal Add chip,
///     which enforces non-zeroness via `first_add_marker * inverse_fam = 1`.
pub fn internal_add_call<AB>(
    clk_high: impl Into<AB::Expr>,
    clk_low: impl Into<AB::Expr>,
    c: impl Into<AB::Expr>,
    first_add_marker: impl Into<AB::Expr>,
    multiplicity: impl Into<AB::Expr>,
) -> AirInteraction<AB::Expr>
where
    AB: AirBuilder,
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
