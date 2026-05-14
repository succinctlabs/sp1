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

use slop_air::AirBuilder;
use slop_algebra::AbstractField;
use sp1_curves::params::{Limbs, NumLimbs};
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

/// Build a tuple on the internal memory bus `EcMulMemory`:
/// `(clk_high, clk_low, c, doubler.x, doubler.y, total.x, total.y)`.
///
/// Used identically for sends and receives — the caller passes the result to
/// `builder.send(...)` or `builder.receive(...)`.
pub fn internal_memory_rw<AB, P>(
    clk_high: AB::Expr,
    clk_low: AB::Expr,
    c: AB::Expr,
    doubler_x: Limbs<AB::Expr, P::Limbs>,
    doubler_y: Limbs<AB::Expr, P::Limbs>,
    total_x: Limbs<AB::Expr, P::Limbs>,
    total_y: Limbs<AB::Expr, P::Limbs>,
    multiplicity: AB::Expr,
) -> AirInteraction<AB::Expr>
where
    AB: AirBuilder,
    P: NumLimbs,
{
    let mut values = Vec::with_capacity(3 + 4 * P::Limbs::USIZE);
    values.push(clk_high);
    values.push(clk_low);
    values.push(c);
    values.extend(doubler_x);
    values.extend(doubler_y);
    values.extend(total_x);
    values.extend(total_y);
    AirInteraction::new(values, multiplicity, InteractionKind::EcMulMemory)
}

/// Build a tuple on the internal opcode bus `EcMulOpcode` for a `Double` step:
/// `(clk_high, clk_low, c, EcMulOp::Double, DOUBLE_MARKER)`.
pub fn internal_double_call<AB>(
    clk_high: AB::Expr,
    clk_low: AB::Expr,
    c: AB::Expr,
    multiplicity: AB::Expr,
) -> AirInteraction<AB::Expr>
where
    AB: AirBuilder,
{
    let values = vec![
        clk_high,
        clk_low,
        c,
        EcMulOp::Double.as_expr::<AB::Expr>(),
        AB::Expr::from_canonical_u8(DOUBLE_MARKER),
    ];
    AirInteraction::new(values, multiplicity, InteractionKind::EcMulOpcode)
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
    clk_high: AB::Expr,
    clk_low: AB::Expr,
    c: AB::Expr,
    first_add_marker: AB::Expr,
    multiplicity: AB::Expr,
) -> AirInteraction<AB::Expr>
where
    AB: AirBuilder,
{
    let values = vec![clk_high, clk_low, c, EcMulOp::Add.as_expr::<AB::Expr>(), first_add_marker];
    AirInteraction::new(values, multiplicity, InteractionKind::EcMulOpcode)
}
