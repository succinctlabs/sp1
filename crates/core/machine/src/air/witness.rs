//! Trace-generation DSL: the witness-gen dual of [`SP1AirBuilder`].
//!
//! SP1 operations already express their *constraints* once via
//! [`crate::air::SP1Operation::lower`] against any [`SP1AirBuilder`], so the same
//! definition runs on multiple backends (constraint folding on host, the DAG
//! interpreter on GPU, verification, …). [`WitnessBuilder`] is the analogous
//! abstraction for *witness generation*: an operation's `witgen` is written once
//! against a `WitnessBuilder`, and the same body runs on different backends:
//!
//! * [`HostWitnessBuilder`] — `Nat = u64`, `Field = F`; every op computes
//!   immediately and writes the row columns / emits lookups. This reproduces the
//!   hand-written `populate` exactly.
//! * (future) a recording builder — `Nat = Field = WireId`; every op pushes onto a
//!   per-gadget op-DAG that a single generic CUDA kernel interprets per row, the
//!   way `zerocheck`/`branchingProgram` already interpret the constraint DAG on
//!   the GPU.
//!
//! The op-set is taken from SP1's real `populate` bodies (field/nat arithmetic,
//! bit extraction, nat→field casts, range/byte lookups, conditional select); add
//! ops only as gadgets need them. See `autoresearch/design/TRACEGEN-DSL.md`.

use std::marker::PhantomData;

use slop_algebra::Field;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};

/// Map a `ByteOpcode` discriminant (the value carried by a witgen opcode wire) back
/// to the enum. Kept in sync with `ByteOpcode` (`#[repr(u8)]`).
#[inline]
pub(crate) fn byte_opcode_from_u64(v: u64) -> ByteOpcode {
    match v {
        0 => ByteOpcode::AND,
        1 => ByteOpcode::OR,
        2 => ByteOpcode::XOR,
        3 => ByteOpcode::U8Range,
        4 => ByteOpcode::LTU,
        5 => ByteOpcode::MSB,
        6 => ByteOpcode::Range,
        _ => panic!("invalid ByteOpcode discriminant {v}"),
    }
}

/// A value-producing builder for trace generation. Implementors choose how each
/// op is realized (compute now, or record an op for a backend to run later).
///
/// `Nat` is an integer-typed wire (RISC-V words, limbs, indices); `Field` is a
/// field-element-typed wire (the actual trace column values).
pub trait WitnessBuilder {
    /// Integer-typed value (host: `u64`).
    type Nat: Copy;
    /// Field-element-typed value (host: the field `F`).
    type Field: Copy;

    /// A literal integer.
    fn const_nat(&mut self, value: u64) -> Self::Nat;

    /// Wrapping integer addition.
    fn wrapping_add(&mut self, a: Self::Nat, b: Self::Nat) -> Self::Nat;

    /// Wrapping integer subtraction.
    fn wrapping_sub(&mut self, a: Self::Nat, b: Self::Nat) -> Self::Nat;

    /// Extract `width` bits of `a` starting at bit `offset` (i.e. `(a >> offset) &
    /// ((1 << width) - 1)`). The common limb/byte decomposition primitive.
    fn bits(&mut self, a: Self::Nat, offset: u32, width: u32) -> Self::Nat;

    /// Integer equality: returns 1 if `a == b`, else 0.
    fn eq(&mut self, a: Self::Nat, b: Self::Nat) -> Self::Nat;

    /// Integer select: `cond` (0 or 1) ? `a` : `b`.
    fn select(&mut self, cond: Self::Nat, a: Self::Nat, b: Self::Nat) -> Self::Nat;

    /// Embed an integer into the field via the canonical representation.
    fn nat_to_field(&mut self, a: Self::Nat) -> Self::Field;

    /// Field addition.
    fn field_add(&mut self, a: Self::Field, b: Self::Field) -> Self::Field;

    /// Field multiplicative inverse (of a non-zero element).
    fn field_inverse(&mut self, a: Self::Field) -> Self::Field;

    /// Emit a `u16` range-check lookup for `a`.
    fn add_u16_range_check(&mut self, a: Self::Nat);

    /// Emit a `u8` range-check lookup verifying `a` and `b` are bytes.
    fn add_u8_range_check(&mut self, a: Self::Nat, b: Self::Nat);

    /// Emit a lookup proving `a < 2^bits`.
    fn add_bit_range_check(&mut self, a: Self::Nat, bits: u8);

    /// Emit a general byte-table lookup `{opcode, a, b, c}` where `opcode` is a
    /// `ByteOpcode` discriminant (0..=6). Covers the per-row-opcode byte ops
    /// (AND/OR/XOR/LTU/MSB) the bitwise/compare chips emit. The byte table's
    /// multiplicity is indexed by `(opcode, b, c)`; `a` (the result) is verified by
    /// the table, not part of the index.
    fn add_byte_lookup(&mut self, opcode: Self::Nat, a: Self::Nat, b: Self::Nat, c: Self::Nat);

    /// Begin a guarded scope: until the matching [`pop_guard`](Self::pop_guard),
    /// every emitted lookup is conditioned on `guard` (a 0/1 nat) — emitted only on
    /// rows where `guard != 0`. This lets a per-row branch (e.g. an immediate operand
    /// that skips its register read, or a mode flag) guard the lookups of the gadgets
    /// it composes WITHOUT changing those gadgets (the columns themselves are merged
    /// with [`select`](Self::select)). Single-level (scopes don't nest) for now.
    fn push_guard(&mut self, guard: Self::Nat);

    /// End the current guarded scope (lookups are unconditional again).
    fn pop_guard(&mut self);
}

/// Host (CPU) backend: every op is evaluated immediately on concrete values, and
/// lookups are forwarded to the shard's [`ByteRecord`]. Identical in behavior to
/// the hand-written `populate`.
pub struct HostWitnessBuilder<'a, F, R: ByteRecord> {
    record: &'a mut R,
    /// Current guard (`Some(0)` suppresses lookups; `None`/`Some(≠0)` emits them).
    guard: Option<u64>,
    _field: PhantomData<F>,
}

impl<'a, F, R: ByteRecord> HostWitnessBuilder<'a, F, R> {
    /// Create a host builder that emits lookups into `record`.
    pub fn new(record: &'a mut R) -> Self {
        Self { record, guard: None, _field: PhantomData }
    }

    /// Whether lookups are currently suppressed by an active guard of value 0.
    #[inline]
    fn suppressed(&self) -> bool {
        matches!(self.guard, Some(0))
    }
}

impl<F: Field, R: ByteRecord> WitnessBuilder for HostWitnessBuilder<'_, F, R> {
    type Nat = u64;
    type Field = F;

    #[inline]
    fn const_nat(&mut self, value: u64) -> u64 {
        value
    }

    #[inline]
    fn wrapping_add(&mut self, a: u64, b: u64) -> u64 {
        a.wrapping_add(b)
    }

    #[inline]
    fn wrapping_sub(&mut self, a: u64, b: u64) -> u64 {
        a.wrapping_sub(b)
    }

    #[inline]
    fn bits(&mut self, a: u64, offset: u32, width: u32) -> u64 {
        debug_assert!(width > 0 && width <= 64);
        let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
        (a >> offset) & mask
    }

    #[inline]
    fn eq(&mut self, a: u64, b: u64) -> u64 {
        u64::from(a == b)
    }

    #[inline]
    fn select(&mut self, cond: u64, a: u64, b: u64) -> u64 {
        if cond != 0 {
            a
        } else {
            b
        }
    }

    #[inline]
    fn nat_to_field(&mut self, a: u64) -> F {
        F::from_canonical_u64(a)
    }

    #[inline]
    fn field_add(&mut self, a: F, b: F) -> F {
        a + b
    }

    #[inline]
    fn field_inverse(&mut self, a: F) -> F {
        a.inverse()
    }

    #[inline]
    fn add_u16_range_check(&mut self, a: u64) {
        if self.suppressed() {
            return;
        }
        self.record.add_u16_range_check(a as u16);
    }

    #[inline]
    fn add_u8_range_check(&mut self, a: u64, b: u64) {
        if self.suppressed() {
            return;
        }
        self.record.add_u8_range_check(a as u8, b as u8);
    }

    #[inline]
    fn add_bit_range_check(&mut self, a: u64, bits: u8) {
        if self.suppressed() {
            return;
        }
        self.record.add_bit_range_check(a as u16, bits);
    }

    #[inline]
    fn add_byte_lookup(&mut self, opcode: u64, a: u64, b: u64, c: u64) {
        if self.suppressed() {
            return;
        }
        self.record.add_byte_lookup_event(ByteLookupEvent {
            opcode: byte_opcode_from_u64(opcode),
            a: a as u16,
            b: b as u8,
            c: c as u8,
        });
    }

    #[inline]
    fn push_guard(&mut self, guard: u64) {
        self.guard = Some(guard);
    }

    #[inline]
    fn pop_guard(&mut self) {
        self.guard = None;
    }
}
