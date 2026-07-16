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
//! * [`RecordingWitnessBuilder`](super::RecordingWitnessBuilder) — `Nat = Field =
//!   WireId`; every op pushes onto a per-gadget op-DAG that a single generic CUDA
//!   kernel interprets per row, the way `zerocheck`/`branchingProgram` already
//!   interpret the constraint DAG on the GPU.
//!
//! The op-set is taken from SP1's real `populate` bodies (field/nat arithmetic,
//! bit extraction, nat→field casts, range/byte lookups, conditional select); add
//! ops only as gadgets need them. See `WITGEN-IR.md` (in this directory) for the
//! IR spec and the chip-porting recipe.

use std::marker::PhantomData;

use slop_algebra::Field;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};

/// Contract-checked variable left shift for the CPU witgen backends. `shift < 64`
/// is an executor invariant: out of contract, the host (release: Rust masks the
/// shift amount) and the GPU kernels (hardware-masked) are NOT guaranteed to
/// agree, so violations must fail loudly on host first — here, in debug builds.
#[inline]
pub(crate) fn wit_shl(a: u64, shift: u64) -> u64 {
    debug_assert!(shift < 64, "witgen Shl out of contract: shift={shift} >= 64");
    a << shift
}

/// Contract-checked variable right shift — see [`wit_shl`].
#[inline]
pub(crate) fn wit_shr(a: u64, shift: u64) -> u64 {
    debug_assert!(shift < 64, "witgen Shr out of contract: shift={shift} >= 64");
    a >> shift
}

/// Contract-checked nat→field embed for the CPU witgen backends. The witgen
/// contract requires the nat to be canonical (`< P`); out of contract the host
/// and the GPU kernel disagree (the kernel reduces mod P). `from_canonical_u64`
/// debug-asserts canonicity for the concrete `SP1Field`, so violations fail
/// loudly on host in debug builds; this wrapper exists to make that contract
/// explicit at every backend's `NatToField`.
#[inline]
pub(crate) fn wit_nat_to_field<F: Field>(a: u64) -> F {
    F::from_canonical_u64(a)
}

/// Map a `ByteOpcode` discriminant (the value carried by a witgen opcode wire) back
/// to the enum. `ByteOpcode` pins its discriminants explicitly (`AND = 0` …
/// `Range = 6` in opcode.rs), so this mapping is stable by construction — keep the
/// two in sync if an opcode is ever added.
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

    /// Variable left shift: `a << shift` (shift is a per-row nat). Unlike [`bits`],
    /// the shift amount is data-dependent (needed by the shift chips).
    fn shl(&mut self, a: Self::Nat, shift: Self::Nat) -> Self::Nat;

    /// Variable right shift: `a >> shift` (shift is a per-row nat).
    fn shr(&mut self, a: Self::Nat, shift: Self::Nat) -> Self::Nat;

    /// Wrapping integer multiplication. Inputs are small (byte-sized in the Mul
    /// chip's convolution) so the product fits a `u64` without overflow.
    fn mul(&mut self, a: Self::Nat, b: Self::Nat) -> Self::Nat;

    /// Bitwise XOR (needed by the SHA precompiles' xor/not u32 gadgets).
    fn xor(&mut self, a: Self::Nat, b: Self::Nat) -> Self::Nat;

    /// Bitwise AND (needed by the SHA precompiles' and u32 gadget).
    fn and(&mut self, a: Self::Nat, b: Self::Nat) -> Self::Nat;

    /// Integer select: `cond` (0 or 1) ? `a` : `b`.
    fn select(&mut self, cond: Self::Nat, a: Self::Nat, b: Self::Nat) -> Self::Nat;

    /// Embed an integer into the field via the canonical representation.
    fn nat_to_field(&mut self, a: Self::Nat) -> Self::Field;

    /// Field addition.
    fn field_add(&mut self, a: Self::Field, b: Self::Field) -> Self::Field;

    /// Field subtraction.
    fn field_sub(&mut self, a: Self::Field, b: Self::Field) -> Self::Field;

    /// Field multiplicative inverse (of a non-zero element).
    fn field_inverse(&mut self, a: Self::Field) -> Self::Field;

    /// Field select: `cond` (a 0/1 nat) ? `a` : `b`. Merges field columns between two
    /// per-row branches (e.g. an immediate operand's columns vs a register read's),
    /// paired with [`push_guard`](Self::push_guard) for the branches' lookups.
    fn field_select(&mut self, cond: Self::Nat, a: Self::Field, b: Self::Field) -> Self::Field;

    /// Emit a `u16` range-check lookup for `a`.
    fn add_u16_range_check(&mut self, a: Self::Nat);

    /// Emit a `u8` range-check lookup verifying `a` and `b` are bytes.
    fn add_u8_range_check(&mut self, a: Self::Nat, b: Self::Nat);

    /// Emit a lookup proving `a < 2^bits`.
    fn add_bit_range_check(&mut self, a: Self::Nat, bits: u8);

    /// Emit a lookup proving `a < 2^bits` where `bits` is a per-row nat (variable
    /// width — needed by the shift chips, whose limb splits depend on the shift).
    fn add_bit_range_check_var(&mut self, a: Self::Nat, bits: Self::Nat);

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
    /// with [`select`](Self::select)). Scopes nest: the effective guard is the AND
    /// (product) of all enclosing scopes, on every backend.
    fn push_guard(&mut self, guard: Self::Nat);

    /// End the current guarded scope (lookups are unconditional again).
    fn pop_guard(&mut self);
}

/// Host (CPU) backend: every op is evaluated immediately on concrete values, and
/// lookups are forwarded to the shard's [`ByteRecord`]. Identical in behavior to
/// the hand-written `populate`.
pub struct HostWitnessBuilder<'a, F, R: ByteRecord> {
    record: &'a mut R,
    /// Stack of effective guards (the AND/product of all enclosing scopes). A scope
    /// suppresses lookups iff the top is 0. Nesting multiplies, so an inner gadget's
    /// own `push_guard` composes with the caller's rather than overwriting it.
    guard_stack: Vec<u64>,
    _field: PhantomData<F>,
}

impl<'a, F, R: ByteRecord> HostWitnessBuilder<'a, F, R> {
    /// Create a host builder that emits lookups into `record`.
    pub fn new(record: &'a mut R) -> Self {
        Self { record, guard_stack: Vec::new(), _field: PhantomData }
    }

    /// Whether lookups are currently suppressed by an active guard of value 0.
    #[inline]
    fn suppressed(&self) -> bool {
        matches!(self.guard_stack.last(), Some(0))
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
    fn shl(&mut self, a: u64, shift: u64) -> u64 {
        wit_shl(a, shift)
    }

    #[inline]
    fn shr(&mut self, a: u64, shift: u64) -> u64 {
        wit_shr(a, shift)
    }

    #[inline]
    fn mul(&mut self, a: u64, b: u64) -> u64 {
        a.wrapping_mul(b)
    }

    #[inline]
    fn xor(&mut self, a: u64, b: u64) -> u64 {
        a ^ b
    }

    #[inline]
    fn and(&mut self, a: u64, b: u64) -> u64 {
        a & b
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
        wit_nat_to_field(a)
    }

    #[inline]
    fn field_add(&mut self, a: F, b: F) -> F {
        a + b
    }

    #[inline]
    fn field_sub(&mut self, a: F, b: F) -> F {
        a - b
    }

    #[inline]
    fn field_inverse(&mut self, a: F) -> F {
        a.inverse()
    }

    #[inline]
    fn field_select(&mut self, cond: u64, a: F, b: F) -> F {
        if cond != 0 {
            a
        } else {
            b
        }
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
    fn add_bit_range_check_var(&mut self, a: u64, bits: u64) {
        if self.suppressed() {
            return;
        }
        self.record.add_bit_range_check(a as u16, bits as u8);
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
        let eff = self.guard_stack.last().copied().unwrap_or(1) * guard;
        self.guard_stack.push(eff);
    }

    #[inline]
    fn pop_guard(&mut self) {
        debug_assert!(!self.guard_stack.is_empty(), "pop_guard without a matching push_guard");
        self.guard_stack.pop();
    }
}
