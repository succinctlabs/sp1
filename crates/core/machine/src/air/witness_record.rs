//! The witgen IR: recording backend, device lowerings, and the CPU reference
//! interpreters the GPU kernels are ports of.
//!
//! Chip witness logic is written once against the [`WitnessBuilder`] trait; this
//! module provides everything downstream of the recording backend:
//!
//! 1. **Record** — [`RecordingWitnessBuilder`] walks a gadget's `witgen` *once*
//!    (the gadget shape is row-independent) and produces a [`WitProgram`]: a flat
//!    op-DAG over SSA [`WireId`]s. [`interpret`] replays it per row and is
//!    validated against the direct-computing `HostWitnessBuilder`.
//!
//! 2. **Lower** — three generations of flat device layouts, all sharing one tag
//!    vocabulary (census on [`WitOpC`]):
//!    - **SSA** [`WitProgram::to_c`] → [`WitOpC`]: the kernel appends one wire
//!      cell per value op (`nat[wc++]`), so the per-thread array is one cell per
//!      op. The original form and the reference the others are validated
//!      against; production reaches it only via the `AR_WITGEN_SLOTS=0`
//!      kill-switch (plus the narrow non-fused column/lookup kernels).
//!    - **Register-allocated ("pinned")** [`WitProgram::allocate_slots`] +
//!      [`WitProgram::to_c_slots`] → [`WitOpCSlot`]: liveness-based slot reuse
//!      bounds the array by max-live wires (Mul: 531 wires → 100 slots). Column
//!      wires stay pinned live for the final readout pass, so `max_slots` ≳ chip
//!      width. Production fallback when the streaming form cannot run (footprint
//!      over cap, or a field-typed multi-column epilogue).
//!    - **Streaming ("store-through")** [`WitProgram::allocate_slots_streaming`]
//!      `+` [`WitProgram::to_c_slots_streaming`]: a single-column wire is
//!      written to the trace at production ([`WitOpCSlot::col`]) and its slot
//!      freed, so the footprint is the true transient working set (Keccak:
//!      2641 → 69). The production default; the launcher tiers on the
//!      footprint (see `sp1-gpu/crates/tracegen/src/riscv/mod.rs`).
//!
//! 3. **Interpret (CPU = executable spec)** — every GPU kernel is a port of a
//!    CPU interpreter here, and every lowering is validated bit-identical to the
//!    SSA reference *before* any CUDA is written: [`interpret`] (op-DAG),
//!    [`interpret_c_columns`] (SSA flat), [`interpret_slots_columns`] /
//!    [`interpret_c_slots_columns`] (register-allocated),
//!    [`interpret_c_slots_streaming_columns`] (streaming), and
//!    [`interpret_c_lookups`] (byte/range histograms — the lookup-emitting dual
//!    of the column forms).
//!
//! The GPU ports live in `sp1-gpu/crates/sys/lib/tracegen/witgen_interp.cu`; the
//! launchers in `sp1-gpu/crates/tracegen/src/riscv/mod.rs`. See
//! `autoresearch/design/WITGEN-IR.md` for the spec and the chip-porting recipe,
//! and `autoresearch/design/TRACEGEN-DSL.md` for the original design.

use hashbrown::HashMap;
use slop_algebra::Field;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};

use crate::bytes::columns::NUM_BYTE_MULT_COLS;

use super::WitnessBuilder;

/// An SSA-style wire id: an index into the interpreter's value array.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WireId(pub u32);

/// One recorded operation of the witgen IR. Value-producing ops append a wire (in
/// program order); lookup ops are pure side effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitOp {
    ConstNat(u64),
    WrappingAdd(WireId, WireId),
    WrappingSub(WireId, WireId),
    Bits {
        src: WireId,
        offset: u32,
        width: u32,
    },
    Eq(WireId, WireId),
    Shl(WireId, WireId),
    Shr(WireId, WireId),
    Mul(WireId, WireId),
    /// Bitwise XOR (tag 24) — SHA precompile gadgets.
    Xor(WireId, WireId),
    /// Bitwise AND (tag 25) — SHA precompile gadgets.
    And(WireId, WireId),
    Select {
        cond: WireId,
        a: WireId,
        b: WireId,
    },
    NatToField(WireId),
    FieldAdd(WireId, WireId),
    FieldSub(WireId, WireId),
    FieldInverse(WireId),
    FieldSelect {
        cond: WireId,
        a: WireId,
        b: WireId,
    },
    U16RangeCheck(WireId),
    U8RangeCheck(WireId, WireId),
    BitRangeCheck {
        src: WireId,
        bits: u8,
    },
    /// Variable-width range check: `bits` is a wire (per-row width).
    BitRangeCheckVar {
        src: WireId,
        bits: WireId,
    },
    /// Guarded lookups: emitted only on rows where `guard != 0` (per-row branches).
    U16RangeCheckGuarded {
        guard: WireId,
        src: WireId,
    },
    U8RangeCheckGuarded {
        guard: WireId,
        a: WireId,
        b: WireId,
    },
    BitRangeCheckGuarded {
        guard: WireId,
        src: WireId,
        bits: u8,
    },
    /// General byte-table lookup `{opcode, a, b, c}` (per-row opcode). `a` (result)
    /// is kept for host fidelity but dropped from the device form (the byte table
    /// indexes multiplicities by `(opcode, b, c)` only).
    ByteLookup {
        opcode: WireId,
        a: WireId,
        b: WireId,
        c: WireId,
    },
    ByteLookupGuarded {
        guard: WireId,
        opcode: WireId,
        a: WireId,
        b: WireId,
        c: WireId,
    },
}

impl WitOp {
    /// Whether this op produces a value wire (the lookup/range-check ops are pure
    /// side effects and produce none — kept in sync with [`WitProgram::num_wires`]).
    pub fn produces_wire(&self) -> bool {
        !matches!(
            self,
            WitOp::U16RangeCheck(..)
                | WitOp::U8RangeCheck(..)
                | WitOp::BitRangeCheck { .. }
                | WitOp::BitRangeCheckVar { .. }
                | WitOp::U16RangeCheckGuarded { .. }
                | WitOp::U8RangeCheckGuarded { .. }
                | WitOp::BitRangeCheckGuarded { .. }
                | WitOp::ByteLookup { .. }
                | WitOp::ByteLookupGuarded { .. }
        )
    }

    /// Invoke `f` on each operand (read) wire id of this op.
    pub fn for_each_operand(&self, mut f: impl FnMut(u32)) {
        use WitOp::*;
        match *self {
            ConstNat(_) => {}
            WrappingAdd(a, b)
            | WrappingSub(a, b)
            | Eq(a, b)
            | Shl(a, b)
            | Shr(a, b)
            | Mul(a, b)
            | Xor(a, b)
            | And(a, b)
            | FieldAdd(a, b)
            | FieldSub(a, b)
            | U8RangeCheck(a, b) => {
                f(a.0);
                f(b.0);
            }
            NatToField(a) | FieldInverse(a) | U16RangeCheck(a) => f(a.0),
            Bits { src, .. } | BitRangeCheck { src, .. } => f(src.0),
            BitRangeCheckVar { src, bits } => {
                f(src.0);
                f(bits.0);
            }
            Select { cond, a, b } | FieldSelect { cond, a, b } => {
                f(cond.0);
                f(a.0);
                f(b.0);
            }
            U16RangeCheckGuarded { guard, src } | BitRangeCheckGuarded { guard, src, .. } => {
                f(guard.0);
                f(src.0);
            }
            U8RangeCheckGuarded { guard, a, b } => {
                f(guard.0);
                f(a.0);
                f(b.0);
            }
            ByteLookup { opcode, a, b, c } => {
                f(opcode.0);
                f(a.0);
                f(b.0);
                f(c.0);
            }
            ByteLookupGuarded { guard, opcode, a, b, c } => {
                f(guard.0);
                f(opcode.0);
                f(a.0);
                f(b.0);
                f(c.0);
            }
        }
    }
}

/// A recorded gadget: the op list plus the number of input wires.
#[derive(Clone, Debug, Default)]
pub struct WitProgram {
    pub ops: Vec<WitOp>,
    pub num_inputs: u32,
}

/// [`WitnessBuilder`] that records ops instead of evaluating them.
pub struct RecordingWitnessBuilder {
    program: WitProgram,
    next_wire: u32,
    /// Stack of effective guard wires. Each entry is the AND (product) of all
    /// enclosing scopes' guards; lookups recorded while non-empty become guarded
    /// variants conditioned on the top wire. Nesting records a `Mul` of the new
    /// guard with the enclosing one, so an inner gadget composes with its caller.
    guard_stack: Vec<WireId>,
}

impl RecordingWitnessBuilder {
    /// Start recording a gadget with `num_inputs` input wires (ids `0..num_inputs`).
    pub fn new(num_inputs: u32) -> Self {
        Self {
            program: WitProgram { ops: Vec::new(), num_inputs },
            next_wire: num_inputs,
            guard_stack: Vec::new(),
        }
    }

    /// The `i`-th input wire.
    pub fn input(i: u32) -> WireId {
        WireId(i)
    }

    /// Record a value-producing op and return its fresh result wire.
    fn value(&mut self, op: WitOp) -> WireId {
        let id = WireId(self.next_wire);
        self.next_wire += 1;
        self.program.ops.push(op);
        id
    }

    /// Finish recording.
    pub fn finish(self) -> WitProgram {
        self.program
    }
}

impl WitnessBuilder for RecordingWitnessBuilder {
    type Nat = WireId;
    type Field = WireId;

    fn const_nat(&mut self, value: u64) -> WireId {
        self.value(WitOp::ConstNat(value))
    }
    fn wrapping_add(&mut self, a: WireId, b: WireId) -> WireId {
        self.value(WitOp::WrappingAdd(a, b))
    }
    fn wrapping_sub(&mut self, a: WireId, b: WireId) -> WireId {
        self.value(WitOp::WrappingSub(a, b))
    }
    fn bits(&mut self, a: WireId, offset: u32, width: u32) -> WireId {
        self.value(WitOp::Bits { src: a, offset, width })
    }
    fn eq(&mut self, a: WireId, b: WireId) -> WireId {
        self.value(WitOp::Eq(a, b))
    }
    fn shl(&mut self, a: WireId, shift: WireId) -> WireId {
        self.value(WitOp::Shl(a, shift))
    }
    fn mul(&mut self, a: WireId, b: WireId) -> WireId {
        self.value(WitOp::Mul(a, b))
    }
    fn xor(&mut self, a: WireId, b: WireId) -> WireId {
        self.value(WitOp::Xor(a, b))
    }
    fn and(&mut self, a: WireId, b: WireId) -> WireId {
        self.value(WitOp::And(a, b))
    }
    fn shr(&mut self, a: WireId, shift: WireId) -> WireId {
        self.value(WitOp::Shr(a, shift))
    }
    fn select(&mut self, cond: WireId, a: WireId, b: WireId) -> WireId {
        self.value(WitOp::Select { cond, a, b })
    }
    fn nat_to_field(&mut self, a: WireId) -> WireId {
        self.value(WitOp::NatToField(a))
    }
    fn field_add(&mut self, a: WireId, b: WireId) -> WireId {
        self.value(WitOp::FieldAdd(a, b))
    }
    fn field_sub(&mut self, a: WireId, b: WireId) -> WireId {
        self.value(WitOp::FieldSub(a, b))
    }
    fn field_inverse(&mut self, a: WireId) -> WireId {
        self.value(WitOp::FieldInverse(a))
    }
    fn field_select(&mut self, cond: WireId, a: WireId, b: WireId) -> WireId {
        self.value(WitOp::FieldSelect { cond, a, b })
    }
    fn add_u16_range_check(&mut self, a: WireId) {
        let op = match self.guard_stack.last().copied() {
            Some(guard) => WitOp::U16RangeCheckGuarded { guard, src: a },
            None => WitOp::U16RangeCheck(a),
        };
        self.program.ops.push(op);
    }
    fn add_u8_range_check(&mut self, a: WireId, b: WireId) {
        let op = match self.guard_stack.last().copied() {
            Some(guard) => WitOp::U8RangeCheckGuarded { guard, a, b },
            None => WitOp::U8RangeCheck(a, b),
        };
        self.program.ops.push(op);
    }
    fn add_bit_range_check(&mut self, a: WireId, bits: u8) {
        let op = match self.guard_stack.last().copied() {
            Some(guard) => WitOp::BitRangeCheckGuarded { guard, src: a, bits },
            None => WitOp::BitRangeCheck { src: a, bits },
        };
        self.program.ops.push(op);
    }
    fn add_bit_range_check_var(&mut self, a: WireId, bits: WireId) {
        // Used only outside guarded scopes (the shift chips' limb range checks).
        debug_assert!(
            self.guard_stack.is_empty(),
            "guarded variable-width range check unsupported"
        );
        self.program.ops.push(WitOp::BitRangeCheckVar { src: a, bits });
    }
    fn add_byte_lookup(&mut self, opcode: WireId, a: WireId, b: WireId, c: WireId) {
        let op = match self.guard_stack.last().copied() {
            Some(guard) => WitOp::ByteLookupGuarded { guard, opcode, a, b, c },
            None => WitOp::ByteLookup { opcode, a, b, c },
        };
        self.program.ops.push(op);
    }
    fn push_guard(&mut self, guard: WireId) {
        // Effective guard = AND (product) of the new guard with the enclosing one.
        let eff = match self.guard_stack.last().copied() {
            Some(prev) => self.value(WitOp::Mul(prev, guard)),
            None => guard,
        };
        self.guard_stack.push(eff);
    }
    fn pop_guard(&mut self) {
        self.guard_stack.pop();
    }
}

/// A runtime wire value: integer- or field-typed (the op that produced it decides).
#[derive(Clone, Copy)]
enum Val<F> {
    Nat(u64),
    Field(F),
}

impl<F: Copy> Val<F> {
    #[inline]
    fn nat(self) -> u64 {
        match self {
            Val::Nat(n) => n,
            Val::Field(_) => panic!("witgen IR: expected a Nat wire, found Field"),
        }
    }
    #[inline]
    fn field(self) -> F {
        match self {
            Val::Field(f) => f,
            Val::Nat(_) => panic!("witgen IR: expected a Field wire, found Nat"),
        }
    }
}

/// Run a recorded [`WitProgram`] for one row: `inputs` are the row's input nats,
/// `record` receives the emitted lookups. Returns the wire-value array; a column
/// wired to `WireId(i)` reads its field value from index `i`. This is the CPU
/// model of the per-row GPU interpreter kernel.
pub fn interpret<F: Field, R: ByteRecord>(
    program: &WitProgram,
    inputs: &[u64],
    record: &mut R,
) -> Vec<F> {
    assert_eq!(inputs.len() as u32, program.num_inputs);
    let mut wires: Vec<Val<F>> = inputs.iter().map(|&v| Val::Nat(v)).collect();
    for op in &program.ops {
        match *op {
            WitOp::ConstNat(v) => wires.push(Val::Nat(v)),
            WitOp::WrappingAdd(a, b) => wires
                .push(Val::Nat(wires[a.0 as usize].nat().wrapping_add(wires[b.0 as usize].nat()))),
            WitOp::WrappingSub(a, b) => wires
                .push(Val::Nat(wires[a.0 as usize].nat().wrapping_sub(wires[b.0 as usize].nat()))),
            WitOp::Bits { src, offset, width } => {
                let x = wires[src.0 as usize].nat();
                let mask = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
                wires.push(Val::Nat((x >> offset) & mask));
            }
            WitOp::Eq(a, b) => wires
                .push(Val::Nat(u64::from(wires[a.0 as usize].nat() == wires[b.0 as usize].nat()))),
            WitOp::Shl(a, s) => {
                wires.push(Val::Nat(wires[a.0 as usize].nat() << wires[s.0 as usize].nat()))
            }
            WitOp::Shr(a, s) => {
                wires.push(Val::Nat(wires[a.0 as usize].nat() >> wires[s.0 as usize].nat()))
            }
            WitOp::Mul(a, b) => wires
                .push(Val::Nat(wires[a.0 as usize].nat().wrapping_mul(wires[b.0 as usize].nat()))),
            WitOp::Xor(a, b) => {
                wires.push(Val::Nat(wires[a.0 as usize].nat() ^ wires[b.0 as usize].nat()))
            }
            WitOp::And(a, b) => {
                wires.push(Val::Nat(wires[a.0 as usize].nat() & wires[b.0 as usize].nat()))
            }
            WitOp::Select { cond, a, b } => {
                let c = wires[cond.0 as usize].nat();
                wires.push(if c != 0 { wires[a.0 as usize] } else { wires[b.0 as usize] });
            }
            WitOp::NatToField(a) => {
                wires.push(Val::Field(F::from_canonical_u64(wires[a.0 as usize].nat())))
            }
            WitOp::FieldAdd(a, b) => {
                wires.push(Val::Field(wires[a.0 as usize].field() + wires[b.0 as usize].field()))
            }
            WitOp::FieldSub(a, b) => {
                wires.push(Val::Field(wires[a.0 as usize].field() - wires[b.0 as usize].field()))
            }
            WitOp::FieldInverse(a) => wires.push(Val::Field(wires[a.0 as usize].field().inverse())),
            WitOp::FieldSelect { cond, a, b } => {
                let c = wires[cond.0 as usize].nat();
                wires.push(if c != 0 { wires[a.0 as usize] } else { wires[b.0 as usize] });
            }
            WitOp::U16RangeCheck(a) => record.add_u16_range_check(wires[a.0 as usize].nat() as u16),
            WitOp::U8RangeCheck(a, b) => record.add_u8_range_check(
                wires[a.0 as usize].nat() as u8,
                wires[b.0 as usize].nat() as u8,
            ),
            WitOp::BitRangeCheck { src, bits } => {
                record.add_bit_range_check(wires[src.0 as usize].nat() as u16, bits)
            }
            WitOp::BitRangeCheckVar { src, bits } => record.add_bit_range_check(
                wires[src.0 as usize].nat() as u16,
                wires[bits.0 as usize].nat() as u8,
            ),
            WitOp::U16RangeCheckGuarded { guard, src } => {
                if wires[guard.0 as usize].nat() != 0 {
                    record.add_u16_range_check(wires[src.0 as usize].nat() as u16)
                }
            }
            WitOp::U8RangeCheckGuarded { guard, a, b } => {
                if wires[guard.0 as usize].nat() != 0 {
                    record.add_u8_range_check(
                        wires[a.0 as usize].nat() as u8,
                        wires[b.0 as usize].nat() as u8,
                    )
                }
            }
            WitOp::BitRangeCheckGuarded { guard, src, bits } => {
                if wires[guard.0 as usize].nat() != 0 {
                    record.add_bit_range_check(wires[src.0 as usize].nat() as u16, bits)
                }
            }
            WitOp::ByteLookup { opcode, a, b, c } => {
                record.add_byte_lookup_event(ByteLookupEvent {
                    opcode: super::byte_opcode_from_u64(wires[opcode.0 as usize].nat()),
                    a: wires[a.0 as usize].nat() as u16,
                    b: wires[b.0 as usize].nat() as u8,
                    c: wires[c.0 as usize].nat() as u8,
                })
            }
            WitOp::ByteLookupGuarded { guard, opcode, a, b, c } => {
                if wires[guard.0 as usize].nat() != 0 {
                    record.add_byte_lookup_event(ByteLookupEvent {
                        opcode: super::byte_opcode_from_u64(wires[opcode.0 as usize].nat()),
                        a: wires[a.0 as usize].nat() as u16,
                        b: wires[b.0 as usize].nat() as u8,
                        c: wires[c.0 as usize].nat() as u8,
                    })
                }
            }
        }
    }
    // Project to a field per wire. Only Field wires (and small Nat wires explicitly
    // converted via `nat_to_field`) are ever read as columns; large intermediate Nat
    // wires (e.g. a u48 sum) are never columns, so reduce mod order with
    // `from_wrapped_u64` rather than the canonical (asserting `n < P`) constructor.
    wires
        .into_iter()
        .map(|w| match w {
            Val::Field(f) => f,
            Val::Nat(n) => F::from_wrapped_u64(n),
        })
        .collect()
}

/// Flat, `#[repr(C)]` form of one [`WitOp`], suitable for upload to the device and
/// interpretation by the GPU kernels (which read this exact layout). The fields are
/// overloaded per `tag`; `a`/`b` are always wire ids when used, while `imm0`/`imm1`
/// carry a WIRE id for some tags and a LITERAL for others — lower by semantic
/// field, never positionally (the iter-065 lesson).
///
/// Value ops (each produces one wire, in program order):
///
/// | tag | op           | a    | b     | imm1        | imm0         |
/// |-----|--------------|------|-------|-------------|--------------|
/// | 0   | ConstNat     | -    | -     | -           | value (lit)  |
/// | 1   | WrappingAdd  | lhs  | rhs   | -           | -            |
/// | 2   | Bits         | src  | -     | width (lit) | offset (lit) |
/// | 3   | NatToField   | src  | -     | -           | -            |
/// | 4   | FieldAdd     | lhs  | rhs   | -           | -            |
/// | 5   | FieldInverse | src  | -     | -           | -            |
/// | 8   | WrappingSub  | lhs  | rhs   | -           | -            |
/// | 11  | Eq           | lhs  | rhs   | -           | -            |
/// | 12  | Select       | cond | then  | else (WIRE) | -            |
/// | 18  | FieldSelect  | cond | then  | else (WIRE) | -            |
/// | 19  | FieldSub     | lhs  | rhs   | -           | -            |
/// | 20  | Shl          | src  | shift | -           | -            |
/// | 21  | Shr          | src  | shift | -           | -            |
/// | 23  | Mul          | lhs  | rhs   | -           | -            |
/// | 24  | Xor          | lhs  | rhs   | -           | -            |
/// | 25  | And          | lhs  | rhs   | -           | -            |
///
/// Lookup ops (emit no wire; skipped by the columns-only interpreters and
/// accumulated into the Range/Byte histograms by the lookup/fused kernels — see
/// [`interpret_c_lookups`] for the index conventions). Byte-table lookups drop the
/// result `a` on device; it is reconstructed deterministically from
/// `(opcode, b, c)` on readback (see [`byte_lookups_from_histograms`]):
///
/// | tag | op                   | a   | b     | imm1          | imm0         |
/// |-----|----------------------|-----|-------|---------------|--------------|
/// | 6   | U16RangeCheck        | src | -     | -             | -            |
/// | 7   | BitRangeCheck        | src | -     | -             | bits (lit)   |
/// | 9   | U8RangeCheck         | a   | b     | -             | -            |
/// | 13  | U16RangeCheckGuarded | src | guard | -             | -            |
/// | 14  | BitRangeCheckGuarded | src | guard | -             | bits (lit)   |
/// | 15  | U8RangeCheckGuarded  | a   | b     | guard (WIRE)  | -            |
/// | 16  | ByteLookup           | b   | c     | opcode (WIRE) | -            |
/// | 17  | ByteLookupGuarded    | b   | c     | opcode (WIRE) | guard (WIRE) |
/// | 22  | BitRangeCheckVar     | src | bits  | -             | -            |
///
/// Tag 10 is unassigned (never allocated; existing tags must stay stable — the
/// compiled kernels switch on these exact values). Adding an op means: one arm in
/// [`to_c`](WitProgram::to_c) and [`to_c_slots`](WitProgram::to_c_slots), one case
/// in each CPU interpreter in this file, and one `case` per kernel switch in
/// `witgen_interp.cu` (7 sites).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct WitOpC {
    pub tag: u32,
    pub a: u32,
    pub b: u32,
    pub imm1: u32,
    pub imm0: u64,
}

/// Slot-resolved counterpart of [`WitOpC`]: the flat op form the *register-
/// allocated* kernel consumes. Every wire reference (`a`/`b`, and `imm1`/`imm0`
/// when they carry a wire) is pre-remapped from an SSA wire id to a reusable slot
/// via [`WitProgram::allocate_slots`], and `out` is the destination slot of the
/// produced wire (`u32::MAX` for lookup ops, which produce none). This lets the
/// kernel do `nat[op.out] = f(nat[op.a], nat[op.b])` into a bounded
/// `max_slots`-entry per-thread array (Mul: 531 wires -> ~100 slots) instead of one
/// cell per value op. Literal fields (`imm0` = const/offset/bits, `imm1` = width)
/// are carried through unchanged — same tag semantics as [`WitProgram::to_c`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct WitOpCSlot {
    pub tag: u32,
    pub out: u32,
    pub a: u32,
    pub b: u32,
    pub imm1: u32,
    /// Store-through column: if != `u32::MAX`, the kernel writes this op's value
    /// straight to trace column `col` at production (streaming lowering), so the
    /// wire need not stay live for a readout pass. `u32::MAX` in the pinned
    /// lowering ([`WitProgram::to_c_slots`]), where columns are read out at the end.
    /// (Fills what was struct padding — layout stays 32 bytes.)
    pub col: u32,
    pub imm0: u64,
}

impl WitProgram {
    /// Total live wires the SSA interpreter needs per row: the inputs plus every
    /// value-producing op (lookup ops emit no wire). The GPU kernel's per-thread
    /// wire arrays must be at least this large on the SSA path; the slot lowerings
    /// bound it by `max_slots` instead.
    pub fn num_wires(&self) -> usize {
        self.num_inputs as usize
            + self
                .ops
                .iter()
                .filter(|op| {
                    !matches!(
                        op,
                        WitOp::U16RangeCheck(..)
                            | WitOp::BitRangeCheck { .. }
                            | WitOp::BitRangeCheckVar { .. }
                            | WitOp::U8RangeCheck(..)
                            | WitOp::U16RangeCheckGuarded { .. }
                            | WitOp::U8RangeCheckGuarded { .. }
                            | WitOp::BitRangeCheckGuarded { .. }
                            | WitOp::ByteLookup { .. }
                            | WitOp::ByteLookupGuarded { .. }
                    )
                })
                .count()
    }

    /// Register-allocate the SSA op-DAG: assign each wire a REUSABLE slot via
    /// liveness (linear scan), so the interpreter's per-thread array only needs
    /// `max_slots` entries (= max simultaneously-live wires) rather than one per
    /// value-op (`num_wires`). Column wires stay live to the end (the kernel reads
    /// them after the whole DAG runs), so their slots are never reused.
    ///
    /// Returns `(wire -> slot, max_slots)`. This is what lets wide gadgets (Mul,
    /// DivRem, precompiles) fit a bounded kernel array (Mul: 531 wires -> ~100
    /// slots), mirroring the register allocation zerocheck already does.
    ///
    /// Generation 2 ("pinned") of the three lowerings (module doc): production's
    /// fallback tier when the streaming form cannot run; also used directly by the
    /// non-fused slot kernels. Pair with [`to_c_slots`](Self::to_c_slots).
    pub fn allocate_slots(&self, col_wires: &[u32]) -> (Vec<u32>, u32) {
        let ni = self.num_inputs as usize;
        let total = self.num_wires();
        let n = self.ops.len();
        let end = n + 1;
        // Def time per wire (inputs at time 0; value op k defines its wire at k+1).
        let mut def = vec![0usize; total];
        let mut wc = ni;
        for (k, op) in self.ops.iter().enumerate() {
            if op.produces_wire() {
                def[wc] = k + 1;
                wc += 1;
            }
        }
        debug_assert_eq!(wc, total, "wire count mismatch");
        // Last-use time per wire (>= its def; col wires live to `end`).
        let mut lastuse = def.clone();
        for (k, op) in self.ops.iter().enumerate() {
            op.for_each_operand(|w| {
                let w = w as usize;
                if w < total && k + 1 > lastuse[w] {
                    lastuse[w] = k + 1;
                }
            });
        }
        for &c in col_wires {
            if (c as usize) < total {
                lastuse[c as usize] = end;
            }
        }
        // Linear-scan allocation in def order; a slot frees once its wire's last use
        // is strictly before the new wire's def (disjoint inclusive live ranges).
        let mut order: Vec<usize> = (0..total).collect();
        order.sort_by_key(|&w| def[w]);
        let mut slot = vec![u32::MAX; total];
        let mut free: Vec<u32> = Vec::new();
        let mut active: Vec<usize> = Vec::new();
        let mut next: u32 = 0;
        for &w in &order {
            let t = def[w];
            let mut i = 0;
            while i < active.len() {
                let aw = active[i];
                if lastuse[aw] < t {
                    free.push(slot[aw]);
                    active.swap_remove(i);
                } else {
                    i += 1;
                }
            }
            let s = free.pop().unwrap_or_else(|| {
                let s = next;
                next += 1;
                s
            });
            slot[w] = s;
            active.push(w);
        }
        (slot, next)
    }

    /// SSA lowering: flatten the op-DAG to the [`WitOpC`] device layout (see the
    /// tag census there). Wire references stay raw SSA ids — the kernel appends
    /// one cell per value op. This is generation 1 of the three lowerings (module
    /// doc): the validation reference for the slot forms, the layout of the
    /// non-fused narrow kernels, and the fused path's `AR_WITGEN_SLOTS=0`
    /// kill-switch form.
    pub fn to_c(&self) -> Vec<WitOpC> {
        self.ops
            .iter()
            .map(|op| match *op {
                WitOp::ConstNat(v) => WitOpC { tag: 0, a: 0, b: 0, imm1: 0, imm0: v },
                WitOp::WrappingAdd(a, b) => WitOpC { tag: 1, a: a.0, b: b.0, imm1: 0, imm0: 0 },
                WitOp::WrappingSub(a, b) => WitOpC { tag: 8, a: a.0, b: b.0, imm1: 0, imm0: 0 },
                WitOp::U8RangeCheck(a, b) => WitOpC { tag: 9, a: a.0, b: b.0, imm1: 0, imm0: 0 },
                WitOp::Eq(a, b) => WitOpC { tag: 11, a: a.0, b: b.0, imm1: 0, imm0: 0 },
                WitOp::Shl(a, s) => WitOpC { tag: 20, a: a.0, b: s.0, imm1: 0, imm0: 0 },
                WitOp::Shr(a, s) => WitOpC { tag: 21, a: a.0, b: s.0, imm1: 0, imm0: 0 },
                WitOp::Mul(a, b) => WitOpC { tag: 23, a: a.0, b: b.0, imm1: 0, imm0: 0 },
                WitOp::Xor(a, b) => WitOpC { tag: 24, a: a.0, b: b.0, imm1: 0, imm0: 0 },
                WitOp::And(a, b) => WitOpC { tag: 25, a: a.0, b: b.0, imm1: 0, imm0: 0 },
                WitOp::BitRangeCheckVar { src, bits } => {
                    WitOpC { tag: 22, a: src.0, b: bits.0, imm1: 0, imm0: 0 }
                }
                WitOp::Select { cond, a, b } => {
                    WitOpC { tag: 12, a: cond.0, b: a.0, imm1: b.0, imm0: 0 }
                }
                WitOp::Bits { src, offset, width } => {
                    WitOpC { tag: 2, a: src.0, b: 0, imm1: width, imm0: offset as u64 }
                }
                WitOp::NatToField(a) => WitOpC { tag: 3, a: a.0, b: 0, imm1: 0, imm0: 0 },
                WitOp::FieldAdd(a, b) => WitOpC { tag: 4, a: a.0, b: b.0, imm1: 0, imm0: 0 },
                WitOp::FieldSub(a, b) => WitOpC { tag: 19, a: a.0, b: b.0, imm1: 0, imm0: 0 },
                WitOp::FieldInverse(a) => WitOpC { tag: 5, a: a.0, b: 0, imm1: 0, imm0: 0 },
                WitOp::FieldSelect { cond, a, b } => {
                    WitOpC { tag: 18, a: cond.0, b: a.0, imm1: b.0, imm0: 0 }
                }
                WitOp::U16RangeCheck(a) => WitOpC { tag: 6, a: a.0, b: 0, imm1: 0, imm0: 0 },
                WitOp::BitRangeCheck { src, bits } => {
                    WitOpC { tag: 7, a: src.0, b: 0, imm1: 0, imm0: bits as u64 }
                }
                // Guarded lookups (per-row branches): the guard wire rides in an
                // otherwise-unused field — `b` for the 1-source checks, `imm1` for u8.
                WitOp::U16RangeCheckGuarded { guard, src } => {
                    WitOpC { tag: 13, a: src.0, b: guard.0, imm1: 0, imm0: 0 }
                }
                WitOp::BitRangeCheckGuarded { guard, src, bits } => {
                    WitOpC { tag: 14, a: src.0, b: guard.0, imm1: 0, imm0: bits as u64 }
                }
                WitOp::U8RangeCheckGuarded { guard, a, b } => {
                    WitOpC { tag: 15, a: a.0, b: b.0, imm1: guard.0, imm0: 0 }
                }
                // Byte-table lookup: device needs only (opcode, b, c) for the
                // multiplicity index — the result `a` is dropped from the device form.
                WitOp::ByteLookup { opcode, a: _, b, c } => {
                    WitOpC { tag: 16, a: b.0, b: c.0, imm1: opcode.0, imm0: 0 }
                }
                WitOp::ByteLookupGuarded { guard, opcode, a: _, b, c } => {
                    WitOpC { tag: 17, a: b.0, b: c.0, imm1: opcode.0, imm0: guard.0 as u64 }
                }
            })
            .collect()
    }

    /// Lower to the slot-resolved [`WitOpCSlot`] form: identical tag semantics to
    /// [`to_c`](Self::to_c), but every wire reference is remapped through `slot` (from
    /// [`allocate_slots`](Self::allocate_slots)) and each value op carries its
    /// destination `out` slot. This is the exact layout the register-allocated kernel
    /// interprets; the lowering is validated by [`interpret_c_slots_columns`] being
    /// bit-identical to the SSA [`interpret_c_columns`].
    pub fn to_c_slots(&self, slot: &[u32]) -> Vec<WitOpCSlot> {
        let s = |w: WireId| slot[w.0 as usize];
        let mut wc = self.num_inputs as usize;
        self.ops
            .iter()
            .map(|op| {
                // Destination slot for value ops (lookups produce no wire).
                let out = if op.produces_wire() {
                    let o = slot[wc];
                    wc += 1;
                    o
                } else {
                    u32::MAX
                };
                // Remap by semantic field (not position) so wire vs. literal is never
                // confused — mirrors `to_c`, wrapping each wire field in `s(..)`.
                let (tag, a, b, imm1, imm0) = match *op {
                    WitOp::ConstNat(v) => (0, 0, 0, 0, v),
                    WitOp::WrappingAdd(a, b) => (1, s(a), s(b), 0, 0),
                    WitOp::WrappingSub(a, b) => (8, s(a), s(b), 0, 0),
                    WitOp::U8RangeCheck(a, b) => (9, s(a), s(b), 0, 0),
                    WitOp::Eq(a, b) => (11, s(a), s(b), 0, 0),
                    WitOp::Shl(a, b) => (20, s(a), s(b), 0, 0),
                    WitOp::Shr(a, b) => (21, s(a), s(b), 0, 0),
                    WitOp::Mul(a, b) => (23, s(a), s(b), 0, 0),
                    WitOp::Xor(a, b) => (24, s(a), s(b), 0, 0),
                    WitOp::And(a, b) => (25, s(a), s(b), 0, 0),
                    WitOp::BitRangeCheckVar { src, bits } => (22, s(src), s(bits), 0, 0),
                    WitOp::Select { cond, a, b } => (12, s(cond), s(a), s(b), 0),
                    WitOp::Bits { src, offset, width } => (2, s(src), 0, width, offset as u64),
                    WitOp::NatToField(a) => (3, s(a), 0, 0, 0),
                    WitOp::FieldAdd(a, b) => (4, s(a), s(b), 0, 0),
                    WitOp::FieldSub(a, b) => (19, s(a), s(b), 0, 0),
                    WitOp::FieldInverse(a) => (5, s(a), 0, 0, 0),
                    WitOp::FieldSelect { cond, a, b } => (18, s(cond), s(a), s(b), 0),
                    WitOp::U16RangeCheck(a) => (6, s(a), 0, 0, 0),
                    WitOp::BitRangeCheck { src, bits } => (7, s(src), 0, 0, bits as u64),
                    WitOp::U16RangeCheckGuarded { guard, src } => (13, s(src), s(guard), 0, 0),
                    WitOp::BitRangeCheckGuarded { guard, src, bits } => {
                        (14, s(src), s(guard), 0, bits as u64)
                    }
                    WitOp::U8RangeCheckGuarded { guard, a, b } => (15, s(a), s(b), s(guard), 0),
                    // Byte-table lookups keep only (opcode, b, c) on device — the
                    // result `a` is dropped (same as `to_c`); opcode/guard are wires.
                    WitOp::ByteLookup { opcode, a: _, b, c } => (16, s(b), s(c), s(opcode), 0),
                    WitOp::ByteLookupGuarded { guard, opcode, a: _, b, c } => {
                        (17, s(b), s(c), s(opcode), u64::from(s(guard)))
                    }
                };
                WitOpCSlot { tag, out, a, b, imm1, col: u32::MAX, imm0 }
            })
            .collect()
    }

    /// STREAMING (store-through) slot allocation: like [`allocate_slots`] but column
    /// wires are NOT pinned to the end — the kernel writes each single-column wire
    /// straight to the trace at production ([`WitOpCSlot::col`]), so its slot frees
    /// at its last *operand* use. Only wires feeding **multiple** columns (rare) are
    /// pinned and written by a small epilogue.
    ///
    /// Returns `(slot, max_slots, epilogue)` where `epilogue` is `(wire, col)` pairs
    /// the kernel must write after the op loop. This collapses `max_slots` from
    /// ~chip-width (columns pinned; iter-073a census: 31–100) to the true transient
    /// working set, enabling shared-memory wire storage and unblocking wide chips
    /// (DivRem 272→transients; Keccak's 2640-column floor).
    ///
    /// Generation 3 ("streaming") of the three lowerings (module doc): the
    /// production default. Pair with [`to_c_slots_streaming`](Self::to_c_slots_streaming).
    pub fn allocate_slots_streaming(&self, col_wires: &[u32]) -> (Vec<u32>, u32, Vec<(u32, u32)>) {
        // Count columns per wire; multi-column wires get pinned + epilogue entries.
        let mut ncols_of = vec![0u32; self.num_wires()];
        for &w in col_wires {
            ncols_of[w as usize] += 1;
        }
        let pinned: Vec<u32> =
            (0..self.num_wires() as u32).filter(|&w| ncols_of[w as usize] >= 2).collect();
        let (slot, max_slots) = self.allocate_slots(&pinned);
        let epilogue: Vec<(u32, u32)> = col_wires
            .iter()
            .enumerate()
            .filter(|&(_, &w)| ncols_of[w as usize] >= 2)
            .map(|(c, &w)| (w, c as u32))
            .collect();
        (slot, max_slots, epilogue)
    }

    /// Lower to the streaming (store-through) [`WitOpCSlot`] form: identical to
    /// [`to_c_slots`](Self::to_c_slots) except each op that produces a
    /// **single-column** wire carries that column in `col` (the kernel stores it at
    /// production). Multi-column wires keep `col = MAX` and are written by the
    /// epilogue from [`allocate_slots_streaming`]; input wires that are columns are
    /// returned separately as `(input_index, col)` for the kernel's load loop.
    pub fn to_c_slots_streaming(
        &self,
        slot: &[u32],
        col_wires: &[u32],
    ) -> (Vec<WitOpCSlot>, Vec<(u32, u32)>) {
        // wire -> its column, only for wires feeding exactly ONE column.
        let mut col_of = vec![u32::MAX; self.num_wires()];
        let mut ncols_of = vec![0u32; self.num_wires()];
        for (c, &w) in col_wires.iter().enumerate() {
            ncols_of[w as usize] += 1;
            col_of[w as usize] = c as u32;
        }
        for w in 0..col_of.len() {
            if ncols_of[w] >= 2 {
                col_of[w] = u32::MAX; // multi-column: epilogue handles it
            }
        }
        let ni = self.num_inputs as usize;
        let input_cols: Vec<(u32, u32)> = col_wires
            .iter()
            .enumerate()
            .filter(|&(_, &w)| (w as usize) < ni && ncols_of[w as usize] == 1)
            .map(|(c, &w)| (w, c as u32))
            .collect();
        let mut ops = self.to_c_slots(slot);
        let mut wc = ni;
        for (k, op) in self.ops.iter().enumerate() {
            if op.produces_wire() {
                ops[k].col = col_of[wc];
                wc += 1;
            }
        }
        (ops, input_cols)
    }
}

/// Columns-only interpreter over the flat [`WitOpC`] layout — the exact reference
/// the GPU kernel ports (one thread per row). Skips lookup ops; returns the field
/// value of every wire, so column `c` reads index `col_wires[c]`.
pub fn interpret_c_columns<F: Field>(
    ops: &[WitOpC],
    num_inputs: u32,
    inputs: &[u64],
    col_wires: &[u32],
) -> Vec<F> {
    assert_eq!(inputs.len() as u32, num_inputs);
    let mut wires: Vec<Val<F>> = inputs.iter().map(|&v| Val::Nat(v)).collect();
    for op in ops {
        match op.tag {
            0 => wires.push(Val::Nat(op.imm0)),
            1 => wires.push(Val::Nat(
                wires[op.a as usize].nat().wrapping_add(wires[op.b as usize].nat()),
            )),
            8 => wires.push(Val::Nat(
                wires[op.a as usize].nat().wrapping_sub(wires[op.b as usize].nat()),
            )),
            2 => {
                let x = wires[op.a as usize].nat();
                let mask = if op.imm1 >= 64 { u64::MAX } else { (1u64 << op.imm1) - 1 };
                wires.push(Val::Nat((x >> op.imm0) & mask));
            }
            11 => wires.push(Val::Nat(u64::from(
                wires[op.a as usize].nat() == wires[op.b as usize].nat(),
            ))),
            20 => wires.push(Val::Nat(wires[op.a as usize].nat() << wires[op.b as usize].nat())),
            21 => wires.push(Val::Nat(wires[op.a as usize].nat() >> wires[op.b as usize].nat())),
            23 => wires.push(Val::Nat(
                wires[op.a as usize].nat().wrapping_mul(wires[op.b as usize].nat()),
            )),
            24 => wires.push(Val::Nat(wires[op.a as usize].nat() ^ wires[op.b as usize].nat())),
            25 => wires.push(Val::Nat(wires[op.a as usize].nat() & wires[op.b as usize].nat())),
            12 => {
                let c = wires[op.a as usize].nat();
                wires.push(if c != 0 { wires[op.b as usize] } else { wires[op.imm1 as usize] });
            }
            3 => wires.push(Val::Field(F::from_canonical_u64(wires[op.a as usize].nat()))),
            4 => {
                wires.push(Val::Field(wires[op.a as usize].field() + wires[op.b as usize].field()))
            }
            19 => {
                wires.push(Val::Field(wires[op.a as usize].field() - wires[op.b as usize].field()))
            }
            5 => wires.push(Val::Field(wires[op.a as usize].field().inverse())),
            18 => {
                let cond = wires[op.a as usize].nat();
                wires.push(if cond != 0 { wires[op.b as usize] } else { wires[op.imm1 as usize] });
            }
            // lookups (incl. guarded + byte-table + var-width): no wire, skipped for columns
            6 | 7 | 9 | 13 | 14 | 15 | 16 | 17 | 22 => {}
            t => panic!("unknown WitOpC tag {t}"),
        }
    }
    col_wires
        .iter()
        .map(|&w| match wires[w as usize] {
            Val::Field(f) => f,
            Val::Nat(n) => F::from_canonical_u64(n),
        })
        .collect()
}

/// Slot-resolved counterpart of [`interpret_c_columns`]: interprets the flat
/// [`WitOpCSlot`] form exactly as the register-allocated kernel does —
/// `vals[op.out] = f(vals[op.a], vals[op.b])` into a bounded `max_slots`-entry array,
/// reading operands from their slots. MUST return columns identical to the SSA
/// [`interpret_c_columns`]; that equivalence (tested over real gadget events) is what
/// pins the [`to_c_slots`](WitProgram::to_c_slots) lowering before it is ported to CUDA.
///
/// `input_slots` is `slot[0..num_inputs]` and `col_slots[c] = slot[col_wires[c]]`.
pub fn interpret_c_slots_columns<F: Field>(
    ops: &[WitOpCSlot],
    num_inputs: u32,
    inputs: &[u64],
    input_slots: &[u32],
    col_slots: &[u32],
    max_slots: u32,
) -> Vec<F> {
    assert_eq!(inputs.len() as u32, num_inputs);
    assert_eq!(input_slots.len() as u32, num_inputs);
    let mut vals: Vec<Val<F>> = vec![Val::Nat(0); max_slots as usize];
    for i in 0..num_inputs as usize {
        vals[input_slots[i] as usize] = Val::Nat(inputs[i]);
    }
    for op in ops {
        let (a, b, out) = (op.a as usize, op.b as usize, op.out as usize);
        match op.tag {
            0 => vals[out] = Val::Nat(op.imm0),
            1 => vals[out] = Val::Nat(vals[a].nat().wrapping_add(vals[b].nat())),
            8 => vals[out] = Val::Nat(vals[a].nat().wrapping_sub(vals[b].nat())),
            2 => {
                let x = vals[a].nat();
                let mask = if op.imm1 >= 64 { u64::MAX } else { (1u64 << op.imm1) - 1 };
                vals[out] = Val::Nat((x >> op.imm0) & mask);
            }
            11 => vals[out] = Val::Nat(u64::from(vals[a].nat() == vals[b].nat())),
            20 => vals[out] = Val::Nat(vals[a].nat() << vals[b].nat()),
            21 => vals[out] = Val::Nat(vals[a].nat() >> vals[b].nat()),
            23 => vals[out] = Val::Nat(vals[a].nat().wrapping_mul(vals[b].nat())),
            24 => vals[out] = Val::Nat(vals[a].nat() ^ vals[b].nat()),
            25 => vals[out] = Val::Nat(vals[a].nat() & vals[b].nat()),
            12 => vals[out] = if vals[a].nat() != 0 { vals[b] } else { vals[op.imm1 as usize] },
            3 => vals[out] = Val::Field(F::from_canonical_u64(vals[a].nat())),
            4 => vals[out] = Val::Field(vals[a].field() + vals[b].field()),
            19 => vals[out] = Val::Field(vals[a].field() - vals[b].field()),
            5 => vals[out] = Val::Field(vals[a].field().inverse()),
            18 => vals[out] = if vals[a].nat() != 0 { vals[b] } else { vals[op.imm1 as usize] },
            // lookups (incl. guarded + byte-table + var-width): no wire, skipped for columns
            6 | 7 | 9 | 13 | 14 | 15 | 16 | 17 | 22 => {}
            t => panic!("unknown WitOpCSlot tag {t}"),
        }
    }
    col_slots
        .iter()
        .map(|&sidx| match vals[sidx as usize] {
            Val::Field(f) => f,
            Val::Nat(n) => F::from_canonical_u64(n),
        })
        .collect()
}

/// STREAMING (store-through) counterpart of [`interpret_c_slots_columns`] — the CPU
/// model of the shared-memory kernel. Columns are written at PRODUCTION (`op.col`),
/// input-columns at load, multi-column wires by the epilogue; there is no readout
/// pass and no `is_field` tracking (store type is static per op). MUST produce
/// columns identical to the SSA [`interpret_c_columns`].
#[allow(clippy::too_many_arguments)]
pub fn interpret_c_slots_streaming_columns<F: Field>(
    ops: &[WitOpCSlot],
    num_inputs: u32,
    inputs: &[u64],
    input_slots: &[u32],
    input_cols: &[(u32, u32)],
    epilogue_slots: &[(u32, u32)],
    n_cols: usize,
    max_slots: u32,
) -> Vec<F> {
    assert_eq!(inputs.len() as u32, num_inputs);
    let mut out = vec![F::zero(); n_cols];
    let mut vals: Vec<Val<F>> = vec![Val::Nat(0); max_slots as usize];
    for i in 0..num_inputs as usize {
        vals[input_slots[i] as usize] = Val::Nat(inputs[i]);
    }
    for &(i, c) in input_cols {
        out[c as usize] = F::from_canonical_u64(inputs[i as usize]);
    }
    for op in ops {
        let (a, b, o) = (op.a as usize, op.b as usize, op.out as usize);
        match op.tag {
            0 => vals[o] = Val::Nat(op.imm0),
            1 => vals[o] = Val::Nat(vals[a].nat().wrapping_add(vals[b].nat())),
            8 => vals[o] = Val::Nat(vals[a].nat().wrapping_sub(vals[b].nat())),
            2 => {
                let x = vals[a].nat();
                let mask = if op.imm1 >= 64 { u64::MAX } else { (1u64 << op.imm1) - 1 };
                vals[o] = Val::Nat((x >> op.imm0) & mask);
            }
            11 => vals[o] = Val::Nat(u64::from(vals[a].nat() == vals[b].nat())),
            20 => vals[o] = Val::Nat(vals[a].nat() << vals[b].nat()),
            21 => vals[o] = Val::Nat(vals[a].nat() >> vals[b].nat()),
            23 => vals[o] = Val::Nat(vals[a].nat().wrapping_mul(vals[b].nat())),
            24 => vals[o] = Val::Nat(vals[a].nat() ^ vals[b].nat()),
            25 => vals[o] = Val::Nat(vals[a].nat() & vals[b].nat()),
            12 => vals[o] = if vals[a].nat() != 0 { vals[b] } else { vals[op.imm1 as usize] },
            3 => vals[o] = Val::Field(F::from_canonical_u64(vals[a].nat())),
            4 => vals[o] = Val::Field(vals[a].field() + vals[b].field()),
            19 => vals[o] = Val::Field(vals[a].field() - vals[b].field()),
            5 => vals[o] = Val::Field(vals[a].field().inverse()),
            18 => vals[o] = if vals[a].nat() != 0 { vals[b] } else { vals[op.imm1 as usize] },
            // lookups: no wire, no column
            6 | 7 | 9 | 13 | 14 | 15 | 16 | 17 | 22 => continue,
            t => panic!("unknown WitOpCSlot tag {t}"),
        }
        if op.col != u32::MAX {
            out[op.col as usize] = match vals[o] {
                Val::Field(f) => f,
                Val::Nat(n) => F::from_canonical_u64(n),
            };
        }
    }
    for &(s, c) in epilogue_slots {
        out[c as usize] = match vals[s as usize] {
            Val::Field(f) => f,
            Val::Nat(n) => F::from_canonical_u64(n),
        };
    }
    out
}

/// Register-allocated counterpart of [`interpret_c_columns`]: runs the op-DAG using
/// the `slot` map (from [`WitProgram::allocate_slots`]) into a reused `max_slots`-entry
/// array instead of the SSA one-slot-per-op array. MUST produce identical columns to
/// the SSA interpreter — this is the CPU model the tiered register-allocated kernel
/// ports (the kernel does `nat[op.out] = f(nat[op.a], nat[op.b])` with these slots).
pub fn interpret_slots_columns<F: Field>(
    program: &WitProgram,
    inputs: &[u64],
    col_wires: &[u32],
    slot: &[u32],
    max_slots: u32,
) -> Vec<F> {
    let ni = program.num_inputs as usize;
    assert_eq!(inputs.len(), ni);
    let mut vals: Vec<Val<F>> = vec![Val::Nat(0); max_slots as usize];
    for i in 0..ni {
        vals[slot[i] as usize] = Val::Nat(inputs[i]);
    }
    let mut wc = ni;
    macro_rules! r {
        ($w:expr) => {
            vals[slot[$w.0 as usize] as usize]
        };
    }
    for op in &program.ops {
        if !op.produces_wire() {
            continue; // lookups/range checks emit no wire (columns don't depend on them)
        }
        let v = match *op {
            WitOp::ConstNat(v) => Val::Nat(v),
            WitOp::WrappingAdd(a, b) => Val::Nat(r!(a).nat().wrapping_add(r!(b).nat())),
            WitOp::WrappingSub(a, b) => Val::Nat(r!(a).nat().wrapping_sub(r!(b).nat())),
            WitOp::Bits { src, offset, width } => {
                let x = r!(src).nat();
                let mask = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
                Val::Nat((x >> offset) & mask)
            }
            WitOp::Eq(a, b) => Val::Nat(u64::from(r!(a).nat() == r!(b).nat())),
            WitOp::Shl(a, b) => Val::Nat(r!(a).nat() << r!(b).nat()),
            WitOp::Shr(a, b) => Val::Nat(r!(a).nat() >> r!(b).nat()),
            WitOp::Mul(a, b) => Val::Nat(r!(a).nat().wrapping_mul(r!(b).nat())),
            WitOp::Xor(a, b) => Val::Nat(r!(a).nat() ^ r!(b).nat()),
            WitOp::And(a, b) => Val::Nat(r!(a).nat() & r!(b).nat()),
            WitOp::Select { cond, a, b } => {
                if r!(cond).nat() != 0 {
                    r!(a)
                } else {
                    r!(b)
                }
            }
            WitOp::NatToField(a) => Val::Field(F::from_canonical_u64(r!(a).nat())),
            WitOp::FieldAdd(a, b) => Val::Field(r!(a).field() + r!(b).field()),
            WitOp::FieldSub(a, b) => Val::Field(r!(a).field() - r!(b).field()),
            WitOp::FieldInverse(a) => Val::Field(r!(a).field().inverse()),
            WitOp::FieldSelect { cond, a, b } => {
                if r!(cond).nat() != 0 {
                    r!(a)
                } else {
                    r!(b)
                }
            }
            _ => unreachable!("non-value op passed produces_wire"),
        };
        vals[slot[wc] as usize] = v;
        wc += 1;
    }
    col_wires
        .iter()
        .map(|&w| match vals[slot[w as usize] as usize] {
            Val::Field(f) => f,
            Val::Nat(n) => F::from_canonical_u64(n),
        })
        .collect()
}

/// Row count of the Range chip's multiplicity table (`range/trace.rs::NUM_ROWS`):
/// a `{Range, a, bits}` lookup lands at `row = a + (1 << bits)`, `bits ≤ 16`.
pub const RANGE_HIST_ROWS: usize = 1 << 17;
/// Row count of the Byte chip's multiplicity table (`bytes/trace.rs::NUM_ROWS`):
/// a `{op, _, b, c}` lookup lands at `row = (b << 8) + c`, column `op as usize`.
pub const BYTE_HIST_ROWS: usize = 1 << 16;

/// Lookup-emitting interpreter over the flat [`WitOpC`] op-DAG — the CPU model of
/// the device byte-lookup histogram kernel (the dual of [`interpret_c_columns`],
/// which produces columns and *skips* the lookup ops). Runs one row at a time and
/// accumulates each emitted lookup into one of two **shard-level** dense
/// multiplicity tables, reusing the same accumulators across every row (heed
/// iter-004: NO per-chunk dense arrays — allocate/zero once per shard, then add).
///
/// The two tables and their index conventions match the consumer chips' own
/// `generate_trace_into` exactly, so the device histogram is bit-for-bit equal to
/// what the host `generate_dependencies` → Byte/Range trace would produce:
/// - **Range chip** (`range/trace.rs`): `U16RangeCheck`/`BitRangeCheck` →
///   `{Range, a, bits}` → `range_hist[a + (1 << bits)] += 1` (single column).
/// - **Byte chip** (`bytes/trace.rs`): `U8RangeCheck` → `{U8Range, b, c}` →
///   `byte_hist[((b << 8) + c) * NUM_BYTE_MULT_COLS + (U8Range as usize)] += 1`.
///
/// Add/Sub emit only these two lookup kinds. Lookups read only `Nat` wires, so the
/// pass is integer-only: field-producing ops push a placeholder to keep wire ids
/// aligned with [`interpret_c_columns`] (their results are never read here).
///
/// `inputs` is row-major `[n_rows][num_inputs]`; `range_hist`/`byte_hist` must be
/// pre-sized to [`RANGE_HIST_ROWS`] and `BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS`.
pub fn interpret_c_lookups(
    ops: &[WitOpC],
    num_inputs: u32,
    inputs: &[u64],
    n_rows: usize,
    range_hist: &mut [u32],
    byte_hist: &mut [u32],
) {
    let ni = num_inputs as usize;
    assert_eq!(inputs.len(), n_rows * ni);
    let mut wires: Vec<u64> = Vec::new();
    for row in 0..n_rows {
        wires.clear();
        wires.extend_from_slice(&inputs[row * ni..(row + 1) * ni]);
        for op in ops {
            match op.tag {
                0 => wires.push(op.imm0),
                1 => wires.push(wires[op.a as usize].wrapping_add(wires[op.b as usize])),
                8 => wires.push(wires[op.a as usize].wrapping_sub(wires[op.b as usize])),
                2 => {
                    let x = wires[op.a as usize];
                    let mask = if op.imm1 >= 64 { u64::MAX } else { (1u64 << op.imm1) - 1 };
                    wires.push((x >> op.imm0) & mask);
                }
                11 => wires.push(u64::from(wires[op.a as usize] == wires[op.b as usize])),
                20 => wires.push(wires[op.a as usize] << wires[op.b as usize]),
                21 => wires.push(wires[op.a as usize] >> wires[op.b as usize]),
                23 => wires.push(wires[op.a as usize].wrapping_mul(wires[op.b as usize])),
                24 => wires.push(wires[op.a as usize] ^ wires[op.b as usize]),
                25 => wires.push(wires[op.a as usize] & wires[op.b as usize]),
                12 => {
                    let c = wires[op.a as usize];
                    wires.push(if c != 0 { wires[op.b as usize] } else { wires[op.imm1 as usize] });
                }
                // Field-producing ops: placeholder wire (never read by a lookup).
                3 | 4 | 5 | 18 | 19 => wires.push(0),
                // U16RangeCheck: {Range, a: v, bits: 16}.
                6 => {
                    let v = wires[op.a as usize] as u16 as usize;
                    range_hist[v + (1 << 16)] += 1;
                }
                // BitRangeCheck: {Range, a: v, bits} (bits in imm0).
                7 => {
                    let v = wires[op.a as usize] as u16 as usize;
                    range_hist[v + (1usize << op.imm0)] += 1;
                }
                // BitRangeCheckVar: {Range, a: v, bits} where bits = nat[b] (a wire).
                22 => {
                    let v = wires[op.a as usize] as u16 as usize;
                    let bits = wires[op.b as usize];
                    range_hist[v + (1usize << bits)] += 1;
                }
                // U8RangeCheck: {U8Range, b: nat[a], c: nat[b]}.
                9 => {
                    let b_val = wires[op.a as usize] as u8 as usize;
                    let c_val = wires[op.b as usize] as u8 as usize;
                    let r = (b_val << 8) + c_val;
                    byte_hist[r * NUM_BYTE_MULT_COLS + (ByteOpcode::U8Range as usize)] += 1;
                }
                // Guarded U16RangeCheck: guard wire in `b`.
                13 => {
                    if wires[op.b as usize] != 0 {
                        let v = wires[op.a as usize] as u16 as usize;
                        range_hist[v + (1 << 16)] += 1;
                    }
                }
                // Guarded BitRangeCheck: guard wire in `b`, bits in imm0.
                14 => {
                    if wires[op.b as usize] != 0 {
                        let v = wires[op.a as usize] as u16 as usize;
                        range_hist[v + (1usize << op.imm0)] += 1;
                    }
                }
                // Guarded U8RangeCheck: guard wire in `imm1`.
                15 => {
                    if wires[op.imm1 as usize] != 0 {
                        let b_val = wires[op.a as usize] as u8 as usize;
                        let c_val = wires[op.b as usize] as u8 as usize;
                        let r = (b_val << 8) + c_val;
                        byte_hist[r * NUM_BYTE_MULT_COLS + (ByteOpcode::U8Range as usize)] += 1;
                    }
                }
                // Byte-table lookup {opcode in imm1, b in a, c in b}: index (b,c,opcode).
                16 => {
                    let b_val = wires[op.a as usize] as u8 as usize;
                    let c_val = wires[op.b as usize] as u8 as usize;
                    let opc = wires[op.imm1 as usize] as usize;
                    byte_hist[((b_val << 8) + c_val) * NUM_BYTE_MULT_COLS + opc] += 1;
                }
                // Guarded byte-table lookup: guard wire in imm0.
                17 => {
                    if wires[op.imm0 as usize] != 0 {
                        let b_val = wires[op.a as usize] as u8 as usize;
                        let c_val = wires[op.b as usize] as u8 as usize;
                        let opc = wires[op.imm1 as usize] as usize;
                        byte_hist[((b_val << 8) + c_val) * NUM_BYTE_MULT_COLS + opc] += 1;
                    }
                }
                t => panic!("unknown WitOpC tag {t}"),
            }
        }
    }
}

/// Reconstruct the `HashMap<ByteLookupEvent, usize>` (the form a chip's
/// `generate_dependencies` produces, and that the Byte/Range chips consume) from the
/// two dense device histograms filled by [`interpret_c_lookups`]. This is the host
/// side of the device byte-lookup path: the prover merges the result into the
/// shard's `byte_lookups` so the existing host Byte/Range tracegen is unchanged.
///
/// Inverts the (bijective) index conventions:
/// - Range:  `row = a + (1 << bits)` ⇒ `bits = ⌊log2(row)⌋`, `a = row - (1<<bits)`.
/// - Byte:   `idx = ((b<<8)+c)*NUM_BYTE_MULT_COLS + (opcode as usize)` ⇒ split row/col.
///
/// Add/Sub populate only the `U8Range` byte column and `Range`; other byte columns
/// (AND/OR/XOR/LTU/MSB) stay zero here and are handled generically should a future
/// device chip emit them.
pub fn byte_lookups_from_histograms(
    range_hist: &[u32],
    byte_hist: &[u32],
) -> HashMap<ByteLookupEvent, usize> {
    let mut map = HashMap::new();
    // Range table (single column): row = a + (1<<bits), bits >= 1 for any real event.
    for (row, &mult) in range_hist.iter().enumerate() {
        if mult == 0 {
            continue;
        }
        let bits = 63 - (row as u64).leading_zeros(); // floor(log2(row))
        let a = (row - (1usize << bits)) as u16;
        map.insert(
            ByteLookupEvent { opcode: ByteOpcode::Range, a, b: bits as u8, c: 0 },
            mult as usize,
        );
    }
    // Byte table (NUM_BYTE_MULT_COLS columns): row = (b<<8)+c, column = opcode index.
    for (idx, &mult) in byte_hist.iter().enumerate() {
        if mult == 0 {
            continue;
        }
        let row = idx / NUM_BYTE_MULT_COLS;
        let col = idx % NUM_BYTE_MULT_COLS;
        let b = (row >> 8) as u8;
        let c = (row & 0xFF) as u8;
        // The histogram indexes by (opcode, b, c) only; the result `a` is dropped to
        // halve the table. But `a` is part of the `ByteLookupEvent` HashMap key the
        // consumer (Byte chip) reads, so it must be reconstructed as the *exact* value
        // the host emits — a deterministic function of (opcode, b, c). Getting this
        // wrong (e.g. `a = 0` for AND/OR/XOR, whose host `a = b OP c` is non-zero)
        // splits the LogUp tuples → GKR cumulative-sum mismatch (caught by the e2e
        // bench on real Bitwise rows; synthetic-only chips like Add/Sub emit just
        // U8Range/Range where `a = 0`, which is why it slipped earlier).
        let (opcode, a) = match col {
            0 => (ByteOpcode::AND, (b & c) as u16),
            1 => (ByteOpcode::OR, (b | c) as u16),
            2 => (ByteOpcode::XOR, (b ^ c) as u16),
            3 => (ByteOpcode::U8Range, 0),
            // LTU lookups are emitted to assert `b < c`, so the host result is 1.
            4 => (ByteOpcode::LTU, 1),
            // MSB of the byte `b` (the lookups always pass `c = 0`).
            5 => (ByteOpcode::MSB, (b >> 7) as u16),
            _ => unreachable!("byte table has {NUM_BYTE_MULT_COLS} columns"),
        };
        map.insert(ByteLookupEvent { opcode, a, b, c }, mult as usize);
    }
    map
}

/// View a column struct recorded over [`WireId`]s as the flat slice of its column
/// wires: index `i` is the wire that produces column `i`. Column structs are
/// `#[repr(C)]` (`AlignedBorrow`), so for `T = WireId` they are a contiguous array
/// of `WireId`. This is how a backend maps the recorded wires onto trace columns
/// generically (no per-gadget code) — the GPU kernel will use the same mapping.
pub fn columns_as_wires<C>(cols: &C) -> &[WireId] {
    let n = core::mem::size_of::<C>() / core::mem::size_of::<WireId>();
    debug_assert_eq!(n * core::mem::size_of::<WireId>(), core::mem::size_of::<C>());
    // Safety: `C` is a `#[repr(C)]` column struct instantiated at `T = WireId`,
    // hence a contiguous `[WireId; n]` with matching alignment.
    unsafe { core::slice::from_raw_parts(cols as *const C as *const WireId, n) }
}

/// Start recording a gadget whose inputs are described by the `#[repr(C)]`
/// (`AlignedBorrow`) witgen-input struct `I` instantiated at `T = WireId`: returns
/// the builder (with `num_inputs` = the struct's field count) and the input view —
/// wires `0..N` cast to `I`, so struct field order IS the packed input layout. The
/// input-side dual of [`columns_as_wires`]: a backend packs each event into one
/// `I<u64>` row and the recorder reads the same struct over wires, so the pack
/// order, the kernel input layout, and the witgen signature cannot drift apart.
pub fn record_witgen_inputs<I: Copy>() -> (RecordingWitnessBuilder, I)
where
    [WireId]: core::borrow::Borrow<I>,
{
    let n = core::mem::size_of::<I>() / core::mem::size_of::<WireId>();
    let wires: Vec<WireId> = (0..n as u32).map(RecordingWitnessBuilder::input).collect();
    let input: &I = core::borrow::Borrow::borrow(wires.as_slice());
    (RecordingWitnessBuilder::new(n as u32), *input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::HostWitnessBuilder;
    use crate::operations::AddrAddOperation;
    use sp1_core_executor::events::ByteLookupEvent;
    use sp1_primitives::SP1Field;

    type F = SP1Field;

    /// Record `AddrAddOperation::witgen` once, then assert that interpreting the
    /// recorded op-DAG reproduces the host backend's columns and lookups exactly
    /// over a range of inputs — validating the record-then-interpret model.
    #[test]
    fn addr_add_record_interpret_matches_host() {
        // Record the gadget once (shape is row-independent).
        let mut rec = RecordingWitnessBuilder::new(2);
        let mut cols_wires = AddrAddOperation::<WireId>::default();
        AddrAddOperation::<WireId>::witgen(
            &mut rec,
            &mut cols_wires,
            RecordingWitnessBuilder::input(0),
            RecordingWitnessBuilder::input(1),
        );
        let program = rec.finish();

        let cases: [(u64, u64); 8] = [
            (0, 0),
            (1, 2),
            (0xFFFF, 0x1),
            (0x12_3456, 0xab_cdef),
            (0xFFFF_FFFF, 0xFF),
            (1 << 40, (1 << 20) + 3),
            (0x7FFF_FFFF_FFFF, 0),
            (0xAAAA_BBBB_CCCC, 0x11_2233),
        ];
        for (a, b) in cases {
            if a.wrapping_add(b) >> 48 != 0 {
                continue; // out of the gadget's valid u48 range
            }
            // Host backend (reference).
            let mut host_cols = AddrAddOperation::<F>::default();
            let mut host_lookups: Vec<ByteLookupEvent> = Vec::new();
            {
                let mut hwb = HostWitnessBuilder::<F, _>::new(&mut host_lookups);
                AddrAddOperation::<F>::witgen(&mut hwb, &mut host_cols, a, b);
            }
            // Interpret the recorded program, mapping wires onto columns generically.
            let mut int_lookups: Vec<ByteLookupEvent> = Vec::new();
            let wires = interpret::<F, _>(&program, &[a, b], &mut int_lookups);
            let col_wires = columns_as_wires(&cols_wires);
            let int_cols: [F; 3] = core::array::from_fn(|i| wires[col_wires[i].0 as usize]);

            assert_eq!(host_cols.value, int_cols, "columns mismatch for ({a:#x}, {b:#x})");
            assert_eq!(host_lookups, int_lookups, "lookups mismatch for ({a:#x}, {b:#x})");

            // Validate the flat `WitOpC` columns-only interpreter — the exact
            // reference the GPU kernel ports (it reads this layout, one thread/row).
            let ops_c = program.to_c();
            let col_wire_idx: Vec<u32> = col_wires.iter().map(|w| w.0).collect();
            let flat_cols =
                interpret_c_columns::<F>(&ops_c, program.num_inputs, &[a, b], &col_wire_idx);
            assert_eq!(
                host_cols.value.to_vec(),
                flat_cols,
                "flat-C columns mismatch for ({a:#x}, {b:#x})"
            );
        }
    }

    /// Validate the device byte-lookup model: accumulate lookups from the `Add`
    /// chip's recorded op-DAG via [`interpret_c_lookups`] and assert the two dense
    /// histograms equal the Range/Byte multiplicity tables the host
    /// `generate_dependencies` would produce — proving the device index convention
    /// before the GPU kernel ports it.
    #[test]
    fn add_lookups_match_generate_dependencies() {
        use crate::alu::add_sub::add::{AddChip, AddCols};
        use crate::SupervisorMode;
        use rand::{rngs::StdRng, Rng, SeedableRng};
        use sp1_core_executor::events::{AluEvent, MemoryReadRecord, MemoryRecordEnum};
        use sp1_core_executor::{ExecutionRecord, Opcode, RTypeRecord};
        use sp1_hypercube::air::MachineAir;

        const NUM_ADD_INPUTS: usize = 16;

        // A register read whose previous timestamp precedes the current one.
        fn read(rng: &mut StdRng) -> MemoryRecordEnum {
            let prev_timestamp = rng.gen::<u32>() as u64;
            let timestamp = prev_timestamp + 1 + (rng.gen::<u32>() as u64);
            MemoryRecordEnum::Read(MemoryReadRecord {
                value: rng.gen::<u32>() as u64,
                timestamp,
                prev_timestamp,
                prev_page_prot_record: None,
            })
        }

        // The model's table sizes must equal the consumer chips' own row counts.
        assert_eq!(RANGE_HIST_ROWS, crate::range::trace::NUM_ROWS);
        assert_eq!(BYTE_HIST_ROWS, crate::bytes::trace::NUM_ROWS);

        let mut rng = StdRng::seed_from_u64(0xADD);
        let add_events = (0..1000)
            .map(|i| {
                let b = rng.gen::<u32>() as u64;
                let c = rng.gen::<u32>() as u64;
                let a = b.wrapping_add(c);
                let alu = AluEvent::new(
                    (i as u64) * 8 + 8,
                    (i as u64) * 4 + 4,
                    Opcode::ADD,
                    a,
                    b,
                    c,
                    false,
                );
                // op_a/op_b/op_c are register indices (< field order, since they are
                // `nat_to_field`'d directly); the operand *values* live in the memory
                // records and the AluEvent (b, c), decomposed into limbs downstream.
                let record = RTypeRecord {
                    op_a: rng.gen_range(1..32),
                    a: read(&mut rng),
                    op_b: rng.gen_range(1..32),
                    b: read(&mut rng),
                    op_c: rng.gen_range(1..32),
                    c: read(&mut rng),
                    is_untrusted: false,
                };
                (alu, record)
            })
            .collect::<Vec<_>>();

        let shard = ExecutionRecord { add_events: add_events.clone(), ..Default::default() };
        let chip = AddChip::<SupervisorMode>::default();

        // Reference: host generate_dependencies → byte_lookups, materialized into the
        // two consumer-chip dense tables exactly as range/trace.rs and bytes/trace.rs.
        let mut dep_out = ExecutionRecord::default();
        MachineAir::<F>::generate_dependencies(&chip, &shard, &mut dep_out);
        let mut ref_range = vec![0u32; RANGE_HIST_ROWS];
        let mut ref_byte = vec![0u32; BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS];
        for (lookup, mult) in dep_out.byte_lookups.iter() {
            if lookup.opcode == ByteOpcode::Range {
                ref_range[(lookup.a as usize) + (1 << lookup.b)] = *mult as u32;
            } else {
                let r = ((lookup.b as usize) << 8) + lookup.c as usize;
                ref_byte[r * NUM_BYTE_MULT_COLS + lookup.opcode as usize] = *mult as u32;
            }
        }

        // Record the Add op-DAG once, pack each event's 16 inputs (mirrors the device
        // tracegen path), then accumulate lookups via the model.
        let mut rec = RecordingWitnessBuilder::new(NUM_ADD_INPUTS as u32);
        let mut cols_w = AddCols::<WireId, SupervisorMode>::default();
        let wire = |i: u32| RecordingWitnessBuilder::input(i);
        AddCols::<WireId, SupervisorMode>::witgen(
            &mut rec,
            &mut cols_w,
            wire(0),
            wire(1),
            wire(2),
            wire(3),
            wire(4),
            wire(5),
            wire(6),
            wire(7),
            wire(8),
            wire(9),
            wire(10),
            wire(11),
            wire(12),
            wire(13),
            wire(14),
            wire(15),
        );
        let program = rec.finish();
        let ops_c = program.to_c();

        let n_events = add_events.len();
        let mut inputs = vec![0u64; n_events * NUM_ADD_INPUTS];
        for (slot, (alu, r)) in inputs.chunks_mut(NUM_ADD_INPUTS).zip(add_events.iter()) {
            let (a, b, c) = (r.a, r.b, r.c);
            slot.copy_from_slice(&[
                alu.clk,
                alu.pc,
                alu.b,
                alu.c,
                r.op_a as u64,
                r.op_b,
                r.op_c,
                a.previous_record().value,
                a.previous_record().timestamp,
                a.current_record().timestamp,
                b.previous_record().value,
                b.previous_record().timestamp,
                b.current_record().timestamp,
                c.previous_record().value,
                c.previous_record().timestamp,
                c.current_record().timestamp,
            ]);
        }

        let mut range_hist = vec![0u32; RANGE_HIST_ROWS];
        let mut byte_hist = vec![0u32; BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS];
        interpret_c_lookups(
            &ops_c,
            program.num_inputs,
            &inputs,
            n_events,
            &mut range_hist,
            &mut byte_hist,
        );

        assert_eq!(range_hist, ref_range, "range histogram mismatch vs generate_dependencies");
        assert_eq!(byte_hist, ref_byte, "byte histogram mismatch vs generate_dependencies");

        // Reconstruct the byte-lookup map from the histograms (the host side of the
        // device path) and assert it equals the host `generate_dependencies` map —
        // validating the index inversion the prover relies on to merge device-
        // produced lookups into `record.byte_lookups`.
        let reconstructed = byte_lookups_from_histograms(&range_hist, &byte_hist);
        assert_eq!(
            reconstructed, dep_out.byte_lookups,
            "reconstructed byte_lookups != generate_dependencies map"
        );
    }

    /// A guarded lookup (recorded inside `push_guard`/`pop_guard`) must be emitted
    /// only on rows where the guard wire is non-zero — the per-row conditional-
    /// execution primitive for immediate/mode-flag chips. Validated on both the
    /// `interpret` (Val) path and the flat-C `interpret_c_lookups` histogram path.
    #[test]
    fn guarded_lookup_emits_only_when_guard_set() {
        use crate::air::WitnessBuilder;

        // input(0) = guard, input(1) = value. One guarded + one unguarded u16 check.
        let mut rec = RecordingWitnessBuilder::new(2);
        let g = RecordingWitnessBuilder::input(0);
        let v = RecordingWitnessBuilder::input(1);
        rec.push_guard(g);
        rec.add_u16_range_check(v);
        rec.pop_guard();
        rec.add_u16_range_check(v);
        let program = rec.finish();

        // `interpret` (Val): guard=0 → only the unguarded check; guard=1 → both.
        for (guard, expected) in [(0u64, 1usize), (1, 2)] {
            let mut lookups: Vec<ByteLookupEvent> = Vec::new();
            let _ = interpret::<F, _>(&program, &[guard, 0x1234], &mut lookups);
            assert_eq!(lookups.len(), expected, "interpret guard={guard}");
        }

        // flat-C histogram: the value's range bin gets 2 hits when guarded, else 1.
        let ops_c = program.to_c();
        let val = 0x55u64;
        let idx = (val as u16 as usize) + (1 << 16);
        for (guard, expected) in [(0u64, 1u32), (1, 2)] {
            let mut range = vec![0u32; RANGE_HIST_ROWS];
            let mut byte = vec![0u32; BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS];
            interpret_c_lookups(&ops_c, 2, &[guard, val], 1, &mut range, &mut byte);
            assert_eq!(range[idx], expected, "interpret_c_lookups guard={guard}");
        }
    }

    /// A general byte-table lookup `{opcode, a, b, c}` (per-row opcode) must index the
    /// byte histogram by `(opcode, b, c)` (result `a` ignored), and `interpret` must
    /// emit the full host event (incl. `a`).
    #[test]
    fn byte_op_lookup_indexes_by_opcode_b_c() {
        use crate::air::WitnessBuilder;
        use sp1_core_executor::ByteOpcode;

        let mut rec = RecordingWitnessBuilder::new(4);
        let opcode = RecordingWitnessBuilder::input(0);
        let a = RecordingWitnessBuilder::input(1);
        let b = RecordingWitnessBuilder::input(2);
        let c = RecordingWitnessBuilder::input(3);
        rec.add_byte_lookup(opcode, a, b, c);
        let program = rec.finish();

        // opcode = 2 (XOR), a = result (ignored by the histogram), b = 0x12, c = 0x34.
        let inputs = [2u64, 0xAB, 0x12, 0x34];

        // flat-C histogram path.
        let ops_c = program.to_c();
        let mut range = vec![0u32; RANGE_HIST_ROWS];
        let mut byte = vec![0u32; BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS];
        interpret_c_lookups(&ops_c, 4, &inputs, 1, &mut range, &mut byte);
        let idx = ((0x12usize << 8) + 0x34) * NUM_BYTE_MULT_COLS + 2;
        assert_eq!(byte[idx], 1, "byte histogram index");
        assert_eq!(byte.iter().sum::<u32>(), 1, "exactly one byte lookup");

        // `interpret` (Val) emits the full host event including the result `a`.
        let mut lookups: Vec<ByteLookupEvent> = Vec::new();
        let _ = interpret::<F, _>(&program, &inputs, &mut lookups);
        assert_eq!(
            lookups,
            vec![ByteLookupEvent { opcode: ByteOpcode::XOR, a: 0xAB, b: 0x12, c: 0x34 }]
        );
    }

    /// Variable shift ops (`shl`/`shr`) and the variable-width range check: columns
    /// compute `a << s` / `a >> s`, and the range lookup indexes by the per-row width.
    #[test]
    fn shifts_and_var_range_check() {
        use crate::air::WitnessBuilder;
        use slop_algebra::AbstractField;
        let mut rec = RecordingWitnessBuilder::new(2);
        let a = RecordingWitnessBuilder::input(0);
        let s = RecordingWitnessBuilder::input(1);
        let l = rec.shl(a, s);
        let r = rec.shr(a, s);
        rec.add_bit_range_check_var(l, s); // {Range, l as u16, bits = s}
        let program = rec.finish();
        let ops_c = program.to_c();

        let inputs = [0x1234u64, 4];
        let col_wires = [l.0, r.0];
        let cols = interpret_c_columns::<F>(&ops_c, 2, &inputs, &col_wires);
        assert_eq!(cols[0], F::from_canonical_u64(0x1234 << 4));
        assert_eq!(cols[1], F::from_canonical_u64(0x1234 >> 4));

        let mut range = vec![0u32; RANGE_HIST_ROWS];
        let mut byte = vec![0u32; BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS];
        interpret_c_lookups(&ops_c, 2, &inputs, 1, &mut range, &mut byte);
        let v = ((0x1234u64 << 4) as u16) as usize;
        assert_eq!(range[v + (1 << 4)], 1, "var-width range lookup index");
        assert_eq!(range.iter().sum::<u32>(), 1);
    }
}
