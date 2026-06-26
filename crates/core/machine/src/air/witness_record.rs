//! Recording backend for the trace-gen DSL: a [`WitnessBuilder`] that, instead of
//! computing, records each op into a flat op-DAG (the witgen IR). The IR is then
//! run by [`interpret`] — a tiny stack/array interpreter — which is the CPU model
//! of the future GPU interpreter kernel (one thread per row).
//!
//! `RecordingWitnessBuilder::record(...)` walks a gadget's `witgen` *once* (the
//! shape is row-independent), producing a [`WitProgram`]; [`interpret`] then runs
//! that program per row with the row's concrete inputs. A unit test asserts that
//! interpreting the recorded program reproduces [`HostWitnessBuilder`] exactly —
//! validating the record-then-interpret model that the CUDA backend will port.
//!
//! See `autoresearch/design/TRACEGEN-DSL.md` (Phase 2).

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
    Bits { src: WireId, offset: u32, width: u32 },
    Eq(WireId, WireId),
    Select { cond: WireId, a: WireId, b: WireId },
    NatToField(WireId),
    FieldAdd(WireId, WireId),
    FieldInverse(WireId),
    U16RangeCheck(WireId),
    U8RangeCheck(WireId, WireId),
    BitRangeCheck { src: WireId, bits: u8 },
    /// Guarded lookups: emitted only on rows where `guard != 0` (per-row branches).
    U16RangeCheckGuarded { guard: WireId, src: WireId },
    U8RangeCheckGuarded { guard: WireId, a: WireId, b: WireId },
    BitRangeCheckGuarded { guard: WireId, src: WireId, bits: u8 },
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
    /// Current guard wire (`Some` inside a guarded scope); lookups recorded while set
    /// become guarded variants.
    guard: Option<WireId>,
}

impl RecordingWitnessBuilder {
    /// Start recording a gadget with `num_inputs` input wires (ids `0..num_inputs`).
    pub fn new(num_inputs: u32) -> Self {
        Self {
            program: WitProgram { ops: Vec::new(), num_inputs },
            next_wire: num_inputs,
            guard: None,
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
    fn select(&mut self, cond: WireId, a: WireId, b: WireId) -> WireId {
        self.value(WitOp::Select { cond, a, b })
    }
    fn nat_to_field(&mut self, a: WireId) -> WireId {
        self.value(WitOp::NatToField(a))
    }
    fn field_add(&mut self, a: WireId, b: WireId) -> WireId {
        self.value(WitOp::FieldAdd(a, b))
    }
    fn field_inverse(&mut self, a: WireId) -> WireId {
        self.value(WitOp::FieldInverse(a))
    }
    fn add_u16_range_check(&mut self, a: WireId) {
        let op = match self.guard {
            Some(guard) => WitOp::U16RangeCheckGuarded { guard, src: a },
            None => WitOp::U16RangeCheck(a),
        };
        self.program.ops.push(op);
    }
    fn add_u8_range_check(&mut self, a: WireId, b: WireId) {
        let op = match self.guard {
            Some(guard) => WitOp::U8RangeCheckGuarded { guard, a, b },
            None => WitOp::U8RangeCheck(a, b),
        };
        self.program.ops.push(op);
    }
    fn add_bit_range_check(&mut self, a: WireId, bits: u8) {
        let op = match self.guard {
            Some(guard) => WitOp::BitRangeCheckGuarded { guard, src: a, bits },
            None => WitOp::BitRangeCheck { src: a, bits },
        };
        self.program.ops.push(op);
    }
    fn push_guard(&mut self, guard: WireId) {
        self.guard = Some(guard);
    }
    fn pop_guard(&mut self) {
        self.guard = None;
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
            WitOp::WrappingAdd(a, b) => {
                wires.push(Val::Nat(wires[a.0 as usize].nat().wrapping_add(wires[b.0 as usize].nat())))
            }
            WitOp::WrappingSub(a, b) => {
                wires.push(Val::Nat(wires[a.0 as usize].nat().wrapping_sub(wires[b.0 as usize].nat())))
            }
            WitOp::Bits { src, offset, width } => {
                let x = wires[src.0 as usize].nat();
                let mask = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
                wires.push(Val::Nat((x >> offset) & mask));
            }
            WitOp::Eq(a, b) => wires.push(Val::Nat(u64::from(
                wires[a.0 as usize].nat() == wires[b.0 as usize].nat(),
            ))),
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
            WitOp::FieldInverse(a) => {
                wires.push(Val::Field(wires[a.0 as usize].field().inverse()))
            }
            WitOp::U16RangeCheck(a) => record.add_u16_range_check(wires[a.0 as usize].nat() as u16),
            WitOp::U8RangeCheck(a, b) => record
                .add_u8_range_check(wires[a.0 as usize].nat() as u8, wires[b.0 as usize].nat() as u8),
            WitOp::BitRangeCheck { src, bits } => {
                record.add_bit_range_check(wires[src.0 as usize].nat() as u16, bits)
            }
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
/// interpretation by the GPU kernel (which reads this exact layout). The fields are
/// overloaded per `tag`:
///
/// | tag | op            | a       | b   | imm0          | imm1   |
/// |-----|---------------|---------|-----|---------------|--------|
/// | 0   | ConstNat      | -       | -   | value         | -      |
/// | 1   | WrappingAdd   | lhs     | rhs | -             | -      |
/// | 2   | Bits          | src     | -   | offset        | width  |
/// | 3   | NatToField    | src     | -   | -             | -      |
/// | 4   | FieldAdd      | lhs     | rhs | -             | -      |
/// | 5   | FieldInverse  | src     | -   | -             | -      |
/// | 6   | U16RangeCheck | src     | -   | -             | -      |
/// | 7   | BitRangeCheck | src     | -   | bits          | -      |
///
/// Tags 6/7 are lookups: they emit no wire and are skipped by the columns-only
/// interpreter (lookups are produced by `generate_dependencies`, not the trace).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct WitOpC {
    pub tag: u32,
    pub a: u32,
    pub b: u32,
    pub imm1: u32,
    pub imm0: u64,
}

impl WitProgram {
    /// Lower the op-DAG to the flat device layout.
    /// Total live wires the interpreter needs per row: the inputs plus every
    /// value-producing op (lookup ops emit no wire). The GPU kernel's per-thread
    /// wire arrays must be at least this large.
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
                            | WitOp::U8RangeCheck(..)
                            | WitOp::U16RangeCheckGuarded { .. }
                            | WitOp::U8RangeCheckGuarded { .. }
                            | WitOp::BitRangeCheckGuarded { .. }
                    )
                })
                .count()
    }

    pub fn to_c(&self) -> Vec<WitOpC> {
        self.ops
            .iter()
            .map(|op| match *op {
                WitOp::ConstNat(v) => WitOpC { tag: 0, a: 0, b: 0, imm1: 0, imm0: v },
                WitOp::WrappingAdd(a, b) => WitOpC { tag: 1, a: a.0, b: b.0, imm1: 0, imm0: 0 },
                WitOp::WrappingSub(a, b) => WitOpC { tag: 8, a: a.0, b: b.0, imm1: 0, imm0: 0 },
                WitOp::U8RangeCheck(a, b) => WitOpC { tag: 9, a: a.0, b: b.0, imm1: 0, imm0: 0 },
                WitOp::Eq(a, b) => WitOpC { tag: 11, a: a.0, b: b.0, imm1: 0, imm0: 0 },
                WitOp::Select { cond, a, b } => {
                    WitOpC { tag: 12, a: cond.0, b: a.0, imm1: b.0, imm0: 0 }
                }
                WitOp::Bits { src, offset, width } => {
                    WitOpC { tag: 2, a: src.0, b: 0, imm1: width, imm0: offset as u64 }
                }
                WitOp::NatToField(a) => WitOpC { tag: 3, a: a.0, b: 0, imm1: 0, imm0: 0 },
                WitOp::FieldAdd(a, b) => WitOpC { tag: 4, a: a.0, b: b.0, imm1: 0, imm0: 0 },
                WitOp::FieldInverse(a) => WitOpC { tag: 5, a: a.0, b: 0, imm1: 0, imm0: 0 },
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
            })
            .collect()
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
            12 => {
                let c = wires[op.a as usize].nat();
                wires.push(if c != 0 {
                    wires[op.b as usize]
                } else {
                    wires[op.imm1 as usize]
                });
            }
            3 => wires.push(Val::Field(F::from_canonical_u64(wires[op.a as usize].nat()))),
            4 => wires.push(Val::Field(wires[op.a as usize].field() + wires[op.b as usize].field())),
            5 => wires.push(Val::Field(wires[op.a as usize].field().inverse())),
            6 | 7 | 9 | 13 | 14 | 15 => {} // lookup (incl. guarded): no wire, skipped for columns
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
                12 => {
                    let c = wires[op.a as usize];
                    wires.push(if c != 0 { wires[op.b as usize] } else { wires[op.imm1 as usize] });
                }
                // Field-producing ops: placeholder wire (never read by a lookup).
                3 | 4 | 5 => wires.push(0),
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
        map.insert(ByteLookupEvent { opcode: ByteOpcode::Range, a, b: bits as u8, c: 0 }, mult as usize);
    }
    // Byte table (NUM_BYTE_MULT_COLS columns): row = (b<<8)+c, column = opcode index.
    for (idx, &mult) in byte_hist.iter().enumerate() {
        if mult == 0 {
            continue;
        }
        let row = idx / NUM_BYTE_MULT_COLS;
        let col = idx % NUM_BYTE_MULT_COLS;
        let opcode = match col {
            0 => ByteOpcode::AND,
            1 => ByteOpcode::OR,
            2 => ByteOpcode::XOR,
            3 => ByteOpcode::U8Range,
            4 => ByteOpcode::LTU,
            5 => ByteOpcode::MSB,
            _ => unreachable!("byte table has {NUM_BYTE_MULT_COLS} columns"),
        };
        let b = (row >> 8) as u8;
        let c = (row & 0xFF) as u8;
        map.insert(ByteLookupEvent { opcode, a: 0, b, c }, mult as usize);
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
                let alu =
                    AluEvent::new((i as u64) * 8 + 8, (i as u64) * 4 + 4, Opcode::ADD, a, b, c, false);
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
}
