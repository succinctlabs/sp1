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

use slop_algebra::Field;
use sp1_core_executor::events::ByteRecord;

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
}

impl RecordingWitnessBuilder {
    /// Start recording a gadget with `num_inputs` input wires (ids `0..num_inputs`).
    pub fn new(num_inputs: u32) -> Self {
        Self { program: WitProgram { ops: Vec::new(), num_inputs }, next_wire: num_inputs }
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
        self.program.ops.push(WitOp::U16RangeCheck(a));
    }
    fn add_u8_range_check(&mut self, a: WireId, b: WireId) {
        self.program.ops.push(WitOp::U8RangeCheck(a, b));
    }
    fn add_bit_range_check(&mut self, a: WireId, bits: u8) {
        self.program.ops.push(WitOp::BitRangeCheck { src: a, bits });
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
        }
    }
    // Project to a field per wire (Nat wires embed canonically; only Field wires
    // are ever read as columns, but returning a uniform Vec keeps indexing simple).
    wires
        .into_iter()
        .map(|w| match w {
            Val::Field(f) => f,
            Val::Nat(n) => F::from_canonical_u64(n),
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
            6 | 7 | 9 => {} // lookup: no wire, skipped for columns
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
}
