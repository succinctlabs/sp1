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
    Bits { src: WireId, offset: u32, width: u32 },
    NatToField(WireId),
    FieldAdd(WireId, WireId),
    FieldInverse(WireId),
    U16RangeCheck(WireId),
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
    fn bits(&mut self, a: WireId, offset: u32, width: u32) -> WireId {
        self.value(WitOp::Bits { src: a, offset, width })
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
            WitOp::Bits { src, offset, width } => {
                let x = wires[src.0 as usize].nat();
                let mask = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
                wires.push(Val::Nat((x >> offset) & mask));
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
        }
    }
}
