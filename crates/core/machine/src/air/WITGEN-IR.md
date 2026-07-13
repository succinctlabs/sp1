# The Witness-Generation IR (witgen IR) — spec & porting guide

Status: supervisor-mode common core + SHA + Keccak fully ported and
crossverified. 25 ops over pinned tag values 0..=25 (value 10 unassigned) — the
`WitTag` enum in witness_record.rs, cbindgen-shared with the CUDA kernels. This
doc is the durable contract: the IR is both the
device-tracegen mechanism and the substrate for future *programmatic chip
construction* — a chip is data (a program + a column map + a packer), not code.
(The `iter-NNN` citations here and in code comments refer to the development
log of the research branch this work landed from; the load-bearing conclusions
are restated where they matter.)

## 1. One witgen, two backends

Chip witness logic is written once, generic over the `WitnessBuilder` trait
(`crates/core/machine/src/air/`). Backends:

- `HostWitnessBuilder` — computes directly; the production CPU tracegen path.
- `RecordingWitnessBuilder` — records each op into a flat op-DAG (`WitProgram`).
  Gadget shape is row-independent, so ONE symbolic execution yields a program
  valid for every row.

```rust
// crates/core/machine/src/operations/add.rs
impl<T> AddOperation<T> {
    pub fn witgen<WB: WitnessBuilder>(
        wb: &mut WB,
        cols: &mut AddOperation<WB::Field>,  // Field = WireId when recording
        a: WB::Nat, b: WB::Nat,
    ) -> WB::Nat {
        let expected = wb.wrapping_add(a, b);
        for i in 0..WORD_SIZE {
            let limb = wb.bits(expected, (i as u32) * 16, 16);
            cols.value[i] = wb.nat_to_field(limb);
            wb.add_u16_range_check(limb);    // lookup: side effect, no wire
        }
        expected
    }
}
```

## 2. The IR (`crates/core/machine/src/air/witness_record.rs`)

- `WireId(u32)` — SSA value id.
- `WitOp` — 25 ops (16 value + 9 lookup). Value ops produce one wire: ConstNat, WrappingAdd/Sub, Mul,
  Xor(24), And(25), Shl, Shr, Eq, Bits{src,offset,width}, Select,
  NatToField, FieldAdd/Sub/Inverse, FieldSelect. Lookup ops produce none and
  feed the shard Byte/Range histograms: U16/U8/BitRangeCheck (+Var, +Guarded),
  ByteLookup(+Guarded) — guards enable per-row branches.
- `WitProgram { ops, num_inputs }`; `num_wires()` = inputs + value ops.
- Semantics quirks that bite: imm0/imm1 hold a WIRE for some tags (Select else,
  guards, byte-lookup opcode) and a LITERAL for others (Bits width/offset,
  ConstNat) — lower by semantic field, never positionally (iter-065).
  Byte-lookup `a` (result) is dropped on device — the byte table indexes
  multiplicities by `(opcode, b, c)` only, so `a` carries no information the
  table needs; it is kept host-side for event fidelity (iter-041).

## 3. Three lowerings

1. **SSA** `to_c() -> Vec<WitOpC{tag,a,b,imm1,imm0}>` — kernel does `nat[wc++]`.
   Legacy path (`AR_WITGEN_SLOTS=0` kill-switch).
2. **Register-allocated** `allocate_slots(col_wires) -> (wire→slot, max_slots)` +
   `to_c_slots` — `WitOpCSlot` gains `out`; liveness-based slot reuse
   (Mul 531 wires → 100 slots). Columns pinned live for the readout pass, so
   max_slots ≳ chip width.
3. **Streaming store-through** `allocate_slots_streaming` + `to_c_slots_streaming`
   — `WitOpCSlot.col != MAX` ⇒ the kernel writes the wire to
   `trace[row + col*height]` at production and frees the slot. Footprint = true
   intermediates (Keccak 2641 → 69; fleet 13–49). Multi-column wires (never
   observed) via a (slot,col) epilogue; input-columns stored at load. No readout
   loop, no `is_field[]` (store type is static per tag). Production default.

## 4. CPU interpreters = executable spec

Every kernel is a port of a CPU interpreter; every lowering is validated
bit-identical to the SSA reference before CUDA is touched:
`interpret` (op-DAG), `interpret_c_columns` (SSA flat),
`interpret_slots_columns` / `interpret_c_slots_columns` (reg-alloc),
`interpret_c_slots_streaming_columns` (store-through),
`interpret_c_lookups` (histograms, dual of the column forms).

## 5. Kernels (`sp1-gpu/crates/sys/lib/tracegen/witgen_interp.cu`)

Generic interpreters, one thread = one event row, `switch(op.tag)`:
SSA family (interp/lookup/fused), slot family (same, `nat[op.out]`), streaming
family: `witgen_fused_streaming_smem_kernel` (`__shared__` wires, cap 24,
`[slot][thread]` layout) and `witgen_fused_streaming_kernel` (local wires, cap
`WITGEN_MAX_WIRES=256`). Launcher tiers by `streaming_max`: ≤24 smem, ≤256
local, pinned fallback only for non-empty epilogue. Byte/Range table traces are
materialized from the histograms (`hist_trace_scatter` + `hist_to_trace`).
Adding an IR op = one `WitTag` variant plus one `case` line per kernel switch
(8 sites; a missed site hits that switch's trapping `default:`), nothing else.

## 6. Porting a chip — the recipe

```rust
// 1. record once (mirrors riscv/add.rs::record_add_program)
fn record_x_program() -> (WitProgram, Vec<u32>) {
    let (mut rec, input) = record_witgen_inputs::<XWitgenInput<WireId>>();
    let mut cols = XCols::<WireId, _>::default();
    XCols::witgen(&mut rec, &mut cols, &input);
    let program = rec.finish();
    // columns_as_wires returns &[WireId]; flatten to the raw u32 wire ids.
    let col_wires = columns_as_wires(&cols).iter().map(|w| w.0).collect();
    (program, col_wires)
}
// 2. pack events -> flat u64 rows (rayon; multi-row chips replay state at pack
//    time — ShaCompress/Keccak/MemoryGlobal pattern; padding rows pack the
//    host's dummy pattern so the kernel covers the full padded height)
// 3. trait impl (boilerplate -> shared launchers)
impl CudaTracegenAir<F> for XChip {
    fn supports_device_main_tracegen(&self) -> bool { true }
    fn supports_device_dependencies(&self) -> bool { true } // FALSE if deps emit
        // GlobalInteractionEvents (MemoryLocal/Syscall*/MemoryGlobal*)!
    async fn generate_trace_device_with_lookups(..) { // the path the PROVER calls
        super::generate_trace_and_lookups_slots(&program, &col_wires, ..).await
    }
}
// 4. FOUR dispatch arms in riscv/mod.rs: device_chip_name map,
//    pack_device_lookup_inputs arm, fused dispatch arm, deps dispatch arm.
//    Missing any => hang / empty trace / unreachable (iter-067).
```

## 7. Mandatory tests per chip

- columns vs host `generate_trace`, bit-for-bit, over real events INCLUDING
  padding/trapped rows, on SSA + slot + streaming interpreters;
- lookups vs host `generate_dependencies` (columns-only tests are blind to
  lookup bugs — iter-041/065);
- report `num_wires`, pinned `max_slots`, `streaming_max`, epilogue size;
- e2e crossverify before enabling in any default (unit tests don't exercise the
  fused prover path — iter-067).

## 8. Coverage (iter-076)

41/122 RiscvAir variants; supervisor common core + SHA + Keccak complete.
Remaining: 38 user-mode twins, untrusted/mprotect family, EC/field precompiles
(Ed25519/Secp/Bls/Bn254/Uint256/Poseidon2 — ShaCompress-recipe ports), and the
by-design exclusions (Program, Byte/Range, Global).
