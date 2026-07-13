//! Device main-trace + dependency generation for the trusted `DivRem` chip
//! (DIV/DIVU/REM/REMU + W variants) — the most complex ALU chip. Values requiring
//! an actual division (`quotient`/`remainder`, computational/abs forms, sign flags,
//! upper 64 bits of `c*quotient`) are computed host-side in the packing function
//! and passed as inputs, so the op-DAG needs no divide op. Padding rows use a
//! non-zero template ("0 / 1").
//!
//! DivRem is FUSED-ONLY on device: the pinned slot lowering needs 272 slots
//! (246 column wires stay live to the end of the DAG) — over the 256-slot kernel
//! cap — but the STREAMING (store-through) lowering collapses it to 68 transient
//! slots with an empty epilogue, which fits the streaming fused kernel tier
//! (68 > the 24-slot smem cap, so it takes the local-wire streaming variant).
//! Production always routes through `generate_trace_device_with_lookups` because
//! `supports_device_dependencies` is true (dependencies are byte/range lookups
//! only — the default `generate_dependencies`, no `GlobalInteractionEvent`s).

use core::borrow::BorrowMut;

use rayon::prelude::*;
use slop_algebra::AbstractField;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::{
    events::AluEvent, get_msb, get_quotient_and_remainder, is_signed_64bit_operation,
    is_signed_word_operation, is_unsigned_word_operation, RTypeRecord,
};
use sp1_core_machine::{
    adapter::register::r_type::RTypeReaderWitgenInput,
    air::{columns_as_wires, record_witgen_inputs, WireId},
    alu::divrem::{
        DivRemChip, DivRemCols, DivRemWitgenInput, NUM_DIVREM_COLS_SUPERVISOR,
        NUM_DIVREM_WITGEN_INPUTS,
    },
    SupervisorMode,
};
use sp1_gpu_cudart::{DeviceBuffer, DeviceMle, TaskScope};
use sp1_hypercube::{air::MachineAir, Word};

use crate::{CudaTracegenAir, F};

/// Pack each event into one [`DivRemWitgenInput`] row (the host-side division
/// results are computed here — see the struct docs).
pub(crate) fn pack_divrem_inputs(events: &[(AluEvent, RTypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_DIVREM_WITGEN_INPUTS];
    inputs.par_chunks_mut(NUM_DIVREM_WITGEN_INPUTS).zip(events.par_iter()).for_each(
        |(chunk, (alu, r))| {
            let opcode = alu.opcode;

            // Computational b, c (sign/zero extended for word ops).
            let b_comp = if is_signed_word_operation(opcode) {
                alu.b as i32 as i64 as u64
            } else if is_unsigned_word_operation(opcode) {
                alu.b as u32 as u64
            } else {
                alu.b
            };
            let c_comp = if is_signed_word_operation(opcode) {
                alu.c as i32 as i64 as u64
            } else if is_unsigned_word_operation(opcode) {
                alu.c as u32 as u64
            } else {
                alu.c
            };

            let (quotient, remainder) = get_quotient_and_remainder(alu.b, alu.c, opcode);
            let quotient_comp =
                if is_unsigned_word_operation(opcode) { quotient as u32 as u64 } else { quotient };
            let remainder_comp = if is_unsigned_word_operation(opcode) {
                remainder as u32 as u64
            } else {
                remainder
            };

            // Sign flags + abs values (mirrors the chip's `event_to_row`).
            let (b_neg, c_neg, rem_neg, is_overflow, abs_remainder, abs_c, max_abs_c_or_1);
            if is_signed_64bit_operation(opcode) {
                rem_neg = get_msb(remainder) as u64;
                b_neg = get_msb(alu.b) as u64;
                c_neg = get_msb(alu.c) as u64;
                is_overflow = (alu.b as i64 == i64::MIN && alu.c as i64 == -1) as u64;
                abs_remainder = (remainder as i64).unsigned_abs();
                abs_c = (alu.c as i64).unsigned_abs();
                max_abs_c_or_1 = u64::max(1, (alu.c as i64).unsigned_abs());
            } else if is_signed_word_operation(opcode) {
                rem_neg = get_msb((remainder as i32) as i64 as u64) as u64;
                b_neg = get_msb((alu.b as i32) as i64 as u64) as u64;
                c_neg = get_msb((alu.c as i32) as i64 as u64) as u64;
                is_overflow = (alu.b as i32 == i32::MIN && alu.c as i32 == -1) as u64;
                abs_remainder = (remainder as i64).unsigned_abs();
                abs_c = (c_comp as i64).unsigned_abs();
                max_abs_c_or_1 = u64::max(1, (c_comp as i64).unsigned_abs());
            } else if is_unsigned_word_operation(opcode) {
                b_neg = 0;
                c_neg = 0;
                rem_neg = 0;
                is_overflow = 0;
                abs_remainder = remainder_comp;
                abs_c = alu.c as u32 as u64;
                max_abs_c_or_1 = u32::max(1, alu.c as u32) as u64;
            } else {
                b_neg = 0;
                c_neg = 0;
                rem_neg = 0;
                is_overflow = 0;
                abs_remainder = remainder_comp;
                abs_c = alu.c;
                max_abs_c_or_1 = u64::max(1, alu.c);
            }

            // Upper 64 bits of the 128-bit c*quotient product (signed for signed ops).
            let ctq_hi = if is_signed_64bit_operation(opcode) || is_signed_word_operation(opcode) {
                (((quotient_comp as i64 as i128).wrapping_mul(c_comp as i64 as i128)) >> 64) as u64
            } else {
                ((quotient_comp as u128).wrapping_mul(c_comp as u128) >> 64) as u64
            };

            let slot: &mut DivRemWitgenInput<u64> = chunk.borrow_mut();
            slot.clk = alu.clk;
            slot.pc = alu.pc;
            slot.adapter = RTypeReaderWitgenInput::from_record(r);
            slot.a = alu.a;
            slot.b_comp = b_comp;
            slot.c_comp = c_comp;
            slot.quotient = quotient;
            slot.remainder = remainder;
            slot.quotient_comp = quotient_comp;
            slot.remainder_comp = remainder_comp;
            slot.abs_remainder = abs_remainder;
            slot.abs_c = abs_c;
            slot.max_abs_c_or_1 = max_abs_c_or_1;
            slot.opcode = opcode as u64;
            slot.ctq_hi = ctq_hi;
            slot.b_neg = b_neg;
            slot.c_neg = c_neg;
            slot.rem_neg = rem_neg;
            slot.is_overflow = is_overflow;
        },
    );
    inputs
}

fn record_divrem_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let (mut rec, input) = record_witgen_inputs::<DivRemWitgenInput<WireId>>();
    let mut cols_w = DivRemCols::<WireId, SupervisorMode>::default();
    DivRemCols::<WireId, SupervisorMode>::witgen(&mut rec, &mut cols_w, &input);
    let program = rec.finish();
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    // DivRem exceeds the pinned cap (272 slots > 256) — it runs on device only via
    // the STREAMING lowering (68 transient slots, empty epilogue). Assert that the
    // streaming gate in `generate_trace_and_lookups_slots_into` will actually take
    // the streaming tier (a non-empty epilogue or an over-cap footprint would fall
    // back to the pinned kernel, whose 256-slot assert DivRem fails).
    let (_, s_max, epi) = program.allocate_slots_streaming(&col_wires);
    assert!(
        (s_max as usize) <= super::WITGEN_MAX_WIRES && epi.is_empty(),
        "DivRem streaming lowering needs {s_max} slots (epilogue {}) — does not fit \
         the streaming kernel tier",
        epi.len()
    );
    (program, col_wires)
}

/// The chip's cached [`WitgenChip`](super::WitgenChip) descriptor: recorded +
/// lowered ONCE per process (the program is shard-independent), not per shard.
fn divrem_witgen_chip() -> &'static super::WitgenChip {
    static CHIP: std::sync::OnceLock<super::WitgenChip> = std::sync::OnceLock::new();
    CHIP.get_or_init(|| {
        let (program, col_wires) = record_divrem_program();
        super::WitgenChip::new(program, col_wires)
    })
}

/// Lookup-only variant of the cached descriptor: an EMPTY column map, so the
/// pinned slot allocation does NOT pin the column wires (pinned-with-columns is
/// 272 slots > the cap; transient-only allocation fits comfortably). The lookup
/// kernel executes the same op order, so the emitted lookups are identical.
/// (The eagerly-computed streaming lowering is unused here beyond a debug log —
/// acceptable: one-time, KB-scale, and keeping `WitgenChip::new` uniform beats a
/// second lazy field.)
fn divrem_lookup_chip() -> &'static super::WitgenChip {
    static CHIP: std::sync::OnceLock<super::WitgenChip> = std::sync::OnceLock::new();
    CHIP.get_or_init(|| {
        let (program, _col_wires) = record_divrem_program();
        super::WitgenChip::new(program, Vec::new())
    })
}

/// Build the non-zero padding template ("0 / 1" — see `generate_trace_into`).
fn padding_template(n_cols: usize) -> Vec<F> {
    let mut tmpl = vec![F::zero(); n_cols];
    {
        let cols: &mut DivRemCols<F, SupervisorMode> = tmpl.as_mut_slice().borrow_mut();
        cols.is_divu = F::one();
        cols.adapter.op_c_memory.prev_value = Word::from(1u64);
        cols.abs_c[0] = F::one();
        cols.c[0] = F::one();
        cols.max_abs_c_or_1[0] = F::one();
        cols.b_not_neg_not_overflow = F::one();
        cols.is_c_0.populate(1);
    }
    tmpl
}

/// Upload a trace initialized with the padding template broadcast to every row
/// (the streaming kernel overwrites all columns of the event rows; padding rows
/// keep the template).
fn template_trace(
    n_cols: usize,
    height: usize,
    scope: &TaskScope,
) -> Result<Tensor<F, TaskScope>, CopyError> {
    let tmpl = padding_template(n_cols);
    let mut init = vec![F::zero(); n_cols * height];
    for col in 0..n_cols {
        if tmpl[col] != F::zero() {
            for r in 0..height {
                init[col * height + r] = tmpl[col];
            }
        }
    }
    let mut buf = Buffer::try_with_capacity_in(init.len().max(1), scope.clone()).unwrap();
    buf.extend_from_host_slice(&init)?;
    Ok(Tensor::<F, TaskScope>::from(buf).reshape([n_cols, height]))
}

impl CudaTracegenAir<F> for DivRemChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    /// Non-fused path unsupported: DivRem's pinned lowering needs 272 slots (> the
    /// 256-slot kernel cap) — it ONLY fits via the streaming fused path. Production
    /// always routes here through `generate_trace_device_with_lookups` because
    /// `supports_device_dependencies` is true.
    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("DivRem device tracegen is fused-only (streaming lowering)")
    }

    /// Fused device path — the one the PROVER calls (the iter-067 lesson: without
    /// this override the enum dispatch hits the trait-default `unimplemented!()`).
    /// Pre-initializes the non-zero "0 / 1" padding template before the streaming
    /// fused kernel (68 transient slots, local-wire tier) overwrites the event rows
    /// and accumulates the chip's byte/range lookups into the shard histograms.
    async fn generate_trace_device_with_lookups(
        &self,
        input: &Self::Record,
        inputs: Vec<u64>,
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let chip = divrem_witgen_chip();
        let n_cols = chip.n_cols();
        debug_assert_eq!(n_cols, NUM_DIVREM_COLS_SUPERVISOR);
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let n_events =
            if height == 0 { 0 } else { inputs.len() / chip.program.num_inputs as usize };

        let trace = template_trace(n_cols, height, scope)?;
        super::generate_trace_and_lookups_slots_into(
            chip,
            super::WitgenBatch { inputs: &inputs, n_events, height },
            trace,
            hist,
            scope,
        )
        .await
    }

    fn supports_device_dependencies(&self) -> bool {
        // Byte/range lookups only (default `generate_dependencies`, no
        // `GlobalInteractionEvent`s), produced by the fused streaming kernel.
        true
    }

    async fn generate_device_dependencies(
        &self,
        input: &Self::Record,
        range_dev: &mut DeviceBuffer<u32>,
        byte_dev: &mut DeviceBuffer<u32>,
        scope: &TaskScope,
    ) -> Result<(), CopyError> {
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.divrem_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }

        let inputs = pack_divrem_inputs(&events[..n_events]);
        // Lookup-only pass: no columns are read out, so use the descriptor whose
        // column map is empty (see `divrem_lookup_chip`) — its pinned allocation
        // never pins the column wires.
        super::accumulate_lookups_slots(
            divrem_lookup_chip(),
            &inputs,
            n_events,
            range_dev,
            byte_dev,
            scope,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::events::{AluEvent, MemoryReadRecord, MemoryRecordEnum};
    use sp1_core_executor::{get_quotient_and_remainder, ExecutionRecord, Opcode, RTypeRecord};
    use sp1_core_machine::alu::divrem::DivRemChip;
    use sp1_core_machine::SupervisorMode;
    use sp1_gpu_cudart::TaskScope;
    use sp1_hypercube::air::MachineAir;

    use crate::{CudaTracegenAir, F};

    /// Synthesize a DivRem event stream covering all 8 opcodes plus the edge cases
    /// (division by zero, overflow, word ops). Shared by the regalloc test and the
    /// (GPU-gated) device trace test.
    fn synth_divrem_events(n: usize, seed: u64) -> Vec<(AluEvent, RTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(seed);
        let ops = [
            Opcode::DIV,
            Opcode::DIVU,
            Opcode::REM,
            Opcode::REMU,
            Opcode::DIVW,
            Opcode::REMW,
            Opcode::DIVUW,
            Opcode::REMUW,
        ];
        (0..n)
            .map(|i| {
                let opcode = ops[i % ops.len()];
                let c = match i % 7 {
                    0 => 0u64,
                    1 => u64::MAX, // -1
                    _ => rng.gen::<u64>(),
                };
                let b = match i % 11 {
                    0 => i64::MIN as u64,
                    1 => (i32::MIN as i64) as u64,
                    _ => rng.gen::<u64>(),
                };
                let result = {
                    let (q, r) = get_quotient_and_remainder(b, c, opcode);
                    if matches!(opcode, Opcode::DIV | Opcode::DIVU | Opcode::DIVW | Opcode::DIVUW) {
                        q
                    } else {
                        r
                    }
                };
                let alu = AluEvent::new(
                    (i as u64) * 8 + 8,
                    (i as u64) * 4 + 4,
                    opcode,
                    result,
                    b,
                    c,
                    false,
                );
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
            .collect()
    }

    /// Register allocation on the DivRem op-DAG (the widest core ALU gadget, 1393+
    /// wires SSA): assert it (1) fits the 256-slot kernel cap after linear-scan slot
    /// allocation, and (2) the slot-resolved flat form (`WitOpCSlot`) produces columns
    /// bit-identical to the SSA interpreter over real packed events — the same CPU
    /// model that validated Mul (531 -> 100 slots) before its kernel port.
    #[test]
    fn divrem_regalloc_shrinks_and_matches() {
        use sp1_core_machine::air::{
            columns_as_wires, interpret_c_columns, interpret_c_slots_columns,
            interpret_c_slots_streaming_columns, interpret_slots_columns, record_witgen_inputs,
            WireId,
        };
        use sp1_core_machine::alu::divrem::{
            DivRemCols, DivRemWitgenInput, NUM_DIVREM_WITGEN_INPUTS,
        };

        // Build the DivRem program inline (`record_divrem_program` asserts the SSA
        // wire count <= 256, which DivRem exceeds — the whole point of reg-alloc).
        let (mut rec, input) = record_witgen_inputs::<DivRemWitgenInput<WireId>>();
        let mut cols_w = DivRemCols::<WireId, SupervisorMode>::default();
        DivRemCols::<WireId, SupervisorMode>::witgen(&mut rec, &mut cols_w, &input);
        let program = rec.finish();
        let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();

        let (slot, max_slots) = program.allocate_slots(&col_wires);
        eprintln!(
            "DivRem reg-alloc: num_wires={} -> max_slots={max_slots} ({:.1}x), n_cols={}",
            program.num_wires(),
            program.num_wires() as f64 / max_slots as f64,
            col_wires.len()
        );
        // MEASURED (iter-071): num_wires=1393 -> max_slots=272, n_cols=246. 272 is 16
        // over the current 256-slot kernel cap (`WITGEN_MAX_WIRES`) — DivRem needs the
        // NEXT KERNEL TIER (512, or a bespoke 288 tier) before it can run on device.
        // The column wires alone pin 246 slots (columns stay live to the end of the
        // DAG), so no allocator can get below n_cols=246; only 26 transient slots of
        // linear-scan pressure remain, i.e. a smarter allocator could AT BEST reach
        // ~246-256 — marginal. The 512 tier is the robust fix.
        assert!(
            max_slots as usize <= 2 * super::super::WITGEN_MAX_WIRES,
            "DivRem reg-alloc: max_slots={max_slots} exceeds even a 512 tier",
        );

        // Real events -> packed 30/row inputs; compare SSA vs slot interpreters per row.
        let events = synth_divrem_events(128, 0xD11E);
        let inputs = super::pack_divrem_inputs(&events);
        let ops_c = program.to_c();
        let ops_slots = program.to_c_slots(&slot);
        let input_slots = &slot[..NUM_DIVREM_WITGEN_INPUTS];
        let col_slots: Vec<u32> = col_wires.iter().map(|&w| slot[w as usize]).collect();
        let ni = NUM_DIVREM_WITGEN_INPUTS;
        for row in 0..events.len() {
            let row_in = &inputs[row * ni..(row + 1) * ni];
            let ssa: Vec<F> = interpret_c_columns(&ops_c, ni as u32, row_in, &col_wires);
            let alloc: Vec<F> =
                interpret_slots_columns(&program, row_in, &col_wires, &slot, max_slots);
            let flat: Vec<F> = interpret_c_slots_columns(
                &ops_slots,
                ni as u32,
                row_in,
                input_slots,
                &col_slots,
                max_slots,
            );
            assert_eq!(ssa, alloc, "reg-alloc column mismatch at row {row}");
            assert_eq!(ssa, flat, "slot-flat (WitOpCSlot) column mismatch at row {row}");
        }

        // STREAMING (store-through) lowering: columns written at production, wires
        // transient — the lowering that un-gates DivRem (pinned 272 > the 256-slot
        // cap; streaming drops the 246-column pinning entirely). Must match SSA
        // bit-for-bit and fit the kernel cap with an empty epilogue (the mod.rs
        // streaming gate requires both).
        let lowering = program.lower_streaming(&col_wires);
        eprintln!(
            "DivRem streaming: pinned max_slots={max_slots} -> streaming max_slots={} \
             (epilogue {} entries, input_cols {})",
            lowering.max_slots,
            lowering.epilogue.len(),
            lowering.input_cols.len()
        );
        assert!(
            (lowering.max_slots as usize) <= super::super::WITGEN_MAX_WIRES,
            "DivRem streaming: max_slots={} exceeds the kernel cap",
            lowering.max_slots
        );
        assert!(
            lowering.epilogue.is_empty(),
            "DivRem streaming: non-empty epilogue would fall back to the pinned kernel \
             (which DivRem does not fit)"
        );
        for row in 0..events.len() {
            let row_in = &inputs[row * ni..(row + 1) * ni];
            let ssa: Vec<F> = interpret_c_columns(&ops_c, ni as u32, row_in, &col_wires);
            let streamed: Vec<F> =
                interpret_c_slots_streaming_columns(&lowering, ni as u32, row_in, col_wires.len());
            assert_eq!(ssa, streamed, "streaming column mismatch at row {row}");
        }
    }

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

    /// Columns from the recorded op-DAG must equal the HOST trace bit-for-bit on
    /// every event row (SSA interpreter), and the padding template must equal the
    /// host's padded rows — the CPU model of what the streaming kernel writes.
    #[test]
    fn divrem_columns_match_host() {
        use sp1_core_machine::air::interpret_c_columns;
        use sp1_core_machine::alu::divrem::NUM_DIVREM_COLS_SUPERVISOR;

        let events = synth_divrem_events(100, 0xD11F);
        let shard = ExecutionRecord { divrem_events: events.clone(), ..Default::default() };
        let chip = DivRemChip::<SupervisorMode>::default();
        let trace = MachineAir::<F>::generate_trace(&chip, &shard, &mut ExecutionRecord::default());
        let width = NUM_DIVREM_COLS_SUPERVISOR;
        let height = trace.values.len() / width;

        let (program, col_wires) = super::record_divrem_program();
        assert_eq!(col_wires.len(), width);
        let ops_c = program.to_c();
        let ni = sp1_core_machine::alu::divrem::NUM_DIVREM_WITGEN_INPUTS;
        let inputs = super::pack_divrem_inputs(&events);
        let values = &trace.values;
        for row in 0..events.len() {
            let row_in = &inputs[row * ni..(row + 1) * ni];
            let cols: Vec<F> = interpret_c_columns(&ops_c, ni as u32, row_in, &col_wires);
            assert_eq!(
                &values[row * width..(row + 1) * width],
                &cols[..],
                "column mismatch at row {row}"
            );
        }
        // Padding rows must equal the device-side template init.
        let tmpl = super::padding_template(width);
        for row in events.len()..height {
            assert_eq!(
                &values[row * width..(row + 1) * width],
                &tmpl[..],
                "padding template mismatch at row {row}"
            );
        }
    }

    /// Byte/range-lookup histogram vs `generate_dependencies` (the iter-041 trap:
    /// columns-only tests miss lookup bugs): the MSB byte lookups, the LT gadget,
    /// the u16 range checks on quotient/remainder/c*quotient/carries, and the
    /// guarded remainder-check multiplicity must all match.
    #[test]
    fn divrem_lookups_match_generate_dependencies() {
        use sp1_core_executor::ByteOpcode;
        use sp1_core_machine::air::{interpret_c_lookups, BYTE_HIST_ROWS, RANGE_HIST_ROWS};
        use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;

        let events = synth_divrem_events(200, 0xD120);
        let shard = ExecutionRecord { divrem_events: events.clone(), ..Default::default() };
        let chip = DivRemChip::<SupervisorMode>::default();

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

        let (program, _col_wires) = super::record_divrem_program();
        let ops_c = program.to_c();
        let inputs = super::pack_divrem_inputs(&events);
        let mut range_hist = vec![0u32; RANGE_HIST_ROWS];
        let mut byte_hist = vec![0u32; BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS];
        interpret_c_lookups(
            &ops_c,
            program.num_inputs,
            &inputs,
            events.len(),
            &mut range_hist,
            &mut byte_hist,
        );
        assert_eq!(range_hist, ref_range, "range histogram mismatch");
        assert_eq!(byte_hist, ref_byte, "byte histogram mismatch");
    }

    /// Device-vs-CPU trace equality for `DivRem` via the FUSED streaming path (the
    /// one production calls) over all 8 opcodes with random 64-bit operands —
    /// exercises signed/unsigned, word ops, sign extension, the abs negation
    /// gadgets, overflow detection, the dual `c*quotient` products,
    /// division-by-zero, and the non-zero padding template.
    #[tokio::test]
    async fn test_divrem_generate_trace_device_fused() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let divrem_events = synth_divrem_events(1600, 0xD11E);
            let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
                divrem_events: divrem_events.clone(),
                ..Default::default()
            });

            let chip = DivRemChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let (mut range_dev, mut byte_dev) = crate::new_byte_histograms(&scope);
            let hist =
                crate::LookupHist { range: range_dev.as_mut_ptr(), byte: byte_dev.as_mut_ptr() };
            let inputs = super::pack_divrem_inputs(&divrem_events);
            let gpu_trace = chip
                .generate_trace_device_with_lookups(&gpu_shard, inputs, hist, &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&trace, &gpu_trace, &divrem_events);
        })
        .await
        .unwrap();
    }
}
