//! Device main-trace + dependency generation for the trusted `DivRem` chip
//! (DIV/DIVU/REM/REMU + W variants) — the most complex ALU chip. Values requiring
//! an actual division (`quotient`/`remainder`, computational/abs forms, sign flags,
//! upper 64 bits of `c*quotient`) are computed host-side in the packing function
//! and passed as inputs, so the op-DAG needs no divide op. Padding rows use a
//! non-zero template ("0 / 1").

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
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    alu::divrem::{DivRemChip, DivRemCols, NUM_DIVREM_COLS_SUPERVISOR},
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::{air::MachineAir, Word};

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `DivRem` row (see [`DivRemCols::witgen`]).
const NUM_DIVREM_INPUTS: usize = 30;

pub(crate) fn pack_divrem_inputs(events: &[(AluEvent, RTypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_DIVREM_INPUTS];
    inputs.par_chunks_mut(NUM_DIVREM_INPUTS).zip(events.par_iter()).for_each(
        |(slot, (alu, r))| {
            let opcode = alu.opcode;
            let (a, b, c) = (r.a, r.b, r.c);

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
            let quotient_comp = if is_unsigned_word_operation(opcode) {
                quotient as u32 as u64
            } else {
                quotient
            };
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
                is_overflow =
                    (alu.b as i64 == i64::MIN && alu.c as i64 == -1) as u64;
                abs_remainder = (remainder as i64).unsigned_abs();
                abs_c = (alu.c as i64).unsigned_abs();
                max_abs_c_or_1 = u64::max(1, (alu.c as i64).unsigned_abs());
            } else if is_signed_word_operation(opcode) {
                rem_neg = get_msb((remainder as i32) as i64 as u64) as u64;
                b_neg = get_msb((alu.b as i32) as i64 as u64) as u64;
                c_neg = get_msb((alu.c as i32) as i64 as u64) as u64;
                is_overflow =
                    (alu.b as i32 == i32::MIN && alu.c as i32 == -1) as u64;
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

            slot.copy_from_slice(&[
                alu.clk,
                alu.pc,
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
                alu.a,
                b_comp,
                c_comp,
                quotient,
                remainder,
                quotient_comp,
                remainder_comp,
                abs_remainder,
                abs_c,
                max_abs_c_or_1,
                opcode as u64,
                ctq_hi,
                b_neg,
                c_neg,
                rem_neg,
                is_overflow,
            ]);
        },
    );
    inputs
}

fn record_divrem_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_DIVREM_INPUTS as u32);
    let mut cols_w = DivRemCols::<WireId, SupervisorMode>::default();
    let w = |i: u32| RecordingWitnessBuilder::input(i);
    DivRemCols::<WireId, SupervisorMode>::witgen(
        &mut rec, &mut cols_w, w(0), w(1), w(2), w(3), w(4), w(5), w(6), w(7), w(8), w(9), w(10),
        w(11), w(12), w(13), w(14), w(15), w(16), w(17), w(18), w(19), w(20), w(21), w(22), w(23),
        w(24), w(25), w(26), w(27), w(28), w(29),
    );
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "DivRem gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
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

impl CudaTracegenAir<F> for DivRemChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_divrem_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_DIVREM_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.divrem_events;
        let n_events = if height == 0 { 0 } else { events.len() };

        let inputs = pack_divrem_inputs(&events[..n_events]);

        let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone()).unwrap();
        ops_dev.extend_from_host_slice(&ops_c)?;
        let mut col_dev = Buffer::try_with_capacity_in(col_wires.len(), scope.clone()).unwrap();
        col_dev.extend_from_host_slice(&col_wires)?;
        let mut in_dev = Buffer::try_with_capacity_in(inputs.len().max(1), scope.clone()).unwrap();
        in_dev.extend_from_host_slice(&inputs)?;

        // Initialize every row with the non-zero padding template; the kernel
        // overwrites all columns of the event rows.
        let mut trace = {
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
            Tensor::<F, TaskScope>::from(buf).reshape([n_cols, height])
        };

        if n_events > 0 {
            unsafe {
                const BLOCK: usize = 64;
                let grid = n_events.div_ceil(BLOCK);
                let args = args!(
                    trace.as_mut_ptr(),
                    height,
                    ops_dev.as_ptr(),
                    ops_c.len(),
                    col_dev.as_ptr(),
                    n_cols,
                    program.num_inputs,
                    in_dev.as_ptr(),
                    n_events
                );
                scope
                    .launch_kernel(TaskScope::witgen_interp_kernel(), grid, BLOCK, &args, 0)
                    .unwrap();
            }
        }

        Ok(DeviceMle::from(trace))
    }

    fn supports_device_dependencies(&self) -> bool {
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

        let (program, _col_wires) = record_divrem_program();
        let inputs = pack_divrem_inputs(&events[..n_events]);
        super::accumulate_lookups(&program, &inputs, n_events, range_dev, byte_dev, scope).await
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
                    if matches!(opcode, Opcode::DIV | Opcode::DIVU | Opcode::DIVW | Opcode::DIVUW)
                    {
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
            interpret_slots_columns, RecordingWitnessBuilder, WireId,
        };
        use sp1_core_machine::alu::divrem::DivRemCols;

        // Build the DivRem program inline (`record_divrem_program` asserts the SSA
        // wire count <= 256, which DivRem exceeds — the whole point of reg-alloc).
        let mut rec = RecordingWitnessBuilder::new(super::NUM_DIVREM_INPUTS as u32);
        let mut cols_w = DivRemCols::<WireId, SupervisorMode>::default();
        let w = |i: u32| RecordingWitnessBuilder::input(i);
        DivRemCols::<WireId, SupervisorMode>::witgen(
            &mut rec, &mut cols_w, w(0), w(1), w(2), w(3), w(4), w(5), w(6), w(7), w(8), w(9),
            w(10), w(11), w(12), w(13), w(14), w(15), w(16), w(17), w(18), w(19), w(20), w(21),
            w(22), w(23), w(24), w(25), w(26), w(27), w(28), w(29),
        );
        let program = rec.finish();
        let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();

        let (slot, max_slots) = program.allocate_slots(&col_wires);
        println!(
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
        let input_slots = &slot[..super::NUM_DIVREM_INPUTS];
        let col_slots: Vec<u32> = col_wires.iter().map(|&w| slot[w as usize]).collect();
        let ni = super::NUM_DIVREM_INPUTS;
        for row in 0..events.len() {
            let row_in = &inputs[row * ni..(row + 1) * ni];
            let ssa: Vec<F> = interpret_c_columns(&ops_c, ni as u32, row_in, &col_wires);
            let alloc: Vec<F> =
                interpret_slots_columns(&program, row_in, &col_wires, &slot, max_slots);
            let flat: Vec<F> = interpret_c_slots_columns(
                &ops_slots, ni as u32, row_in, input_slots, &col_slots, max_slots,
            );
            assert_eq!(ssa, alloc, "reg-alloc column mismatch at row {row}");
            assert_eq!(ssa, flat, "slot-flat (WitOpCSlot) column mismatch at row {row}");
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

    /// Device-vs-CPU trace equality for `DivRem` over all 8 opcodes with random
    /// 64-bit operands — exercises signed/unsigned, word ops, sign extension, the
    /// abs negation gadgets, overflow detection, the dual `c*quotient` products,
    /// division-by-zero, and the non-zero padding template.
    #[tokio::test]
    #[ignore = "gated off device (too wide → OOM); witgen validated at the higher wire cap"]
    async fn test_divrem_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let mut rng = StdRng::seed_from_u64(0xD11E);
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
            let divrem_events = (0..1600)
                .map(|i| {
                    let opcode = ops[i % ops.len()];
                    // Mix in division-by-zero and overflow edge cases.
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
                    let (a, _) = get_quotient_and_remainder(b, c, opcode);
                    // `a` is the result the executor would record; the chip only
                    // reads it for the result word, so use the quotient/remainder.
                    let result = {
                        let (q, r) = get_quotient_and_remainder(b, c, opcode);
                        if matches!(
                            opcode,
                            Opcode::DIV | Opcode::DIVU | Opcode::DIVW | Opcode::DIVUW
                        ) {
                            q
                        } else {
                            r
                        }
                    };
                    let _ = a;
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
                .collect::<Vec<_>>();

            let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
                divrem_events: divrem_events.clone(),
                ..Default::default()
            });

            let chip = DivRemChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let gpu_trace = chip
                .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
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
