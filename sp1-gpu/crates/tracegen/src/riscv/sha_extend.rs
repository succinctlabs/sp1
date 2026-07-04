//! Device main-trace + dependency generation for the `ShaExtend` precompile — the
//! FIRST precompile port. The chip is 48-rows-per-event, but each row depends only
//! on its own step's memory records, so the port packs one input row per
//! (event, j) pair and keeps the one-thread-per-row kernel. Trapped events (whose
//! 48 rows the host leaves all-zero) pack as `is_real = 0` rows: the record fn
//! guards every lookup on `is_real` and masks every column wire with
//! `field_select(is_real, col, 0)`.
//!
//! Dependencies are byte-lookups only (no global interaction events), so the fused
//! device path is available like the ALU chips.

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_tensor::Tensor;
use sp1_core_executor::{
    events::{PrecompileEvent, ShaExtendEvent},
    ExecutionRecord, SyscallCode, TrapError,
};
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId, WitnessBuilder},
    syscall::precompiles::sha256::{ShaExtendChip, ShaExtendCols, NUM_SHA_EXTEND_COLS},
};
use sp1_gpu_cudart::{DeviceBuffer, DeviceMle, TaskScope};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per ShaExtend ROW (one of the 48 steps of an event).
const NUM_SHA_EXTEND_INPUTS: usize = 19;

/// Pack 48 input rows per event. `events` yields `(trap_error, &ShaExtendEvent)`.
pub(crate) fn pack_sha_extend_inputs(
    events: &[(Option<TrapError>, &ShaExtendEvent)],
) -> Vec<u64> {
    let row_size = NUM_SHA_EXTEND_INPUTS;
    let mut inputs: Vec<u64> = vec![0u64; events.len() * 48 * row_size];
    inputs.par_chunks_mut(48 * row_size).zip(events.par_iter()).for_each(
        |(chunk, (trap_error, event))| {
            if trap_error.is_some() {
                return; // all-zero rows (is_real = 0) — matches the host's zero rows
            }
            let bumped_clk = event.clk + 1;
            for (j, slot) in chunk.chunks_mut(row_size).enumerate() {
                let mr = &event.memory_records[j];
                slot.copy_from_slice(&[
                    bumped_clk,
                    event.w_ptr,
                    j as u64,
                    mr.w_i_minus_15_reads.value,
                    mr.w_i_minus_15_reads.prev_timestamp,
                    mr.w_i_minus_15_reads.timestamp,
                    mr.w_i_minus_2_reads.value,
                    mr.w_i_minus_2_reads.prev_timestamp,
                    mr.w_i_minus_2_reads.timestamp,
                    mr.w_i_minus_16_reads.value,
                    mr.w_i_minus_16_reads.prev_timestamp,
                    mr.w_i_minus_16_reads.timestamp,
                    mr.w_i_minus_7_reads.value,
                    mr.w_i_minus_7_reads.prev_timestamp,
                    mr.w_i_minus_7_reads.timestamp,
                    mr.w_i_write.prev_value,
                    mr.w_i_write.prev_timestamp,
                    mr.w_i_write.timestamp,
                    1, // is_real
                ]);
            }
        },
    );
    inputs
}

/// Pack straight from a record (the `pack_device_lookup_inputs` arm).
pub(crate) fn pack_for_record(input: &ExecutionRecord) -> Vec<u64> {
    pack_sha_extend_inputs(&collect_events(input))
}

/// Collect this shard's SHA_EXTEND events with their trap state.
fn collect_events(input: &ExecutionRecord) -> Vec<(Option<TrapError>, &ShaExtendEvent)> {
    input
        .get_precompile_events(SyscallCode::SHA_EXTEND)
        .iter()
        .map(|(syscall_event, event)| {
            let event = if let PrecompileEvent::ShaExtend(event) = event {
                event
            } else {
                unreachable!()
            };
            (syscall_event.trap_error, event)
        })
        .collect()
}

pub(crate) fn record_sha_extend_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_SHA_EXTEND_INPUTS as u32);
    let mut cols_w = ShaExtendCols::<WireId>::default();
    let w = |i: u32| RecordingWitnessBuilder::input(i);
    let is_real = w(18);
    // Trapped events are packed as all-zero rows: guard every lookup on is_real...
    rec.push_guard(is_real);
    ShaExtendCols::<WireId>::witgen(
        &mut rec, &mut cols_w, w(0), w(1), w(2), w(3), w(4), w(5), w(6), w(7), w(8), w(9), w(10),
        w(11), w(12), w(13), w(14), w(15), w(16), w(17), is_real,
    );
    rec.pop_guard();
    // ...and mask every column wire so is_real = 0 rows are ALL-zero (the host
    // leaves trapped events' rows zeroed). Generic over the column struct.
    let zero = rec.const_nat(0);
    let zero_f = rec.nat_to_field(zero);
    let col_wires: Vec<u32> = columns_as_wires(&cols_w)
        .to_vec()
        .into_iter()
        .map(|cw| rec.field_select(is_real, cw, zero_f).0)
        .collect();
    let program = rec.finish();
    (program, col_wires)
}

impl CudaTracegenAir<F> for ShaExtendChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_sha_extend_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_SHA_EXTEND_COLS);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = collect_events(input);
        let n_rows = if height == 0 { 0 } else { events.len() * 48 };
        let inputs = pack_sha_extend_inputs(&events);

        // Wide gadget: register-allocated slot kernel path (like Mul).
        let trace = Tensor::<F, TaskScope>::zeros_in([n_cols, height], scope.clone());
        super::generate_columns_slots_into(
            &program, &col_wires, &inputs, n_rows, height, trace, scope,
        )
        .await
    }

    async fn generate_trace_device_with_lookups(
        &self,
        input: &Self::Record,
        inputs: Vec<u64>,
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_sha_extend_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_SHA_EXTEND_COLS);
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let n_rows = if height == 0 { 0 } else { inputs.len() / program.num_inputs as usize };
        super::generate_trace_and_lookups_slots(
            &program, &col_wires, n_cols, &inputs, n_rows, height, hist, scope,
        )
        .await
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
        let events = collect_events(input);
        let n_rows = if height == 0 { 0 } else { events.len() * 48 };
        if n_rows == 0 {
            return Ok(());
        }
        let (program, col_wires) = record_sha_extend_program();
        let inputs = pack_sha_extend_inputs(&events);
        super::accumulate_lookups_slots(
            &program, &col_wires, &inputs, n_rows, range_dev, byte_dev, scope,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core_executor::events::{
        MemoryReadRecord, MemoryWriteRecord, PrecompileEvent, ShaExtendEvent,
        ShaExtendMemoryRecords, SyscallEvent,
    };
    use sp1_core_executor::{ByteOpcode, ExecutionRecord, SyscallCode};
    use sp1_core_machine::air::{
        interpret_c_columns, interpret_c_lookups, interpret_c_slots_columns, BYTE_HIST_ROWS,
        RANGE_HIST_ROWS,
    };
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    use sp1_core_machine::syscall::precompiles::sha256::{ShaExtendChip, NUM_SHA_EXTEND_COLS};
    use sp1_hypercube::air::MachineAir;

    use crate::F;

    fn read(rng: &mut StdRng, clk: u64) -> MemoryReadRecord {
        MemoryReadRecord {
            value: rng.gen::<u32>() as u64,
            timestamp: clk,
            prev_timestamp: clk - 1 - (rng.gen::<u64>() & 0xFFFF),
            prev_page_prot_record: None,
        }
    }

    /// A record with `n` synthetic SHA_EXTEND events (48 steps each, valid SHA-256
    /// message-schedule memory records shape-wise; values random).
    fn synth_shard(n: usize, seed: u64) -> ExecutionRecord {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut record = ExecutionRecord::default();
        for e in 0..n {
            let clk = (e as u64 + 1) * 1_000_000 + 1;
            let w_ptr = (rng.gen::<u64>() & 0xFFFF_FFFF) & !7;
            let memory_records = (0..48)
                .map(|j| {
                    let step_clk = clk + 1 + j;
                    ShaExtendMemoryRecords {
                        w_i_minus_15_reads: read(&mut rng, step_clk),
                        w_i_minus_2_reads: read(&mut rng, step_clk),
                        w_i_minus_16_reads: read(&mut rng, step_clk),
                        w_i_minus_7_reads: read(&mut rng, step_clk),
                        w_i_write: MemoryWriteRecord {
                            prev_timestamp: step_clk - 1,
                            prev_page_prot_record: None,
                            prev_value: rng.gen::<u32>() as u64,
                            timestamp: step_clk,
                            value: rng.gen::<u32>() as u64,
                        },
                    }
                })
                .collect();
            let event = ShaExtendEvent {
                clk,
                w_ptr,
                memory_records,
                page_prot_records: Default::default(),
                local_mem_access: Vec::new(),
                local_page_prot_access: Vec::new(),
            };
            let syscall_event = SyscallEvent {
                pc: 4,
                next_pc: 8,
                clk,
                should_send: true,
                syscall_code: SyscallCode::SHA_EXTEND,
                syscall_id: SyscallCode::SHA_EXTEND.syscall_id(),
                arg1: w_ptr,
                arg2: 0,
                exit_code: 0,
                sig_return_pc_record: None,
                trap_result: None,
                trap_error: None,
            };
            record.precompile_events.add_event(
                SyscallCode::SHA_EXTEND,
                syscall_event,
                PrecompileEvent::ShaExtend(event),
            );
        }
        record
    }

    /// Columns from the recorded op-DAG must equal the host trace for every one of
    /// the 48 rows per event, on BOTH the SSA and the register-allocated
    /// slot-resolved interpreters (ShaExtend is a wide gadget → slot kernel path).
    #[test]
    fn sha_extend_columns_match_host() {
        let shard = synth_shard(4, 0x5AE1);
        let chip = ShaExtendChip;
        let trace = MachineAir::<F>::generate_trace(&chip, &shard, &mut ExecutionRecord::default());
        let width = NUM_SHA_EXTEND_COLS;

        let (program, col_wires) = super::record_sha_extend_program();
        let (slot, max_slots) = program.allocate_slots(&col_wires);
        println!(
            "ShaExtend: num_wires={} max_slots={max_slots} n_cols={}",
            program.num_wires(),
            col_wires.len()
        );
        assert!(
            (max_slots as usize) <= crate::riscv::WITGEN_MAX_WIRES,
            "ShaExtend needs {max_slots} slots > 256 kernel cap — needs tiering"
        );
        let ops_c = program.to_c();
        let ops_slots = program.to_c_slots(&slot);
        let ni = super::NUM_SHA_EXTEND_INPUTS;
        let input_slots = &slot[..ni];
        let col_slots: Vec<u32> = col_wires.iter().map(|&w| slot[w as usize]).collect();
        let events = super::collect_events(&shard);
        let inputs = super::pack_sha_extend_inputs(&events);
        let n_rows = events.len() * 48;
        for row in 0..n_rows {
            let row_in = &inputs[row * ni..(row + 1) * ni];
            let cols: Vec<F> = interpret_c_columns(&ops_c, ni as u32, row_in, &col_wires);
            assert_eq!(
                &trace.values[row * width..(row + 1) * width],
                &cols[..],
                "column mismatch at row {row}"
            );
            let flat: Vec<F> = interpret_c_slots_columns(
                &ops_slots, ni as u32, row_in, input_slots, &col_slots, max_slots,
            );
            assert_eq!(cols, flat, "slot-flat column mismatch at row {row}");
        }
    }

    /// Byte-lookup histogram vs `generate_dependencies` (the iter-041 trap): the
    /// rotate/shift bit-range checks, XOR byte lookups, Add4 carries, memory
    /// timestamps, and the per-step LTU must all match.
    #[test]
    fn sha_extend_lookups_match_generate_dependencies() {
        let shard = synth_shard(4, 0x5AE2);
        let chip = ShaExtendChip;

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

        let (program, _col_wires) = super::record_sha_extend_program();
        let ops_c = program.to_c();
        let events = super::collect_events(&shard);
        let inputs = super::pack_sha_extend_inputs(&events);
        let n_rows = events.len() * 48;
        let mut range_hist = vec![0u32; RANGE_HIST_ROWS];
        let mut byte_hist = vec![0u32; BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS];
        interpret_c_lookups(
            &ops_c,
            program.num_inputs,
            &inputs,
            n_rows,
            &mut range_hist,
            &mut byte_hist,
        );
        assert_eq!(range_hist, ref_range, "range histogram mismatch");
        assert_eq!(byte_hist, ref_byte, "byte histogram mismatch");
    }
}
