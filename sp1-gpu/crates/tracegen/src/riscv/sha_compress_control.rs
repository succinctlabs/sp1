//! Device main-trace + dependency generation for the SUPERVISOR-mode
//! `ShaCompressControl` chip — the controller that receives the SHA_COMPRESS
//! syscall: clk split + `SyscallAddrOperation`s on `w_ptr` (512) and `h_ptr` (64)
//! + the two slice-end `AddrAddOperation`s + the 8 initial/final SHA state
//! half-words. One row per SHA_COMPRESS event; padding rows are all-zero.
//! NARROW chip (~53 cols) — plain fused path.
//!
//! `final_state[i]` is the u32 wrapping difference `write.value - h[i]` (the
//! compression's additive delta); computed on device as a u64 `WrappingSub` whose
//! low 32 bits equal the u32 wrap (both operands < 2^32).
//!
//! Dependencies are byte/range lookups only, so the fused device path is
//! available.

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_tensor::Tensor;
use sp1_core_executor::{events::PrecompileEvent, ExecutionRecord, SyscallCode};
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId, WitProgram, WitnessBuilder},
    operations::{AddrAddOperation, SyscallAddrOperation},
    syscall::precompiles::sha256::{
        num_sha_compress_control_cols_supervisor, ShaCompressControlChip,
        ShaCompressControlCols,
    },
    SupervisorMode,
};
use sp1_gpu_cudart::{DeviceBuffer, DeviceMle, TaskScope};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `ShaCompressControl` row: clk + w_ptr + h_ptr +
/// 8 x h[i] + 8 x h_write_records[i].value.
const NUM_SHA_COMPRESS_CONTROL_INPUTS: usize = 3 + 8 + 8;

const IN_CLK: u32 = 0;
const IN_W_PTR: u32 = 1;
const IN_H_PTR: u32 = 2;
const IN_H: u32 = 3; // ..11
const IN_VALUE: u32 = 11; // ..19

pub(crate) fn pack_sha_compress_control_inputs(input: &ExecutionRecord) -> Vec<u64> {
    let events = input.get_precompile_events(SyscallCode::SHA_COMPRESS);
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_SHA_COMPRESS_CONTROL_INPUTS];
    inputs.par_chunks_mut(NUM_SHA_COMPRESS_CONTROL_INPUTS).zip(events.par_iter()).for_each(
        |(slot, (_, event))| {
            let event = if let PrecompileEvent::ShaCompress(event) = event {
                event
            } else {
                unreachable!()
            };
            slot[IN_CLK as usize] = event.clk;
            slot[IN_W_PTR as usize] = event.w_ptr;
            slot[IN_H_PTR as usize] = event.h_ptr;
            for i in 0..8 {
                slot[IN_H as usize + i] = event.h[i] as u64;
                slot[IN_VALUE as usize + i] = event.h_write_records[i].value;
            }
        },
    );
    inputs
}

fn record_sha_compress_control_program() -> (WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_SHA_COMPRESS_CONTROL_INPUTS as u32);
    // SAFETY: #[repr(C)] over Copy WireId; SupervisorMode's SliceProtCols are
    // empty; every field is assigned below (column tests would catch a miss).
    let mut cols: ShaCompressControlCols<WireId, SupervisorMode> = unsafe { core::mem::zeroed() };
    let w = RecordingWitnessBuilder::input;

    let clk = w(IN_CLK);
    let w_ptr = w(IN_W_PTR);
    let h_ptr = w(IN_H_PTR);
    let clk_high = rec.bits(clk, 24, 32);
    cols.clk_high = rec.nat_to_field(clk_high);
    let clk_low = rec.bits(clk, 0, 24);
    cols.clk_low = rec.nat_to_field(clk_low);
    // `w_ptr` has 64 words (512 bytes); `h_ptr` has 8 words (64 bytes).
    SyscallAddrOperation::<WireId>::witgen(&mut rec, &mut cols.w_ptr, w_ptr, 512);
    SyscallAddrOperation::<WireId>::witgen(&mut rec, &mut cols.h_ptr, h_ptr, 64);
    let off_w = rec.const_nat(63 * 8);
    AddrAddOperation::<WireId>::witgen(&mut rec, &mut cols.w_slice_end, w_ptr, off_w);
    let off_h = rec.const_nat(7 * 8);
    AddrAddOperation::<WireId>::witgen(&mut rec, &mut cols.h_slice_end, h_ptr, off_h);
    let one = rec.const_nat(1);
    cols.is_real = rec.nat_to_field(one);

    for i in 0..8 {
        let h = w(IN_H + i as u32);
        let value = w(IN_VALUE + i as u32);
        // initial_state[i] = u32_to_half_word(h[i]).
        let h_lo = rec.bits(h, 0, 16);
        let h_hi = rec.bits(h, 16, 16);
        cols.initial_state[i] = [rec.nat_to_field(h_lo), rec.nat_to_field(h_hi)];
        // final_state[i] = u32_to_half_word((value as u32).wrapping_sub(h[i])):
        // u64 WrappingSub's low 32 bits equal the u32 wrap (both < 2^32).
        let v32 = rec.bits(value, 0, 32);
        let diff = rec.wrapping_sub(v32, h);
        let d_lo = rec.bits(diff, 0, 16);
        let d_hi = rec.bits(diff, 16, 16);
        cols.final_state[i] = [rec.nat_to_field(d_lo), rec.nat_to_field(d_hi)];
    }

    let col_wires: Vec<u32> = columns_as_wires(&cols).iter().map(|cw| cw.0).collect();
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "ShaCompressControl gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    (program, col_wires)
}

impl CudaTracegenAir<F> for ShaCompressControlChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_sha_compress_control_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, num_sha_compress_control_cols_supervisor());
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let inputs = pack_sha_compress_control_inputs(input);
        let n_events =
            if height == 0 { 0 } else { inputs.len() / NUM_SHA_COMPRESS_CONTROL_INPUTS };
        let trace = Tensor::<F, TaskScope>::zeros_in([n_cols, height], scope.clone());
        super::generate_columns_slots_into(
            &program, &col_wires, &inputs, n_events, height, trace, scope,
        )
        .await
    }

    /// Fused device path — the one the PROVER calls (iter-067 lesson).
    async fn generate_trace_device_with_lookups(
        &self,
        input: &Self::Record,
        inputs: Vec<u64>,
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_sha_compress_control_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, num_sha_compress_control_cols_supervisor());
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let n_events = if height == 0 { 0 } else { inputs.len() / program.num_inputs as usize };
        super::generate_trace_and_lookups_slots(
            &program, &col_wires, n_cols, &inputs, n_events, height, hist, scope,
        )
        .await
    }

    fn supports_device_dependencies(&self) -> bool {
        true // byte/range lookups only
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
        let inputs = pack_sha_compress_control_inputs(input);
        let n_events =
            if height == 0 { 0 } else { inputs.len() / NUM_SHA_COMPRESS_CONTROL_INPUTS };
        if n_events == 0 {
            return Ok(());
        }
        let (program, col_wires) = record_sha_compress_control_program();
        super::accumulate_lookups_slots(
            &program, &col_wires, &inputs, n_events, range_dev, byte_dev, scope,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core_executor::events::{
        MemoryReadRecord, MemoryWriteRecord, PrecompileEvent, ShaCompressEvent, SyscallEvent,
    };
    use sp1_core_executor::{ByteOpcode, ExecutionRecord, SyscallCode};
    use sp1_core_machine::air::{
        interpret_c_columns, interpret_c_lookups, interpret_c_slots_columns, BYTE_HIST_ROWS,
        RANGE_HIST_ROWS,
    };
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    use sp1_core_machine::syscall::precompiles::sha256::{
        num_sha_compress_control_cols_supervisor, ShaCompressControlChip,
    };
    use sp1_core_machine::SupervisorMode;
    use sp1_hypercube::air::MachineAir;

    use crate::F;

    fn synth_shard(n: usize, seed: u64) -> ExecutionRecord {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut record = ExecutionRecord::default();
        for e in 0..n {
            let clk = (e as u64 + 1) * 1_000_000 + 1;
            let w_ptr = ((rng.gen::<u64>() & 0x7F_FFFF_FFFF) | 0x1_0000) & !7;
            let h_ptr = ((rng.gen::<u64>() & 0x7F_FFFF_FFFF) | 0x1_0000) & !7;
            let h: [u32; 8] = core::array::from_fn(|_| rng.gen::<u32>());
            let h_read_records: [MemoryReadRecord; 8] = core::array::from_fn(|i| {
                MemoryReadRecord {
                    value: h[i] as u64,
                    timestamp: clk,
                    prev_timestamp: clk - 1,
                    prev_page_prot_record: None,
                }
            });
            let h_write_records: [MemoryWriteRecord; 8] = core::array::from_fn(|i| {
                MemoryWriteRecord {
                    value: rng.gen::<u32>() as u64,
                    timestamp: clk + 2,
                    prev_value: h[i] as u64,
                    prev_timestamp: clk,
                    prev_page_prot_record: None,
                }
            });
            let event = ShaCompressEvent {
                clk,
                w_ptr,
                h_ptr,
                w: (0..64).map(|_| rng.gen::<u32>()).collect(),
                h,
                h_read_records,
                w_i_read_records: Vec::new(),
                h_write_records,
                local_mem_access: Vec::new(),
                page_prot_access: Default::default(),
                local_page_prot_access: Vec::new(),
            };
            let syscall_event = SyscallEvent {
                pc: 4,
                next_pc: 8,
                clk,
                should_send: true,
                syscall_code: SyscallCode::SHA_COMPRESS,
                syscall_id: SyscallCode::SHA_COMPRESS.syscall_id(),
                arg1: w_ptr,
                arg2: h_ptr,
                exit_code: 0,
                sig_return_pc_record: None,
                trap_result: None,
                trap_error: None,
            };
            record.precompile_events.add_event(
                SyscallCode::SHA_COMPRESS,
                syscall_event,
                PrecompileEvent::ShaCompress(event),
            );
        }
        record
    }

    /// Columns from the recorded op-DAG must equal the HOST trace bit-for-bit on
    /// the SSA and pinned-slot interpreters — exercises the u32 wrapping
    /// final-state delta (value < h[i] on random inputs half the time).
    #[test]
    fn sha_compress_control_columns_match_host() {
        let shard = synth_shard(45, 0x5CC01);
        let chip = ShaCompressControlChip::<SupervisorMode>::new();
        let trace =
            MachineAir::<F>::generate_trace(&chip, &shard, &mut ExecutionRecord::default());
        let width = num_sha_compress_control_cols_supervisor();

        let (program, col_wires) = super::record_sha_compress_control_program();
        assert_eq!(col_wires.len(), width);
        let (slot, max_slots) = program.allocate_slots(&col_wires);
        let (_, s_max, epi) = program.allocate_slots_streaming(&col_wires);
        println!(
            "ShaCompressControl: num_wires={} n_cols={} pinned_max_slots={max_slots} \
             streaming_max_slots={s_max} epilogue={}",
            program.num_wires(),
            col_wires.len(),
            epi.len(),
        );

        let ni = super::NUM_SHA_COMPRESS_CONTROL_INPUTS;
        let ops_c = program.to_c();
        let ops_slots = program.to_c_slots(&slot);
        let input_slots = &slot[..ni];
        let col_slots: Vec<u32> = col_wires.iter().map(|&w| slot[w as usize]).collect();
        let inputs = super::pack_sha_compress_control_inputs(&shard);
        let n_events = inputs.len() / ni;
        for row in 0..n_events {
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
            assert_eq!(cols, flat, "pinned-slot column mismatch at row {row}");
        }
    }

    /// Byte/range-lookup histogram vs `generate_dependencies` (the iter-041 trap).
    #[test]
    fn sha_compress_control_lookups_match_generate_dependencies() {
        let shard = synth_shard(60, 0x5CC02);
        let chip = ShaCompressControlChip::<SupervisorMode>::new();

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

        let (program, _col_wires) = super::record_sha_compress_control_program();
        let ops_c = program.to_c();
        let inputs = super::pack_sha_compress_control_inputs(&shard);
        let n_events = inputs.len() / super::NUM_SHA_COMPRESS_CONTROL_INPUTS;
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
        assert_eq!(range_hist, ref_range, "range histogram mismatch");
        assert_eq!(byte_hist, ref_byte, "byte histogram mismatch");
    }
}
