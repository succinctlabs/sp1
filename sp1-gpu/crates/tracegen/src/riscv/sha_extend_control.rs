//! Device main-trace + dependency generation for the SUPERVISOR-mode
//! `ShaExtendControl` chip — the controller that receives the SHA_EXTEND syscall:
//! clk split + `SyscallAddrOperation` on `w_ptr` (512 bytes) + the 16th/17th/64th
//! word `AddrAddOperation`s + `is_real`. One row per SHA_EXTEND event; padding
//! rows are all-zero. NARROW chip (18 cols) — plain fused path.
//!
//! Dependencies are byte/range lookups only (default `generate_dependencies`
//! re-runs the trace; the syscall receive / SHA interactions are AIR-level), so
//! the fused device path is available.

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_tensor::Tensor;
use sp1_core_executor::{events::PrecompileEvent, ExecutionRecord, SyscallCode};
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId, WitProgram, WitnessBuilder},
    operations::{AddrAddOperation, SyscallAddrOperation},
    syscall::precompiles::sha256::{
        num_sha_extend_control_cols_supervisor, ShaExtendControlChip, ShaExtendControlCols,
    },
    SupervisorMode,
};
use sp1_gpu_cudart::{DeviceBuffer, DeviceMle, TaskScope};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `ShaExtendControl` row: clk + w_ptr.
const NUM_SHA_EXTEND_CONTROL_INPUTS: usize = 2;

pub(crate) fn pack_sha_extend_control_inputs(input: &ExecutionRecord) -> Vec<u64> {
    let events = input.get_precompile_events(SyscallCode::SHA_EXTEND);
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_SHA_EXTEND_CONTROL_INPUTS];
    inputs.par_chunks_mut(NUM_SHA_EXTEND_CONTROL_INPUTS).zip(events.par_iter()).for_each(
        |(slot, (_, event))| {
            let event =
                if let PrecompileEvent::ShaExtend(event) = event { event } else { unreachable!() };
            slot[0] = event.clk;
            slot[1] = event.w_ptr;
        },
    );
    inputs
}

fn record_sha_extend_control_program() -> (WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_SHA_EXTEND_CONTROL_INPUTS as u32);
    // SAFETY: #[repr(C)] over Copy WireId; SupervisorMode's SliceProtCols are
    // empty; every field is assigned below (column tests would catch a miss).
    let mut cols: ShaExtendControlCols<WireId, SupervisorMode> = unsafe { core::mem::zeroed() };
    let w = RecordingWitnessBuilder::input;

    let clk = w(0);
    let w_ptr = w(1);
    let clk_high = rec.bits(clk, 24, 32);
    cols.clk_high = rec.nat_to_field(clk_high);
    let clk_low = rec.bits(clk, 0, 24);
    cols.clk_low = rec.nat_to_field(clk_low);
    // The precompile accesses 64 words = 512 bytes.
    SyscallAddrOperation::<WireId>::witgen(&mut rec, &mut cols.w_ptr, w_ptr, 512);
    let off_16 = rec.const_nat(15 * 8);
    AddrAddOperation::<WireId>::witgen(&mut rec, &mut cols.w_16th_addr, w_ptr, off_16);
    let off_17 = rec.const_nat(16 * 8);
    AddrAddOperation::<WireId>::witgen(&mut rec, &mut cols.w_17th_addr, w_ptr, off_17);
    let off_64 = rec.const_nat(63 * 8);
    AddrAddOperation::<WireId>::witgen(&mut rec, &mut cols.w_64th_addr, w_ptr, off_64);
    let one = rec.const_nat(1);
    cols.is_real = rec.nat_to_field(one);

    let col_wires: Vec<u32> = columns_as_wires(&cols).iter().map(|cw| cw.0).collect();
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "ShaExtendControl gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    (program, col_wires)
}

impl CudaTracegenAir<F> for ShaExtendControlChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_sha_extend_control_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, num_sha_extend_control_cols_supervisor());
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let inputs = pack_sha_extend_control_inputs(input);
        let n_events = if height == 0 { 0 } else { inputs.len() / NUM_SHA_EXTEND_CONTROL_INPUTS };
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
        let (program, col_wires) = record_sha_extend_control_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, num_sha_extend_control_cols_supervisor());
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
        let inputs = pack_sha_extend_control_inputs(input);
        let n_events = if height == 0 { 0 } else { inputs.len() / NUM_SHA_EXTEND_CONTROL_INPUTS };
        if n_events == 0 {
            return Ok(());
        }
        let (program, col_wires) = record_sha_extend_control_program();
        super::accumulate_lookups_slots(
            &program, &col_wires, &inputs, n_events, range_dev, byte_dev, scope,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core_executor::events::{PrecompileEvent, ShaExtendEvent, SyscallEvent};
    use sp1_core_executor::{ByteOpcode, ExecutionRecord, SyscallCode};
    use sp1_core_machine::air::{
        interpret_c_columns, interpret_c_lookups, interpret_c_slots_columns, BYTE_HIST_ROWS,
        RANGE_HIST_ROWS,
    };
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    use sp1_core_machine::syscall::precompiles::sha256::{
        num_sha_extend_control_cols_supervisor, ShaExtendControlChip,
    };
    use sp1_core_machine::SupervisorMode;
    use sp1_hypercube::air::MachineAir;

    use crate::F;

    fn synth_shard(n: usize, seed: u64) -> ExecutionRecord {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut record = ExecutionRecord::default();
        for e in 0..n {
            let clk = (e as u64 + 1) * 1_000_000 + 1;
            // Valid syscall addr: >= 2^16, 8-aligned; exercise the u16::MAX top-limb
            // edge occasionally.
            let w_ptr = if e % 5 == 0 {
                (0xFFFF_FFFF_0000u64) | ((rng.gen::<u64>() & 0xFFF0) & !7)
            } else {
                ((rng.gen::<u64>() & 0x7F_FFFF_FFFF) | 0x1_0000) & !7
            };
            let event = ShaExtendEvent {
                clk,
                w_ptr,
                memory_records: Vec::new(),
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

    /// Columns from the recorded op-DAG must equal the HOST trace bit-for-bit on
    /// the SSA and pinned-slot interpreters.
    #[test]
    fn sha_extend_control_columns_match_host() {
        let shard = synth_shard(45, 0x5EC01);
        let chip = ShaExtendControlChip::<SupervisorMode>::new();
        let trace = MachineAir::<F>::generate_trace(&chip, &shard, &mut ExecutionRecord::default());
        let width = num_sha_extend_control_cols_supervisor();

        let (program, col_wires) = super::record_sha_extend_control_program();
        assert_eq!(col_wires.len(), width);
        let (slot, max_slots) = program.allocate_slots(&col_wires);
        let (_, s_max, epi) = program.allocate_slots_streaming(&col_wires);
        eprintln!(
            "ShaExtendControl: num_wires={} n_cols={} pinned_max_slots={max_slots} \
             streaming_max_slots={s_max} epilogue={}",
            program.num_wires(),
            col_wires.len(),
            epi.len(),
        );

        let ni = super::NUM_SHA_EXTEND_CONTROL_INPUTS;
        let ops_c = program.to_c();
        let ops_slots = program.to_c_slots(&slot);
        let input_slots = &slot[..ni];
        let col_slots: Vec<u32> = col_wires.iter().map(|&w| slot[w as usize]).collect();
        let inputs = super::pack_sha_extend_control_inputs(&shard);
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
                &ops_slots,
                ni as u32,
                row_in,
                input_slots,
                &col_slots,
                max_slots,
            );
            assert_eq!(cols, flat, "pinned-slot column mismatch at row {row}");
        }
    }

    /// Byte/range-lookup histogram vs `generate_dependencies` (the iter-041 trap).
    #[test]
    fn sha_extend_control_lookups_match_generate_dependencies() {
        let shard = synth_shard(60, 0x5EC02);
        let chip = ShaExtendControlChip::<SupervisorMode>::new();

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

        let (program, _col_wires) = super::record_sha_extend_control_program();
        let ops_c = program.to_c();
        let inputs = super::pack_sha_extend_control_inputs(&shard);
        let n_events = inputs.len() / super::NUM_SHA_EXTEND_CONTROL_INPUTS;
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
