//! Device main-trace + dependency generation for the SUPERVISOR-mode
//! `SyscallInstrs` chip — the ECALL instruction table (RTypeReader adapter +
//! CPUState + five syscall-id IsZero discriminators + COMMIT index bitmap /
//! public-values digest + the HALT / COMMIT_DEFERRED_PROOFS SP1Field-word range
//! checks). One row per `syscall_event`; padding rows are all-zero.
//!
//! Dependencies are byte/range lookups only (the chip uses the DEFAULT
//! `generate_dependencies`, which re-runs `generate_trace`; unlike the
//! SyscallCore/SyscallPrecompile TABLES it emits no `GlobalInteractionEvent`s),
//! so the fused device path is available like the ALU chips.

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_tensor::Tensor;
use sp1_core_executor::{events::SyscallEvent, RTypeRecord};
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    syscall::instructions::{
        columns::{SyscallInstrColumns, NUM_SYSCALL_INSTR_COLS_SUPERVISOR},
        SyscallInstrsChip,
    },
    SupervisorMode,
};
use sp1_gpu_cudart::{DeviceBuffer, DeviceMle, TaskScope};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `SyscallInstrs` row (see
/// [`SyscallInstrColumns::witgen`]).
const NUM_SYSCALL_INSTR_INPUTS: usize = 19;

pub(crate) fn pack_syscall_instr_inputs(events: &[(SyscallEvent, RTypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_SYSCALL_INSTR_INPUTS];
    inputs.par_chunks_mut(NUM_SYSCALL_INSTR_INPUTS).zip(events.par_iter()).for_each(
        |(slot, (e, r))| {
            let (a, b, c) = (r.a, r.b, r.c);
            slot.copy_from_slice(&[
                e.clk,
                e.pc,
                r.op_a as u64,
                a.previous_record().value,
                a.previous_record().timestamp,
                a.current_record().timestamp,
                a.current_record().value,
                r.op_b,
                b.previous_record().value,
                b.previous_record().timestamp,
                b.current_record().timestamp,
                b.current_record().value,
                r.op_c,
                c.previous_record().value,
                c.previous_record().timestamp,
                c.current_record().timestamp,
                c.current_record().value,
                e.arg1,
                e.arg2,
            ]);
        },
    );
    inputs
}

fn record_syscall_instr_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_SYSCALL_INSTR_INPUTS as u32);
    let mut cols_w = SyscallInstrColumns::<WireId, SupervisorMode>::default();
    let w = |i: u32| RecordingWitnessBuilder::input(i);
    SyscallInstrColumns::<WireId, SupervisorMode>::witgen(
        &mut rec, &mut cols_w, w(0), w(1), w(2), w(3), w(4), w(5), w(6), w(7), w(8), w(9), w(10),
        w(11), w(12), w(13), w(14), w(15), w(16), w(17), w(18),
    );
    let program = rec.finish();
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    // 277 SSA wires exceed the SSA kernel's cap, but register allocation bounds the
    // per-thread footprint by max-live slots — SyscallInstrs uses the slot kernels
    // (like Mul), so assert on the allocated footprint, not raw wires.
    let (_, max_slots) = program.allocate_slots(&col_wires);
    assert!(
        max_slots as usize <= super::WITGEN_MAX_WIRES,
        "SyscallInstrs gadget needs {max_slots} slots > kernel capacity {}",
        super::WITGEN_MAX_WIRES
    );
    (program, col_wires)
}

impl CudaTracegenAir<F> for SyscallInstrsChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_syscall_instr_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_SYSCALL_INSTR_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.syscall_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        let inputs = pack_syscall_instr_inputs(&events[..n_events]);

        // Zero padding; slot kernel path (register-allocated).
        let trace = Tensor::<F, TaskScope>::zeros_in([n_cols, height], scope.clone());
        super::generate_columns_slots_into(
            &program, &col_wires, &inputs, n_events, height, trace, scope,
        )
        .await
    }

    /// Fused device path — the one the PROVER calls (iter-067 lesson: without this
    /// override the enum dispatch hits the trait-default `unimplemented!()`).
    async fn generate_trace_device_with_lookups(
        &self,
        input: &Self::Record,
        inputs: Vec<u64>,
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_syscall_instr_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_SYSCALL_INSTR_COLS_SUPERVISOR);
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let n_events = if height == 0 { 0 } else { inputs.len() / program.num_inputs as usize };
        super::generate_trace_and_lookups_slots(
            &program, &col_wires, n_cols, &inputs, n_events, height, hist, scope,
        )
        .await
    }

    fn supports_device_dependencies(&self) -> bool {
        // Byte/range lookups only (default `generate_dependencies`); no
        // `GlobalInteractionEvent`s (those live in the SyscallCore TABLE chip).
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
        let events = &input.syscall_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }

        let (program, col_wires) = record_syscall_instr_program();
        let inputs = pack_syscall_instr_inputs(&events[..n_events]);
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
        MemoryReadRecord, MemoryRecordEnum, MemoryWriteRecord, SyscallEvent,
    };
    use sp1_core_executor::{ByteOpcode, ExecutionRecord, RTypeRecord, SyscallCode};
    use sp1_core_machine::air::{
        interpret_c_columns, interpret_c_lookups, interpret_c_slots_columns,
        interpret_c_slots_streaming_columns, BYTE_HIST_ROWS, RANGE_HIST_ROWS,
    };
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    use sp1_core_machine::syscall::instructions::{
        columns::NUM_SYSCALL_INSTR_COLS_SUPERVISOR, SyscallInstrsChip,
    };
    use sp1_core_machine::SupervisorMode;
    use sp1_hypercube::air::MachineAir;

    use crate::F;

    fn read(rng: &mut StdRng, value: u64) -> MemoryRecordEnum {
        let prev_timestamp = rng.gen::<u32>() as u64;
        let timestamp = prev_timestamp + 1 + (rng.gen::<u32>() as u64);
        MemoryRecordEnum::Read(MemoryReadRecord {
            value,
            timestamp,
            prev_timestamp,
            prev_page_prot_record: None,
        })
    }

    /// Synthesize syscall instruction events over the interesting codes: HALT
    /// (op_b field range check + HALT_PC next_pc), COMMIT (index bitmap + digest
    /// bytes + guarded u8 range checks), COMMIT_DEFERRED_PROOFS (op_c field range
    /// check + bitmap), ENTER_UNCONSTRAINED, HINT_LEN, WRITE, SHA_EXTEND (generic).
    fn synth_events(n: usize, seed: u64) -> Vec<(SyscallEvent, RTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(seed);
        let codes = [
            SyscallCode::HALT,
            SyscallCode::WRITE,
            SyscallCode::COMMIT,
            SyscallCode::SHA_EXTEND,
            SyscallCode::COMMIT_DEFERRED_PROOFS,
            SyscallCode::ENTER_UNCONSTRAINED,
            SyscallCode::HINT_LEN,
        ];
        (0..n)
            .map(|i| {
                let code = codes[i % codes.len()];
                // op_a's PREVIOUS value carries the syscall id in its low byte
                // (the t0 register); mix high bytes to exercise the byte split.
                let a_prev = (rng.gen::<u64>() & 0xFFFF_FFFF_FF00) | code.syscall_id() as u64;
                let a_prev_ts = rng.gen::<u32>() as u64;
                let a = MemoryRecordEnum::Write(MemoryWriteRecord {
                    value: rng.gen::<u32>() as u64,
                    timestamp: a_prev_ts + 1 + (rng.gen::<u32>() as u64),
                    prev_value: a_prev,
                    prev_timestamp: a_prev_ts,
                    prev_page_prot_record: None,
                });
                // COMMIT/COMMIT_DEFERRED_PROOFS read the digest word index from
                // op_b (must be < 8) and the digest word from op_c.
                let is_commit_kind = matches!(
                    code,
                    SyscallCode::COMMIT | SyscallCode::COMMIT_DEFERRED_PROOFS
                );
                let b_val =
                    if is_commit_kind { (i as u64) % 8 } else { rng.gen::<u64>() };
                let c_val = rng.gen::<u32>() as u64;
                let event = SyscallEvent {
                    pc: (i as u64) * 4 + 4,
                    next_pc: (i as u64) * 4 + 8,
                    clk: (i as u64) * 8 + 9, // clk ≡ 1 (mod 8) for CPUState
                    should_send: code.should_send() == 1,
                    syscall_code: code,
                    syscall_id: code.syscall_id(),
                    arg1: b_val,
                    arg2: c_val,
                    exit_code: 0,
                    sig_return_pc_record: None,
                    trap_result: None,
                    trap_error: None,
                };
                let record = RTypeRecord {
                    op_a: 5, // t0
                    a,
                    op_b: rng.gen_range(1..32),
                    b: read(&mut rng, b_val),
                    op_c: rng.gen_range(1..32),
                    c: read(&mut rng, c_val),
                    is_untrusted: false,
                };
                (event, record)
            })
            .collect()
    }

    /// Columns from the recorded op-DAG must equal the HOST trace bit-for-bit on
    /// the SSA, pinned-slot, AND streaming interpreters (the kernels' CPU models).
    /// Also prints the slot-footprint decision numbers.
    #[test]
    fn syscall_instrs_columns_match_host() {
        let events = synth_events(140, 0x5CA11);
        let shard = ExecutionRecord { syscall_events: events.clone(), ..Default::default() };
        let chip = SyscallInstrsChip::<SupervisorMode>::default();
        let trace =
            MachineAir::<F>::generate_trace(&chip, &shard, &mut ExecutionRecord::default());
        let width = NUM_SYSCALL_INSTR_COLS_SUPERVISOR;

        let (program, col_wires) = super::record_syscall_instr_program();
        assert_eq!(col_wires.len(), width);
        let (slot, max_slots) = program.allocate_slots(&col_wires);
        let (s_slot, s_max, epi) = program.allocate_slots_streaming(&col_wires);
        println!(
            "SyscallInstrs: num_wires={} n_cols={} pinned_max_slots={max_slots} \
             streaming_max_slots={s_max} epilogue={}",
            program.num_wires(),
            col_wires.len(),
            epi.len(),
        );

        let ni = super::NUM_SYSCALL_INSTR_INPUTS;
        let ops_c = program.to_c();
        let ops_slots = program.to_c_slots(&slot);
        let input_slots = &slot[..ni];
        let col_slots: Vec<u32> = col_wires.iter().map(|&w| slot[w as usize]).collect();
        let (ops_stream, input_cols) = program.to_c_slots_streaming(&s_slot, &col_wires);
        let s_input_slots = &s_slot[..ni];
        let epi_slots: Vec<(u32, u32)> =
            epi.iter().map(|&(w, c)| (s_slot[w as usize], c)).collect();

        let inputs = super::pack_syscall_instr_inputs(&events);
        for row in 0..events.len() {
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
            let streamed: Vec<F> = interpret_c_slots_streaming_columns(
                &ops_stream, ni as u32, row_in, s_input_slots, &input_cols, &epi_slots, width,
                s_max,
            );
            assert_eq!(cols, streamed, "streaming column mismatch at row {row}");
        }
    }

    /// Byte/range-lookup histogram vs `generate_dependencies` (the iter-041 trap):
    /// the op_a u16 range checks, the low-byte u8 pairs, the COMMIT-guarded digest
    /// u8 pairs, the HALT/COMMIT_DEFERRED_PROOFS compare range checks, and the
    /// CPUState/RTypeReader lookups must all match.
    #[test]
    fn syscall_instrs_lookups_match_generate_dependencies() {
        let events = synth_events(210, 0x5CA12);
        let shard = ExecutionRecord { syscall_events: events.clone(), ..Default::default() };
        let chip = SyscallInstrsChip::<SupervisorMode>::default();

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

        let (program, _col_wires) = super::record_syscall_instr_program();
        let ops_c = program.to_c();
        let inputs = super::pack_syscall_instr_inputs(&events);
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
}
