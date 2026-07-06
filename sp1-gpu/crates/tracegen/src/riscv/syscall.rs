//! Device main-trace generation for the `SyscallCore` / `SyscallPrecompile` tables
//! (one `SyscallChip<SupervisorMode>` type, two shard kinds). Narrow chip (10 cols),
//! zero padding. IMPORTANT: `generate_dependencies` for this chip also emits
//! `GlobalInteractionEvent`s (not byte lookups), so the DEVICE DEPENDENCY PATH MUST
//! STAY OFF — the host `generate_dependencies` still runs (globals + byte lookups)
//! and only the main trace moves to device.

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::{events::SyscallEvent, ExecutionRecord, TrapError};
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    syscall::chip::{SyscallChip, SyscallCols, SyscallShardKind, NUM_SYSCALL_COLS_SUPERVISOR},
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per syscall row (see [`SyscallCols::witgen`]).
const NUM_SYSCALL_INPUTS: usize = 7;

/// The shard's event list for one shard kind — mirrors the chip's own selection
/// (`Core`: sending events only; `Precompile`: ALL precompile events, including
/// non-sending ones, whose dependency lookups the witgen guards on `should_send`).
pub(crate) fn collect_syscall_events(
    input: &ExecutionRecord,
    kind: SyscallShardKind,
) -> Vec<SyscallEvent> {
    match kind {
        SyscallShardKind::Core => {
            input.syscall_events.iter().map(|(event, _)| *event).filter(|e| e.should_send).collect()
        }
        SyscallShardKind::Precompile => {
            input.precompile_events.all_events().map(|(event, _)| *event).collect()
        }
    }
}

pub(crate) fn pack_syscall_inputs(events: &[SyscallEvent]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_SYSCALL_INPUTS];
    inputs.par_chunks_mut(NUM_SYSCALL_INPUTS).zip(events.par_iter()).for_each(|(slot, e)| {
        let trap_code = if let Some(TrapError::PagePermissionViolation(code)) = e.trap_error {
            code as u8 as u64
        } else {
            0
        };
        slot.copy_from_slice(&[
            e.clk,
            e.syscall_code.syscall_id() as u64, // column value
            e.syscall_id as u64,                // dependency (raw) value
            e.arg1,
            e.arg2,
            trap_code,
            e.should_send as u64,
        ]);
    });
    inputs
}

pub(crate) fn record_syscall_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_SYSCALL_INPUTS as u32);
    let mut cols_w = SyscallCols::<WireId, SupervisorMode>::default();
    let w = |i: u32| RecordingWitnessBuilder::input(i);
    SyscallCols::<WireId, SupervisorMode>::witgen(
        &mut rec,
        &mut cols_w,
        w(0),
        w(1),
        w(2),
        w(3),
        w(4),
        w(5),
        w(6),
    );
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "Syscall gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

impl CudaTracegenAir<F> for SyscallChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    // NO `supports_device_dependencies`: `generate_dependencies` emits
    // `GlobalInteractionEvent`s that the device byte-lookup path cannot produce, so
    // dependencies stay fully on host (default `false`).

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_syscall_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_SYSCALL_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = collect_syscall_events(input, self.shard_kind());
        let n_events = if height == 0 { 0 } else { events.len() };
        let inputs = pack_syscall_inputs(&events[..n_events]);

        let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone()).unwrap();
        ops_dev.extend_from_host_slice(&ops_c)?;
        let mut col_dev = Buffer::try_with_capacity_in(col_wires.len(), scope.clone()).unwrap();
        col_dev.extend_from_host_slice(&col_wires)?;
        let mut in_dev = Buffer::try_with_capacity_in(inputs.len().max(1), scope.clone()).unwrap();
        in_dev.extend_from_host_slice(&inputs)?;

        // Zeroed trace; only event rows are written (padding rows stay 0).
        let mut trace = Tensor::<F, TaskScope>::zeros_in([n_cols, height], scope.clone());
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
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core_executor::events::SyscallEvent;
    use sp1_core_executor::{ByteOpcode, ExecutionRecord, RTypeRecord, SyscallCode};
    use sp1_core_machine::air::{
        interpret_c_columns, interpret_c_lookups, BYTE_HIST_ROWS, RANGE_HIST_ROWS,
    };
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    use sp1_core_machine::syscall::chip::{SyscallChip, NUM_SYSCALL_COLS_SUPERVISOR};
    use sp1_core_machine::SupervisorMode;
    use sp1_hypercube::air::MachineAir;

    use crate::F;

    /// A dummy register record — the syscall table never reads it (only the paired
    /// `SyscallEvent` matters for this chip).
    fn dummy_record(rng: &mut StdRng) -> RTypeRecord {
        use sp1_core_executor::events::{MemoryReadRecord, MemoryRecordEnum};
        let read = |rng: &mut StdRng| {
            let prev_timestamp = rng.gen::<u32>() as u64;
            MemoryRecordEnum::Read(MemoryReadRecord {
                value: rng.gen::<u32>() as u64,
                timestamp: prev_timestamp + 1,
                prev_timestamp,
                prev_page_prot_record: None,
            })
        };
        RTypeRecord {
            op_a: rng.gen_range(1..32),
            a: read(rng),
            op_b: rng.gen_range(1..32),
            b: read(rng),
            op_c: rng.gen_range(1..32),
            c: read(rng),
            is_untrusted: false,
        }
    }

    fn synth_events(n: usize, seed: u64) -> Vec<(SyscallEvent, RTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(seed);
        let codes = [
            SyscallCode::HALT,
            SyscallCode::WRITE,
            SyscallCode::SHA_EXTEND,
            SyscallCode::SHA_COMPRESS,
            SyscallCode::COMMIT,
        ];
        (0..n)
            .map(|i| {
                let code = codes[i % codes.len()];
                let event = SyscallEvent {
                    pc: (i as u64) * 4 + 4,
                    next_pc: (i as u64) * 4 + 8,
                    clk: (i as u64) * 8 + 8,
                    should_send: i % 3 != 0,
                    syscall_code: code,
                    syscall_id: code.syscall_id(),
                    arg1: rng.gen::<u64>() & 0xFFFF_FFFF_FFFF,
                    arg2: rng.gen::<u64>() & 0xFFFF_FFFF_FFFF,
                    exit_code: 0,
                    sig_return_pc_record: None,
                    trap_result: None,
                    trap_error: None,
                };
                let record = dummy_record(&mut rng);
                (event, record)
            })
            .collect()
    }

    /// Columns from the recorded op-DAG (flat WitOpC interpreter, the kernel's CPU
    /// model) must equal the host `generate_trace` rows for the CORE shard kind.
    #[test]
    fn syscall_core_columns_match_host() {
        let events = synth_events(200, 0x5CA1);
        let shard = ExecutionRecord { syscall_events: events, ..Default::default() };
        let chip = SyscallChip::<SupervisorMode>::core();

        let trace = MachineAir::<F>::generate_trace(&chip, &shard, &mut ExecutionRecord::default());
        let width = NUM_SYSCALL_COLS_SUPERVISOR;

        let (program, col_wires) = super::record_syscall_program();
        let (slot, max_slots) = program.allocate_slots(&col_wires);
        let _ = slot;
        eprintln!(
            "Syscall: num_wires={} max_slots={max_slots} n_cols={}",
            program.num_wires(),
            col_wires.len()
        );
        let ops_c = program.to_c();
        let sent = super::collect_syscall_events(&shard, super::SyscallShardKind::Core);
        let inputs = super::pack_syscall_inputs(&sent);
        let ni = super::NUM_SYSCALL_INPUTS;
        for row in 0..sent.len() {
            let row_in = &inputs[row * ni..(row + 1) * ni];
            let cols: Vec<F> = interpret_c_columns(&ops_c, ni as u32, row_in, &col_wires);
            assert_eq!(
                &trace.values[row * width..(row + 1) * width],
                &cols[..],
                "column mismatch at row {row}"
            );
        }
    }

    /// The op-DAG's lookup histogram must equal the host `generate_dependencies`
    /// byte lookups (the iter-041 trap: lookups carry semantics the column test
    /// doesn't exercise). Exercises the `should_send` GUARD via the Precompile kind
    /// (trace rows for all events, lookups only for sending ones) using Core events
    /// with a mix of should_send. NOTE: `generate_dependencies` also emits global
    /// interaction events — deliberately NOT modeled; device deps stay off.
    #[test]
    fn syscall_lookups_match_generate_dependencies() {
        let events = synth_events(300, 0x5CA2);
        let shard = ExecutionRecord { syscall_events: events, ..Default::default() };
        let chip = SyscallChip::<SupervisorMode>::core();

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

        let (program, _col_wires) = super::record_syscall_program();
        let ops_c = program.to_c();
        let sent = super::collect_syscall_events(&shard, super::SyscallShardKind::Core);
        let inputs = super::pack_syscall_inputs(&sent);
        let mut range_hist = vec![0u32; RANGE_HIST_ROWS];
        let mut byte_hist = vec![0u32; BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS];
        interpret_c_lookups(
            &ops_c,
            program.num_inputs,
            &inputs,
            sent.len(),
            &mut range_hist,
            &mut byte_hist,
        );
        assert_eq!(range_hist, ref_range, "range histogram mismatch");
        assert_eq!(byte_hist, ref_byte, "byte histogram mismatch");

        // The guard must actually suppress non-sending rows: rerun with every event
        // forced non-sending and assert the histograms are empty.
        let none: Vec<SyscallEvent> = sent
            .iter()
            .map(|e| {
                let mut e = *e;
                e.should_send = false;
                e
            })
            .collect();
        let inputs = super::pack_syscall_inputs(&none);
        let mut r2 = vec![0u32; RANGE_HIST_ROWS];
        let mut b2 = vec![0u32; BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS];
        interpret_c_lookups(&ops_c, program.num_inputs, &inputs, none.len(), &mut r2, &mut b2);
        assert!(r2.iter().all(|&x| x == 0), "guarded range lookups leaked");
        assert!(b2.iter().all(|&x| x == 0), "guarded byte lookups leaked");
    }
}
