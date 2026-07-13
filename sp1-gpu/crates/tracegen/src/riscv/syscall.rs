//! Device main-trace + byte-lookup generation for the `SyscallCore` /
//! `SyscallPrecompile` tables (one `SyscallChip<SupervisorMode>` type, two shard
//! kinds). Narrow chip (10 cols), zero padding. Host `generate_dependencies` ALSO
//! emits `GlobalInteractionEvent`s — those cannot be produced on device, so the
//! prover keeps them on host via `generate_global_dependencies` while the byte
//! lookups fuse into the main-trace kernel here (the witgen guards them on
//! `should_send`; `syscall_lookups_match_generate_dependencies` is the parity
//! proof).

use core::borrow::BorrowMut;

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::{events::SyscallEvent, ExecutionRecord, TrapError};
use sp1_core_machine::{
    air::{columns_as_wires, record_witgen_inputs, WireId},
    syscall::chip::{
        SyscallChip, SyscallCols, SyscallShardKind, SyscallWitgenInput,
        NUM_SYSCALL_COLS_SUPERVISOR, NUM_SYSCALL_WITGEN_INPUTS,
    },
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

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

/// Pack each event into one [`SyscallWitgenInput`] row.
pub(crate) fn pack_syscall_inputs(events: &[SyscallEvent]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_SYSCALL_WITGEN_INPUTS];
    inputs.par_chunks_mut(NUM_SYSCALL_WITGEN_INPUTS).zip(events.par_iter()).for_each(
        |(chunk, e)| {
            let slot: &mut SyscallWitgenInput<u64> = chunk.borrow_mut();
            slot.clk = e.clk;
            slot.syscall_id = e.syscall_code.syscall_id() as u64; // column value
            slot.raw_syscall_id = e.syscall_id as u64; // dependency (raw) value
            slot.arg1 = e.arg1;
            slot.arg2 = e.arg2;
            slot.trap_code = if let Some(TrapError::PagePermissionViolation(code)) = e.trap_error {
                code as u8 as u64
            } else {
                0
            };
            slot.should_send = e.should_send as u64;
        },
    );
    inputs
}

pub(crate) fn record_syscall_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let (mut rec, input) = record_witgen_inputs::<SyscallWitgenInput<WireId>>();
    let mut cols_w = SyscallCols::<WireId, SupervisorMode>::default();
    SyscallCols::<WireId, SupervisorMode>::witgen(&mut rec, &mut cols_w, &input);
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

/// The chip's cached [`WitgenChip`] descriptor: recorded + lowered ONCE per
/// process (the program is shard-independent — both Core and Precompile shard
/// kinds share it), not per shard.
fn syscall_witgen_chip() -> &'static super::WitgenChip {
    static CHIP: std::sync::OnceLock<super::WitgenChip> = std::sync::OnceLock::new();
    CHIP.get_or_init(|| {
        let (program, col_wires) = record_syscall_program();
        super::WitgenChip::new(program, col_wires)
    })
}

impl CudaTracegenAir<F> for SyscallChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    // `supports_device_dependencies` (byte lookups fused on device) is decided at
    // the `RiscvAir` level; the `GlobalInteractionEvent`s stay on host via
    // `generate_global_dependencies`.

    async fn generate_trace_device_with_lookups(
        &self,
        input: &Self::Record,
        inputs: Vec<u64>,
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        // Fused: one op-DAG pass writes the columns AND accumulates this chip's
        // byte/range lookups into the shared shard histograms.
        let chip = syscall_witgen_chip();
        debug_assert_eq!(chip.n_cols(), NUM_SYSCALL_COLS_SUPERVISOR);
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let n_events =
            if height == 0 { 0 } else { inputs.len() / chip.program.num_inputs as usize };
        super::generate_trace_and_lookups(
            chip,
            super::WitgenBatch { inputs: &inputs, n_events, height },
            hist,
            scope,
        )
        .await
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
        let events = collect_syscall_events(input, self.shard_kind());
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }
        let inputs = pack_syscall_inputs(&events[..n_events]);
        super::accumulate_lookups(
            syscall_witgen_chip(),
            &inputs,
            n_events,
            range_dev,
            byte_dev,
            scope,
        )
        .await
    }

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
        let ni = sp1_core_machine::syscall::chip::NUM_SYSCALL_WITGEN_INPUTS;
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

    /// The FUSED production entry point (`generate_trace_device_with_lookups`) must
    /// produce columns identical to the CPU trace AND a histogram identical to the
    /// standalone lookup pass (`generate_device_dependencies`) — the device leg of
    /// the globals-on-host split (the host leg is covered by the core machine's
    /// `global_dependencies_are_the_global_subset` test). Core kind with mixed
    /// `should_send` so the lookup guard is exercised.
    #[tokio::test]
    async fn test_syscall_fused_kernel() {
        use crate::CudaTracegenAir;
        use slop_tensor::Tensor;
        use sp1_gpu_cudart::TaskScope;
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let events = synth_events(300, 0x5CA3);
            let shard = ExecutionRecord { syscall_events: events, ..Default::default() };
            let chip = SyscallChip::<SupervisorMode>::core();
            let cpu_trace = Tensor::<F>::from(MachineAir::<F>::generate_trace(
                &chip,
                &shard,
                &mut ExecutionRecord::default(),
            ));

            // Reference histogram via the standalone lookup pass.
            let (mut r_ref, mut b_ref) = crate::new_byte_histograms(&scope);
            chip.generate_device_dependencies(&shard, &mut r_ref, &mut b_ref, &scope)
                .await
                .unwrap();
            let r_ref_h: Vec<u32> = r_ref.to_host().unwrap();
            let b_ref_h: Vec<u32> = b_ref.to_host().unwrap();

            // Fused: the production entry point, inputs packed as the prover packs them.
            let sent = super::collect_syscall_events(&shard, super::SyscallShardKind::Core);
            let packed = super::pack_syscall_inputs(&sent);
            let (r_f, b_f) = crate::new_byte_histograms(&scope);
            let hist = crate::LookupHist {
                range: r_f.as_ptr() as *mut u32,
                byte: b_f.as_ptr() as *mut u32,
            };
            let fused_trace = chip
                .generate_trace_device_with_lookups(&shard, packed, hist, &scope)
                .await
                .expect("fused tracegen should succeed")
                .to_host()
                .expect("copy fused trace to host")
                .into_guts();
            let r_f_h: Vec<u32> = r_f.to_host().unwrap();
            let b_f_h: Vec<u32> = b_f.to_host().unwrap();

            crate::tests::test_traces_eq(&cpu_trace, &fused_trace, &sent);
            assert_eq!(r_f_h, r_ref_h, "fused range histogram must match the lookup pass");
            assert_eq!(b_f_h, b_ref_h, "fused byte histogram must match the lookup pass");
        })
        .await
        .unwrap();
    }
}
