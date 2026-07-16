//! Device main-trace + dependency generation for the trusted `ShiftLeft` chip
//! (SLL/SLLW + immediate). The most complex chip: a per-row shift amount drives
//! variable `shl`/`shr` limb splits and variable-width range checks, plus the
//! SLL/SLLW + immediate per-row branches (handled via guard / field_select).

use core::borrow::BorrowMut;

use rayon::prelude::*;
use slop_algebra::AbstractField;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use sp1_core_executor::{events::AluEvent, ALUTypeRecord};
use sp1_core_machine::{
    adapter::register::alu_type::ALUTypeReaderWitgenInput,
    air::{columns_as_wires, record_witgen_inputs, WireId},
    alu::sll::{
        ShiftLeftChip, ShiftLeftCols, ShiftLeftWitgenInput, NUM_SHIFT_LEFT_COLS_SUPERVISOR,
        NUM_SHIFT_LEFT_WITGEN_INPUTS,
    },
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Pack each event into one [`ShiftLeftWitgenInput`] row. Immediate rows have no
/// `c` register read, so those fields pack as zeros (unused on the device).
pub(crate) fn pack_sll_inputs(events: &[(AluEvent, ALUTypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_SHIFT_LEFT_WITGEN_INPUTS];
    inputs.par_chunks_mut(NUM_SHIFT_LEFT_WITGEN_INPUTS).zip(events.par_iter()).for_each(
        |(chunk, (alu, r))| {
            let slot: &mut ShiftLeftWitgenInput<u64> = chunk.borrow_mut();
            slot.clk = alu.clk;
            slot.pc = alu.pc;
            slot.a = alu.a; // result
            slot.b = alu.b;
            slot.c = alu.c; // shift source
            slot.opcode = alu.opcode as u64;
            slot.adapter = ALUTypeReaderWitgenInput::from_record(r);
        },
    );
    inputs
}

/// Record the `ShiftLeft` chip's witgen op-DAG (row-independent) + the column→wire map.
fn record_sll_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let (mut rec, input) = record_witgen_inputs::<ShiftLeftWitgenInput<WireId>>();
    let mut cols_w = ShiftLeftCols::<WireId, SupervisorMode>::default();
    ShiftLeftCols::<WireId, SupervisorMode>::witgen(&mut rec, &mut cols_w, &input);
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "ShiftLeft gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

/// The chip's cached [`WitgenChip`] descriptor: recorded + lowered ONCE per
/// process (the program is shard-independent), not per shard.
pub(crate) fn sll_witgen_chip() -> &'static super::WitgenChip {
    static CHIP: std::sync::OnceLock<super::WitgenChip> = std::sync::OnceLock::new();
    CHIP.get_or_init(|| {
        let (program, col_wires) = record_sll_program();
        super::WitgenChip::new(program, col_wires)
    })
}

/// The CPU padding template (`generate_trace_into`'s padded rows): v_01/v_012/v_0123 = 1.
fn sll_template(n_cols: usize) -> Vec<F> {
    let mut tmpl = vec![F::zero(); n_cols];
    let cols: &mut ShiftLeftCols<F, SupervisorMode> = tmpl.as_mut_slice().borrow_mut();
    cols.v_01 = F::one();
    cols.v_012 = F::one();
    cols.v_0123 = F::one();
    tmpl
}

impl CudaTracegenAir<F> for ShiftLeftChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        // The chip's cached descriptor: recorded + lowered once per process.
        let chip = sll_witgen_chip();
        let ops_c = chip.ssa();
        let n_cols = chip.n_cols();
        debug_assert_eq!(n_cols, NUM_SHIFT_LEFT_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.shift_left_events;
        let n_events = if height == 0 { 0 } else { events.len() };

        let inputs = pack_sll_inputs(&events[..n_events]);

        let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone()).unwrap();
        ops_dev.extend_from_host_slice(ops_c)?;
        let mut col_dev =
            Buffer::try_with_capacity_in(chip.col_wires.len(), scope.clone()).unwrap();
        col_dev.extend_from_host_slice(&chip.col_wires)?;
        let mut in_dev = Buffer::try_with_capacity_in(inputs.len().max(1), scope.clone()).unwrap();
        in_dev.extend_from_host_slice(&inputs)?;

        // Padding rows are NOT all-zero for this chip: the CPU padding template sets
        // v_01/v_012/v_0123 = 1. Fill the padding rows ON DEVICE (H2) — the kernel
        // writes every column of the event rows.
        let mut trace =
            super::template_trace(n_cols, height, n_events, &sll_template(n_cols), scope)?;

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
                    chip.program.num_inputs,
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

    async fn generate_trace_device_with_lookups(
        &self,
        input: &Self::Record,
        inputs: &[u64],
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        // Fused column+lookup pass. ShiftLeft padding rows are NOT all-zero: the CPU
        // padding template sets v_01/v_012/v_0123 = 1, so initialize the device trace
        // with that template (broadcast to all rows) before the kernel overwrites event
        // rows — same as `generate_trace_device`, but the fused kernel also accumulates
        // this chip's byte/range lookups into the shared shard histograms.
        let chip = sll_witgen_chip();
        let n_cols = chip.n_cols();
        debug_assert_eq!(n_cols, NUM_SHIFT_LEFT_COLS_SUPERVISOR);
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let n_events =
            if height == 0 { 0 } else { inputs.len() / chip.program.num_inputs as usize };

        let trace = super::template_trace(n_cols, height, n_events, &sll_template(n_cols), scope)?;

        super::generate_trace_and_lookups_into(
            chip,
            super::WitgenBatch { inputs, n_events, height },
            trace,
            hist,
            scope,
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
        let events = &input.shift_left_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }

        let inputs = pack_sll_inputs(&events[..n_events]);
        super::accumulate_lookups(sll_witgen_chip(), &inputs, n_events, range_dev, byte_dev, scope)
            .await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::events::{AluEvent, MemoryReadRecord, MemoryRecordEnum};
    use sp1_core_executor::{ALUTypeRecord, ExecutionRecord, Opcode};
    use sp1_core_machine::alu::sll::ShiftLeftChip;
    use sp1_core_machine::SupervisorMode;
    use sp1_gpu_cudart::TaskScope;
    use sp1_hypercube::air::MachineAir;

    use crate::{CudaTracegenAir, F};

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

    /// MIXED SLL/SLLW + register/immediate events with random shift amounts.
    fn synth_events(n: usize, seed: u64) -> Vec<(AluEvent, ALUTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(seed);
        (0..n)
            .map(|i| {
                let sllw = i % 2 == 0;
                let opcode = if sllw { Opcode::SLLW } else { Opcode::SLL };
                let b = rng.gen::<u64>();
                let c = rng.gen::<u64>();
                let a =
                    if sllw { ((b as i32) << (c & 0x1f)) as i64 as u64 } else { b << (c & 0x3f) };
                let alu =
                    AluEvent::new((i as u64) * 8 + 8, (i as u64) * 4 + 4, opcode, a, b, c, false);
                let imm = i % 3 == 0;
                let record = ALUTypeRecord {
                    op_a: rng.gen_range(1..32),
                    a: read(&mut rng),
                    op_b: rng.gen_range(1..32),
                    b: read(&mut rng),
                    op_c: if imm { c } else { rng.gen_range(1..32) },
                    c: if imm { None } else { Some(read(&mut rng)) },
                    is_imm: imm,
                    is_untrusted: false,
                };
                (alu, record)
            })
            .collect()
    }

    /// Device-vs-CPU trace equality for `ShiftLeft` over MIXED SLL/SLLW + register/
    /// immediate events with random shift amounts — exercises the variable shifts,
    /// variable-width range checks, and the SLLW guard.
    #[tokio::test]
    async fn test_shift_left_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let shift_left_events = synth_events(1200, 0x511);

            let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
                shift_left_events: shift_left_events.clone(),
                ..Default::default()
            });

            let chip = ShiftLeftChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let gpu_trace = chip
                .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&trace, &gpu_trace, &shift_left_events);
        })
        .await
        .unwrap();
    }

    /// Device-vs-CPU trace equality for `ShiftLeft` via the FUSED entry
    /// (`generate_trace_device_with_lookups` — the one production calls, since
    /// `supports_device_dependencies` is true), covering the device-side padding
    /// template fill on this path (non-power-of-two count ⇒ padding rows present).
    #[tokio::test]
    async fn test_shift_left_generate_trace_device_fused() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let shift_left_events = synth_events(1200, 0x511F);

            let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
                shift_left_events: shift_left_events.clone(),
                ..Default::default()
            });

            let chip = ShiftLeftChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let (mut range_dev, mut byte_dev) = crate::new_byte_histograms(&scope);
            let hist =
                crate::LookupHist { range: range_dev.as_mut_ptr(), byte: byte_dev.as_mut_ptr() };
            let inputs = super::pack_sll_inputs(&shift_left_events);
            let gpu_trace = chip
                .generate_trace_device_with_lookups(&gpu_shard, &inputs, hist, &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&trace, &gpu_trace, &shift_left_events);
        })
        .await
        .unwrap();
    }
}
