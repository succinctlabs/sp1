//! Device main-trace + dependency generation for the trusted `Jal` chip (jal).
//! Two AddOperations (jump target `pc + b`, return address `pc + 4` guarded by
//! op_a≠0) over the `JTypeReader` adapter.

use core::borrow::BorrowMut;

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::{events::JumpEvent, JTypeRecord};
use sp1_core_machine::{
    adapter::register::j_type::JTypeReaderWitgenInput,
    air::{columns_as_wires, record_witgen_inputs, WireId},
    control_flow::{
        JalChip, JalColumns, JalWitgenInput, NUM_JAL_COLS_SUPERVISOR, NUM_JAL_WITGEN_INPUTS,
    },
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Pack each event into one [`JalWitgenInput`] row.
pub(crate) fn pack_jal_inputs(events: &[(JumpEvent, JTypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_JAL_WITGEN_INPUTS];
    inputs.par_chunks_mut(NUM_JAL_WITGEN_INPUTS).zip(events.par_iter()).for_each(
        |(chunk, (ev, r))| {
            let slot: &mut JalWitgenInput<u64> = chunk.borrow_mut();
            slot.clk = ev.clk;
            slot.pc = ev.pc;
            slot.adapter = JTypeReaderWitgenInput::from_record(r);
            slot.event_b = ev.b;
        },
    );
    inputs
}

fn record_jal_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let (mut rec, input) = record_witgen_inputs::<JalWitgenInput<WireId>>();
    let mut cols_w = JalColumns::<WireId, SupervisorMode>::default();
    JalColumns::<WireId, SupervisorMode>::witgen(&mut rec, &mut cols_w, &input);
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "Jal gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

/// The chip's cached [`WitgenChip`] descriptor: recorded + lowered ONCE per
/// process (the program is shard-independent), not per shard.
fn jal_witgen_chip() -> &'static super::WitgenChip {
    static CHIP: std::sync::OnceLock<super::WitgenChip> = std::sync::OnceLock::new();
    CHIP.get_or_init(|| {
        let (program, col_wires) = record_jal_program();
        super::WitgenChip::new(program, col_wires)
    })
}

impl CudaTracegenAir<F> for JalChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_jal_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_JAL_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.jal_events;
        let n_events = if height == 0 { 0 } else { events.len() };

        let inputs = pack_jal_inputs(&events[..n_events]);

        let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone()).unwrap();
        ops_dev.extend_from_host_slice(&ops_c)?;
        let mut col_dev = Buffer::try_with_capacity_in(col_wires.len(), scope.clone()).unwrap();
        col_dev.extend_from_host_slice(&col_wires)?;
        let mut in_dev = Buffer::try_with_capacity_in(inputs.len().max(1), scope.clone()).unwrap();
        in_dev.extend_from_host_slice(&inputs)?;

        // Padding rows are all-zero (is_real = 0).
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

    async fn generate_trace_device_with_lookups(
        &self,
        input: &Self::Record,
        inputs: Vec<u64>,
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        // Fused: one op-DAG pass writes the columns AND accumulates this chip's
        // byte/range lookups into the shared shard histograms — replaces the separate
        // `generate_trace_device` + dependency pass for this chip.
        let chip = jal_witgen_chip();
        debug_assert_eq!(chip.n_cols(), NUM_JAL_COLS_SUPERVISOR);
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
        let events = &input.jal_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }

        let inputs = pack_jal_inputs(&events[..n_events]);
        super::accumulate_lookups(jal_witgen_chip(), &inputs, n_events, range_dev, byte_dev, scope)
            .await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::events::{JumpEvent, MemoryReadRecord, MemoryRecordEnum};
    use sp1_core_executor::{ExecutionRecord, JTypeRecord, Opcode};
    use sp1_core_machine::control_flow::JalChip;
    use sp1_core_machine::SupervisorMode;
    use sp1_gpu_cudart::TaskScope;
    use sp1_hypercube::air::MachineAir;

    use crate::{CudaTracegenAir, F};

    fn read(rng: &mut StdRng) -> MemoryRecordEnum {
        let prev_timestamp = rng.gen::<u32>() as u64;
        let timestamp = prev_timestamp + 1 + (rng.gen::<u32>() as u64);
        MemoryRecordEnum::Read(MemoryReadRecord {
            value: rng.gen::<u64>(),
            timestamp,
            prev_timestamp,
            prev_page_prot_record: None,
        })
    }

    #[tokio::test]
    async fn test_jal_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let mut rng = StdRng::seed_from_u64(0x4A1);
            let jal_events = (0..1200)
                .map(|i| {
                    let pc = (i as u64) * 4 + 4;
                    let b = (rng.gen::<u32>() as u64) & !1u64;
                    let op_a = if i % 3 == 0 { 0 } else { rng.gen_range(1..32) };
                    let ev = JumpEvent {
                        clk: (i as u64) * 8 + 8,
                        pc,
                        next_pc: pc.wrapping_add(b),
                        opcode: Opcode::JAL,
                        a: pc.wrapping_add(4),
                        b,
                        c: 0,
                        op_a_0: op_a == 0,
                    };
                    let record = JTypeRecord {
                        op_a,
                        a: read(&mut rng),
                        op_b: b,
                        op_c: 0,
                        is_untrusted: false,
                    };
                    (ev, record)
                })
                .collect::<Vec<_>>();

            let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
                jal_events: jal_events.clone(),
                ..Default::default()
            });

            let chip = JalChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let gpu_trace = chip
                .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&trace, &gpu_trace, &jal_events);
        })
        .await
        .unwrap();
    }
}
