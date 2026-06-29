//! Device main-trace + dependency generation for the trusted `LoadDouble` chip
//! (full 64-bit `ld`). First memory chip on the device path: composes the
//! `MemoryAccessCols` (the read, with the high/low-24-bit timestamp comparison),
//! the `AddressOperation` (`addr = b + c`), and the immediate-only `ITypeReader`.

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::{events::MemInstrEvent, ITypeRecord};
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    memory::instructions::load::load_double::{
        LoadDoubleChip, LoadDoubleColumns, NUM_LOAD_DOUBLE_COLS_SUPERVISOR,
    },
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `LoadDouble` row (see [`LoadDoubleColumns::witgen`]).
const NUM_LD_INPUTS: usize = 16;

fn pack_ld_inputs(events: &[(MemInstrEvent, ITypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_LD_INPUTS];
    inputs.par_chunks_mut(NUM_LD_INPUTS).zip(events.par_iter()).for_each(|(slot, (ev, r))| {
        let a = r.a;
        let b = r.b;
        let m = ev.mem_access;
        slot.copy_from_slice(&[
            ev.clk,
            ev.pc,
            r.op_a as u64,
            a.previous_record().value,
            a.previous_record().timestamp,
            a.current_record().timestamp,
            r.op_b,
            b.previous_record().value,
            b.previous_record().timestamp,
            b.current_record().timestamp,
            r.op_c,
            ev.b,
            ev.c,
            m.previous_record().value,
            m.previous_record().timestamp,
            m.current_record().timestamp,
        ]);
    });
    inputs
}

fn record_ld_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_LD_INPUTS as u32);
    let mut cols_w = LoadDoubleColumns::<WireId, SupervisorMode>::default();
    let w = |i: u32| RecordingWitnessBuilder::input(i);
    LoadDoubleColumns::<WireId, SupervisorMode>::witgen(
        &mut rec, &mut cols_w, w(0), w(1), w(2), w(3), w(4), w(5), w(6), w(7), w(8), w(9), w(10),
        w(11), w(12), w(13), w(14), w(15),
    );
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "LoadDouble gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

impl CudaTracegenAir<F> for LoadDoubleChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_ld_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_LOAD_DOUBLE_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.memory_load_double_events;
        let n_events = if height == 0 { 0 } else { events.len() };

        let inputs = pack_ld_inputs(&events[..n_events]);

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
        let events = &input.memory_load_double_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }

        let (program, _col_wires) = record_ld_program();
        let inputs = pack_ld_inputs(&events[..n_events]);
        super::accumulate_lookups(&program, &inputs, n_events, range_dev, byte_dev, scope).await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::events::{
        MemInstrEvent, MemoryReadRecord, MemoryRecordEnum,
    };
    use sp1_core_executor::{ExecutionRecord, ITypeRecord, Opcode};
    use sp1_core_machine::memory::instructions::load::load_double::LoadDoubleChip;
    use sp1_core_machine::SupervisorMode;
    use sp1_gpu_cudart::TaskScope;
    use sp1_hypercube::air::MachineAir;

    use crate::{CudaTracegenAir, F};

    /// A read record whose previous timestamp strictly precedes the current one
    /// (required by the timestamp gadget's `prev < cur` assertion).
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

    /// Device-vs-CPU trace equality for `LoadDouble` — exercises the memory-access
    /// timestamp comparison (both high-limb-equal and not), the address operation,
    /// and the ITypeReader adapter.
    #[tokio::test]
    async fn test_load_double_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let mut rng = StdRng::seed_from_u64(0x1D);
            let memory_load_double_events = (0..1200)
                .map(|i| {
                    let b = rng.gen::<u32>() as u64;
                    let c = rng.gen::<u16>() as u64;
                    let ev = MemInstrEvent {
                        clk: (i as u64) * 8 + 8,
                        pc: (i as u64) * 4 + 4,
                        opcode: Opcode::LD,
                        a: rng.gen::<u64>(),
                        b,
                        c,
                        op_a_0: false,
                        mem_access: read(&mut rng),
                    };
                    let record = ITypeRecord {
                        op_a: rng.gen_range(1..32),
                        a: read(&mut rng),
                        op_b: rng.gen_range(1..32),
                        b: read(&mut rng),
                        op_c: c,
                        is_untrusted: false,
                    };
                    (ev, record)
                })
                .collect::<Vec<_>>();

            let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
                memory_load_double_events: memory_load_double_events.clone(),
                ..Default::default()
            });

            let chip = LoadDoubleChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let gpu_trace = chip
                .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&trace, &gpu_trace, &memory_load_double_events);
        })
        .await
        .unwrap();
    }
}
