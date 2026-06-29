//! Device main-trace + dependency generation for the trusted `StoreDouble` chip
//! (sd). Like `LoadDouble`: memory access + address operation + `ITypeReader`.

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::{events::MemInstrEvent, ITypeRecord};
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    memory::instructions::store::store_double::{
        StoreDoubleChip, StoreDoubleColumns, NUM_STORE_DOUBLE_COLS_SUPERVISOR,
    },
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `StoreDoubleChip` row (see [`StoreDoubleColumns::witgen`]).
const NUM_STORE_DOUBLE_INPUTS: usize = 16;

fn pack_store_double_inputs(events: &[(MemInstrEvent, ITypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_STORE_DOUBLE_INPUTS];
    inputs.par_chunks_mut(NUM_STORE_DOUBLE_INPUTS).zip(events.par_iter()).for_each(|(slot, (ev, r))| {
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

fn record_store_double_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_STORE_DOUBLE_INPUTS as u32);
    let mut cols_w = StoreDoubleColumns::<WireId, SupervisorMode>::default();
    let w = |i: u32| RecordingWitnessBuilder::input(i);
    StoreDoubleColumns::<WireId, SupervisorMode>::witgen(
        &mut rec, &mut cols_w, w(0), w(1), w(2), w(3), w(4), w(5), w(6), w(7), w(8), w(9), w(10),
        w(11), w(12), w(13), w(14), w(15),
    );
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "store_double gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

impl CudaTracegenAir<F> for StoreDoubleChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_store_double_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_STORE_DOUBLE_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.memory_store_double_events;
        let n_events = if height == 0 { 0 } else { events.len() };

        let inputs = pack_store_double_inputs(&events[..n_events]);

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
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        // Fused: one op-DAG pass writes the columns AND accumulates this chip's
        // byte/range lookups into the shared shard histograms — replaces the separate
        // `generate_trace_device` + dependency pass for this chip.
        let (program, col_wires) = record_store_double_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_STORE_DOUBLE_COLS_SUPERVISOR);
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.memory_store_double_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        let inputs = pack_store_double_inputs(&events[..n_events]);
        super::generate_trace_and_lookups(
            &program, &col_wires, n_cols, &inputs, n_events, height, hist, scope,
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
        let events = &input.memory_store_double_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }

        let (program, _col_wires) = record_store_double_program();
        let inputs = pack_store_double_inputs(&events[..n_events]);
        super::accumulate_lookups(&program, &inputs, n_events, range_dev, byte_dev, scope).await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::events::{
        MemInstrEvent, MemoryReadRecord, MemoryRecordEnum, MemoryWriteRecord,
    };
    use sp1_core_executor::{ExecutionRecord, ITypeRecord, Opcode};
    use sp1_core_machine::memory::instructions::store::store_double::StoreDoubleChip;
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

    /// A write record with distinct prev/new values, exercising the store path's
    /// prev_value vs value distinction.
    fn write(rng: &mut StdRng) -> MemoryRecordEnum {
        let prev_timestamp = rng.gen::<u32>() as u64;
        let timestamp = prev_timestamp + 1 + (rng.gen::<u32>() as u64);
        MemoryRecordEnum::Write(MemoryWriteRecord {
            prev_timestamp,
            prev_page_prot_record: None,
            prev_value: rng.gen::<u64>(),
            timestamp,
            value: rng.gen::<u64>(),
        })
    }

    /// Device-vs-CPU trace equality for `StoreDoubleChip`.
    #[tokio::test]
    async fn test_store_double_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let mut rng = StdRng::seed_from_u64(0x5D);
            let memory_store_double_events = (0..1200)
                .map(|i| {
                    let b = rng.gen::<u32>() as u64;
                    let c = rng.gen::<u16>() as u64;
                    let ev = MemInstrEvent {
                        clk: (i as u64) * 8 + 8,
                        pc: (i as u64) * 4 + 4,
                        opcode: Opcode::SD,
                        a: rng.gen::<u64>(),
                        b,
                        c,
                        op_a_0: false,
                        mem_access: write(&mut rng),
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
                memory_store_double_events: memory_store_double_events.clone(),
                ..Default::default()
            });

            let chip = StoreDoubleChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let gpu_trace = chip
                .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&trace, &gpu_trace, &memory_store_double_events);
        })
        .await
        .unwrap();
    }
}
