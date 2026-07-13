//! Device main-trace + dependency generation for the trusted `StoreHalf` chip
//! (sh): two offset bits + the stored word.

use core::borrow::BorrowMut;

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::{events::MemInstrEvent, ITypeRecord};
use sp1_core_machine::{
    adapter::register::i_type::ITypeReaderWitgenInput,
    air::{columns_as_wires, record_witgen_inputs, WireId},
    memory::instructions::store::store_half::{
        StoreHalfChip, StoreHalfColumns, StoreHalfWitgenInput, NUM_STORE_HALF_COLS_SUPERVISOR,
        NUM_STORE_HALF_WITGEN_INPUTS,
    },
    memory::MemoryAccessWitgenInput,
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Pack each event into one [`StoreHalfWitgenInput`] row.
pub(crate) fn pack_store_half_inputs(events: &[(MemInstrEvent, ITypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_STORE_HALF_WITGEN_INPUTS];
    inputs.par_chunks_mut(NUM_STORE_HALF_WITGEN_INPUTS).zip(events.par_iter()).for_each(
        |(chunk, (ev, r))| {
            let slot: &mut StoreHalfWitgenInput<u64> = chunk.borrow_mut();
            slot.clk = ev.clk;
            slot.pc = ev.pc;
            slot.adapter = ITypeReaderWitgenInput::from_record(r);
            slot.b_val = ev.b;
            slot.c_val = ev.c;
            slot.mem = MemoryAccessWitgenInput::from_record(ev.mem_access);
            slot.mem_value = ev.mem_access.value();
        },
    );
    inputs
}

fn record_store_half_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let (mut rec, input) = record_witgen_inputs::<StoreHalfWitgenInput<WireId>>();
    let mut cols_w = StoreHalfColumns::<WireId, SupervisorMode>::default();
    StoreHalfColumns::<WireId, SupervisorMode>::witgen(&mut rec, &mut cols_w, &input);
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "store_half gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

/// The chip's cached [`WitgenChip`] descriptor: recorded + lowered ONCE per
/// process (the program is shard-independent), not per shard.
fn store_half_witgen_chip() -> &'static super::WitgenChip {
    static CHIP: std::sync::OnceLock<super::WitgenChip> = std::sync::OnceLock::new();
    CHIP.get_or_init(|| {
        let (program, col_wires) = record_store_half_program();
        super::WitgenChip::new(program, col_wires)
    })
}

impl CudaTracegenAir<F> for StoreHalfChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_store_half_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_STORE_HALF_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.memory_store_half_events;
        let n_events = if height == 0 { 0 } else { events.len() };

        let inputs = pack_store_half_inputs(&events[..n_events]);

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
        let chip = store_half_witgen_chip();
        debug_assert_eq!(chip.n_cols(), NUM_STORE_HALF_COLS_SUPERVISOR);
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
        let events = &input.memory_store_half_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }

        let inputs = pack_store_half_inputs(&events[..n_events]);
        super::accumulate_lookups(
            store_half_witgen_chip(),
            &inputs,
            n_events,
            range_dev,
            byte_dev,
            scope,
        )
        .await
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
    use sp1_core_machine::memory::instructions::store::store_half::StoreHalfChip;
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

    /// Device-vs-CPU trace equality for `StoreHalfChip`.
    #[tokio::test]
    async fn test_store_half_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let mut rng = StdRng::seed_from_u64(0x5048);
            let memory_store_half_events = (0..1200)
                .map(|i| {
                    let b = rng.gen::<u32>() as u64;
                    let c = rng.gen::<u16>() as u64;
                    let ev = MemInstrEvent {
                        clk: (i as u64) * 8 + 8,
                        pc: (i as u64) * 4 + 4,
                        opcode: Opcode::SH,
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
                memory_store_half_events: memory_store_half_events.clone(),
                ..Default::default()
            });

            let chip = StoreHalfChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let gpu_trace = chip
                .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&trace, &gpu_trace, &memory_store_half_events);
        })
        .await
        .unwrap();
    }
}
