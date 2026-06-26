//! Device main-trace generation for the trusted `Add` chip via the generic witgen
//! interpreter. We record the chip's `AddCols::witgen` op-DAG once (row
//! independent), pack each event's inputs, and run one thread per row on the GPU —
//! the column-only port of the CPU `generate_trace_into`. Byte lookups still come
//! from the CPU `generate_dependencies` (device lookups are a later step).

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    alu::add_sub::add::{AddChip, AddCols, NUM_ADD_COLS_SUPERVISOR},
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `Add` row (see [`AddCols::witgen`]).
const NUM_ADD_INPUTS: usize = 16;

impl CudaTracegenAir<F> for AddChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        // Record the chip's witgen op-DAG once — its shape is row-independent.
        let mut rec = RecordingWitnessBuilder::new(NUM_ADD_INPUTS as u32);
        let mut cols_w = AddCols::<WireId, SupervisorMode>::default();
        let wire = |i: u32| RecordingWitnessBuilder::input(i);
        AddCols::<WireId, SupervisorMode>::witgen(
            &mut rec,
            &mut cols_w,
            wire(0),
            wire(1),
            wire(2),
            wire(3),
            wire(4),
            wire(5),
            wire(6),
            wire(7),
            wire(8),
            wire(9),
            wire(10),
            wire(11),
            wire(12),
            wire(13),
            wire(14),
            wire(15),
        );
        let program = rec.finish();
        assert!(
            program.num_wires() <= super::WITGEN_MAX_WIRES,
            "Add gadget needs {} wires > kernel capacity {}",
            program.num_wires(),
            super::WITGEN_MAX_WIRES
        );
        let ops_c = program.to_c();
        let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_ADD_COLS_SUPERVISOR);

        // Padded height (handles the trust-mode guard via `num_rows`).
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.add_events;
        let n_events = if height == 0 { 0 } else { events.len() };

        // Pack each event's inputs (mirrors the fields the CPU `populate` reads).
        // Parallel: the serial pack dominated wall-time at large sizes.
        let mut inputs: Vec<u64> = vec![0u64; n_events * NUM_ADD_INPUTS];
        inputs.par_chunks_mut(NUM_ADD_INPUTS).zip(events.par_iter()).for_each(
            |(slot, (alu, r))| {
                let (a, b, c) = (r.a, r.b, r.c);
                slot.copy_from_slice(&[
                    alu.clk,
                    alu.pc,
                    alu.b,
                    alu.c,
                    r.op_a as u64,
                    r.op_b,
                    r.op_c,
                    a.previous_record().value,
                    a.previous_record().timestamp,
                    a.current_record().timestamp,
                    b.previous_record().value,
                    b.previous_record().timestamp,
                    b.current_record().timestamp,
                    c.previous_record().value,
                    c.previous_record().timestamp,
                    c.current_record().timestamp,
                ]);
            },
        );

        // Upload op-DAG, column→wire map, and inputs.
        let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone()).unwrap();
        ops_dev.extend_from_host_slice(&ops_c)?;
        let mut col_dev = Buffer::try_with_capacity_in(col_wires.len(), scope.clone()).unwrap();
        col_dev.extend_from_host_slice(&col_wires)?;
        let mut in_dev = Buffer::try_with_capacity_in(inputs.len().max(1), scope.clone()).unwrap();
        in_dev.extend_from_host_slice(&inputs)?;

        // Zeroed trace; only event rows are written (padding rows stay 0 — is_real=0).
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
    use slop_tensor::Tensor;
    use sp1_core_executor::events::{AluEvent, MemoryReadRecord, MemoryRecordEnum};
    use sp1_core_executor::{ExecutionRecord, Opcode, RTypeRecord};
    use sp1_core_machine::alu::add_sub::add::AddChip;
    use sp1_core_machine::SupervisorMode;
    use sp1_gpu_cudart::TaskScope;
    use sp1_hypercube::air::MachineAir;

    use crate::{CudaTracegenAir, F};

    /// A register read whose previous timestamp precedes the current one (required
    /// by the timestamp gadget).
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

    #[tokio::test]
    async fn test_add_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let mut rng = StdRng::seed_from_u64(0xADD);
            let add_events = (0..1000)
                .map(|i| {
                    let b = rng.gen::<u32>() as u64;
                    let c = rng.gen::<u32>() as u64;
                    let a = b.wrapping_add(c);
                    let alu = AluEvent::new(
                        (i as u64) * 8 + 8,
                        (i as u64) * 4 + 4,
                        Opcode::ADD,
                        a,
                        b,
                        c,
                        false,
                    );
                    let record = RTypeRecord {
                        op_a: rng.gen_range(1..32),
                        a: read(&mut rng),
                        op_b: b,
                        b: read(&mut rng),
                        op_c: c,
                        c: read(&mut rng),
                        is_untrusted: false,
                    };
                    (alu, record)
                })
                .collect::<Vec<_>>();

            let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
                add_events: add_events.clone(),
                ..Default::default()
            });

            let chip = AddChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let gpu_trace = chip
                .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&trace, &gpu_trace, &add_events);
        })
        .await
        .unwrap();
    }
}
