//! Device main-trace generation for the trusted `Sub` chip — identical in shape to
//! [`super::add`], differing only in `SubOperation` vs `AddOperation`. See `add.rs`
//! for the approach (record the op-DAG once, pack per-event inputs, run the generic
//! witgen interpreter one thread per row).

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    alu::add_sub::sub::{SubChip, SubCols, NUM_SUB_COLS_SUPERVISOR},
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `Sub` row (see [`SubCols::witgen`]).
const NUM_SUB_INPUTS: usize = 16;

impl CudaTracegenAir<F> for SubChip<SupervisorMode> {
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
        let mut rec = RecordingWitnessBuilder::new(NUM_SUB_INPUTS as u32);
        let mut cols_w = SubCols::<WireId, SupervisorMode>::default();
        let wire = |i: u32| RecordingWitnessBuilder::input(i);
        SubCols::<WireId, SupervisorMode>::witgen(
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
        let ops_c = program.to_c();
        let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_SUB_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.sub_events;
        let n_events = if height == 0 { 0 } else { events.len() };

        // Parallel pack (mirrors the fields the CPU `populate` reads).
        let mut inputs: Vec<u64> = vec![0u64; n_events * NUM_SUB_INPUTS];
        inputs.par_chunks_mut(NUM_SUB_INPUTS).zip(events.par_iter()).for_each(
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

        let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone()).unwrap();
        ops_dev.extend_from_host_slice(&ops_c)?;
        let mut col_dev = Buffer::try_with_capacity_in(col_wires.len(), scope.clone()).unwrap();
        col_dev.extend_from_host_slice(&col_wires)?;
        let mut in_dev = Buffer::try_with_capacity_in(inputs.len().max(1), scope.clone()).unwrap();
        in_dev.extend_from_host_slice(&inputs)?;

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
    use sp1_core_machine::alu::add_sub::sub::SubChip;
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

    #[tokio::test]
    async fn test_sub_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let mut rng = StdRng::seed_from_u64(0x5B);
            let sub_events = (0..1000)
                .map(|i| {
                    let b = rng.gen::<u32>() as u64;
                    let c = rng.gen::<u32>() as u64;
                    let a = b.wrapping_sub(c);
                    let alu = AluEvent::new(
                        (i as u64) * 8 + 8,
                        (i as u64) * 4 + 4,
                        Opcode::SUB,
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
                sub_events: sub_events.clone(),
                ..Default::default()
            });

            let chip = SubChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let gpu_trace = chip
                .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&trace, &gpu_trace, &sub_events);
        })
        .await
        .unwrap();
    }
}
