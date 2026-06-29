//! Device main-trace generation and dependency generation for the trusted `Subw`
//! chip. Identical in shape to [`super::sub`] (same `RTypeReader` adapter + 16
//! inputs); only `SubwOperation` (32-bit sub + msb) differs from `SubOperation`.

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::{events::AluEvent, RTypeRecord};
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    alu::add_sub::subw::{SubwChip, SubwCols, NUM_SUBW_COLS_SUPERVISOR},
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `Subw` row (see [`SubwCols::witgen`]).
const NUM_SUBW_INPUTS: usize = 16;

/// Pack each event's witgen inputs (the 16 fields the CPU `populate` reads, in
/// `SubwCols::witgen` order). Shared by device main-tracegen and dependency-gen.
fn pack_subw_inputs(events: &[(AluEvent, RTypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_SUBW_INPUTS];
    inputs.par_chunks_mut(NUM_SUBW_INPUTS).zip(events.par_iter()).for_each(|(slot, (alu, r))| {
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
    });
    inputs
}

/// Record the `Subw` chip's witgen op-DAG (row-independent) + the column→wire map,
/// asserting it fits the kernel's per-thread wire capacity.
fn record_subw_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_SUBW_INPUTS as u32);
    let mut cols_w = SubwCols::<WireId, SupervisorMode>::default();
    let wire = |i: u32| RecordingWitnessBuilder::input(i);
    SubwCols::<WireId, SupervisorMode>::witgen(
        &mut rec, &mut cols_w, wire(0), wire(1), wire(2), wire(3), wire(4), wire(5), wire(6),
        wire(7), wire(8), wire(9), wire(10), wire(11), wire(12), wire(13), wire(14), wire(15),
    );
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "Subw gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

impl CudaTracegenAir<F> for SubwChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_subw_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_SUBW_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.subw_events;
        let n_events = if height == 0 { 0 } else { events.len() };

        let inputs = pack_subw_inputs(&events[..n_events]);

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
        let events = &input.subw_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }

        let (program, _col_wires) = record_subw_program();
        let inputs = pack_subw_inputs(&events[..n_events]);
        super::accumulate_lookups(&program, &inputs, n_events, range_dev, byte_dev, scope).await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::events::{AluEvent, MemoryReadRecord, MemoryRecordEnum};
    use sp1_core_executor::{ExecutionRecord, Opcode, RTypeRecord};
    use sp1_core_machine::alu::add_sub::subw::SubwChip;
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

    /// Device-vs-CPU trace equality for the `Subw` chip over random events — both
    /// paths use `SubwCols::witgen`, so this validates the device kernel path.
    #[tokio::test]
    async fn test_subw_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let mut rng = StdRng::seed_from_u64(0x5B_0000);
            let subw_events = (0..1000)
                .map(|i| {
                    let b = rng.gen::<u32>() as u64;
                    let c = rng.gen::<u32>() as u64;
                    let a = (b as i32).wrapping_sub(c as i32) as i64 as u64;
                    let alu = AluEvent::new(
                        (i as u64) * 8 + 8,
                        (i as u64) * 4 + 4,
                        Opcode::SUBW,
                        a,
                        b,
                        c,
                        false,
                    );
                    // op_b/op_c are register indices (< field order), `nat_to_field`'d
                    // directly; the operand values live in `b`/`c`.
                    let record = RTypeRecord {
                        op_a: rng.gen_range(1..32),
                        a: read(&mut rng),
                        op_b: rng.gen_range(1..32),
                        b: read(&mut rng),
                        op_c: rng.gen_range(1..32),
                        c: read(&mut rng),
                        is_untrusted: false,
                    };
                    (alu, record)
                })
                .collect::<Vec<_>>();

            let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
                subw_events: subw_events.clone(),
                ..Default::default()
            });

            let chip = SubwChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let gpu_trace = chip
                .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&trace, &gpu_trace, &subw_events);
        })
        .await
        .unwrap();
    }
}
