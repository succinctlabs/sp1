//! Device main-trace generation for the trusted `Add` chip via the generic witgen
//! interpreter. We record the chip's `AddCols::witgen` op-DAG once (row
//! independent), pack each event's inputs, and run one thread per row on the GPU —
//! the column-only port of the CPU `generate_trace_into`. Byte lookups still come
//! from the CPU `generate_dependencies` (device lookups are a later step).

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::{events::AluEvent, RTypeRecord};
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    alu::add_sub::add::{AddChip, AddCols, NUM_ADD_COLS_SUPERVISOR},
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `Add` row (see [`AddCols::witgen`]).
const NUM_ADD_INPUTS: usize = 16;

/// Pack each event's witgen inputs (the 16 fields the CPU `populate` path reads, in
/// `AddCols::witgen` order). Parallel: the serial pack dominated wall-time at large
/// sizes (iter-014). Shared by device main-tracegen and device dependency-gen.
fn pack_add_inputs(events: &[(AluEvent, RTypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_ADD_INPUTS];
    inputs.par_chunks_mut(NUM_ADD_INPUTS).zip(events.par_iter()).for_each(|(slot, (alu, r))| {
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

/// Record the `Add` chip's witgen op-DAG (row-independent) and assert it fits the
/// kernel's per-thread wire capacity. Shared by main-tracegen and dependency-gen.
fn record_add_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_ADD_INPUTS as u32);
    let mut cols_w = AddCols::<WireId, SupervisorMode>::default();
    let wire = |i: u32| RecordingWitnessBuilder::input(i);
    AddCols::<WireId, SupervisorMode>::witgen(
        &mut rec, &mut cols_w, wire(0), wire(1), wire(2), wire(3), wire(4), wire(5), wire(6),
        wire(7), wire(8), wire(9), wire(10), wire(11), wire(12), wire(13), wire(14), wire(15),
    );
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "Add gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

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
        let (program, col_wires) = record_add_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_ADD_COLS_SUPERVISOR);

        // Padded height (handles the trust-mode guard via `num_rows`).
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.add_events;
        let n_events = if height == 0 { 0 } else { events.len() };

        // Pack each event's inputs (parallel; see `pack_add_inputs`).
        let inputs = pack_add_inputs(&events[..n_events]);

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
        // Same op-DAG + input packing as the main trace; run the lookup kernel (not the
        // column kernel) to accumulate this chip's byte/range multiplicities into the
        // SHARED shard histograms. The prover reads them back and reconstructs the
        // `byte_lookups` map ONCE across all device chips (`merge_device_dependencies`).
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.add_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }
        let (program, _col_wires) = record_add_program();
        let inputs = pack_add_inputs(&events[..n_events]);
        super::accumulate_lookups(&program, &inputs, n_events, range_dev, byte_dev, scope).await
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
                    // op_b/op_c are register indices (< field order), since they are
                    // `nat_to_field`'d directly; the operand values live in `b`/`c`.
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

    /// The FUSED kernel must produce, in ONE pass, columns identical to the CPU trace
    /// AND a byte/range histogram identical to the standalone lookup kernel (the union
    /// of the two separate kernels, with no interference between the column and lookup
    /// outputs).
    #[tokio::test]
    async fn test_add_fused_kernel() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let mut rng = StdRng::seed_from_u64(0xF05ED);
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
                        op_b: rng.gen_range(1..32),
                        b: read(&mut rng),
                        op_c: rng.gen_range(1..32),
                        c: read(&mut rng),
                        is_untrusted: false,
                    };
                    (alu, record)
                })
                .collect::<Vec<_>>();

            let gpu_shard =
                ExecutionRecord { add_events: add_events.clone(), ..Default::default() };
            let chip = AddChip::<SupervisorMode>::default();

            // CPU reference columns.
            let cpu_trace = Tensor::<F>::from(
                chip.generate_trace(&gpu_shard, &mut ExecutionRecord::default()),
            );

            // Build the op-DAG + packed inputs once (shared by both device paths).
            let (program, col_wires) = super::record_add_program();
            let n_cols = col_wires.len();
            let height =
                <AddChip<SupervisorMode> as MachineAir<F>>::num_rows(&chip, &gpu_shard).unwrap();
            let n_events = if height == 0 { 0 } else { add_events.len() };
            let inputs = super::pack_add_inputs(&add_events[..n_events]);

            // Reference histogram from the standalone lookup kernel.
            let (mut r_ref, mut b_ref) = crate::new_byte_histograms(&scope);
            crate::riscv::accumulate_lookups(
                &program, &inputs, n_events, &mut r_ref, &mut b_ref, &scope,
            )
            .await
            .unwrap();
            let r_ref_h: Vec<u32> = r_ref.to_host().unwrap();
            let b_ref_h: Vec<u32> = b_ref.to_host().unwrap();

            // Fused kernel: columns + histogram in a single op-DAG pass.
            let (mut r_f, mut b_f) = crate::new_byte_histograms(&scope);
            let fused_trace = crate::riscv::generate_trace_and_lookups(
                &program, &col_wires, n_cols, &inputs, n_events, height, &mut r_f, &mut b_f, &scope,
            )
            .await
            .expect("fused tracegen should succeed")
            .to_host()
            .expect("copy fused trace to host")
            .into_guts();
            let r_f_h: Vec<u32> = r_f.to_host().unwrap();
            let b_f_h: Vec<u32> = b_f.to_host().unwrap();

            crate::tests::test_traces_eq(&cpu_trace, &fused_trace, &add_events);
            assert_eq!(r_f_h, r_ref_h, "fused range histogram must match the lookup kernel");
            assert_eq!(b_f_h, b_ref_h, "fused byte histogram must match the lookup kernel");
        })
        .await
        .unwrap();
    }
}
