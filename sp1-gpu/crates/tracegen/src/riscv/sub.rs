//! Device main-trace generation for the trusted `Sub` chip — identical in shape to
//! [`super::add`], differing only in `SubOperation` vs `AddOperation`. See `add.rs`
//! for the approach (record the op-DAG once, pack per-event inputs, run the generic
//! witgen interpreter one thread per row).

use core::borrow::BorrowMut;

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::{events::AluEvent, RTypeRecord};
use sp1_core_machine::{
    adapter::register::r_type::RTypeReaderWitgenInput,
    air::{columns_as_wires, record_witgen_inputs, WireId},
    alu::add_sub::sub::{
        SubChip, SubCols, SubWitgenInput, NUM_SUB_COLS_SUPERVISOR, NUM_SUB_WITGEN_INPUTS,
    },
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Pack each event into one [`SubWitgenInput`] row. Shared by device main-tracegen
/// and dependency-gen.
pub(crate) fn pack_sub_inputs(events: &[(AluEvent, RTypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_SUB_WITGEN_INPUTS];
    inputs.par_chunks_mut(NUM_SUB_WITGEN_INPUTS).zip(events.par_iter()).for_each(
        |(chunk, (alu, r))| {
            let slot: &mut SubWitgenInput<u64> = chunk.borrow_mut();
            slot.clk = alu.clk;
            slot.pc = alu.pc;
            slot.b = alu.b;
            slot.c = alu.c;
            slot.adapter = RTypeReaderWitgenInput::from_record(r);
        },
    );
    inputs
}

/// Record the `Sub` chip's witgen op-DAG (row-independent) + the column→wire map,
/// asserting it fits the kernel's per-thread wire capacity.
fn record_sub_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let (mut rec, input) = record_witgen_inputs::<SubWitgenInput<WireId>>();
    let mut cols_w = SubCols::<WireId, SupervisorMode>::default();
    SubCols::<WireId, SupervisorMode>::witgen(&mut rec, &mut cols_w, &input);
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "Sub gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

/// The chip's cached [`WitgenChip`] descriptor: recorded + lowered ONCE per
/// process (the program is shard-independent), not per shard.
pub(crate) fn sub_witgen_chip() -> &'static super::WitgenChip {
    static CHIP: std::sync::OnceLock<super::WitgenChip> = std::sync::OnceLock::new();
    CHIP.get_or_init(|| {
        let (program, col_wires) = record_sub_program();
        super::WitgenChip::new(program, col_wires)
    })
}

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
        // The chip's cached descriptor: recorded + lowered once per process.
        let chip = sub_witgen_chip();
        let ops_c = chip.ssa();
        let n_cols = chip.n_cols();
        debug_assert_eq!(n_cols, NUM_SUB_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.sub_events;
        let n_events = if height == 0 { 0 } else { events.len() };

        // Parallel pack (see `pack_sub_inputs`).
        let inputs = pack_sub_inputs(&events[..n_events]);

        let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone()).unwrap();
        ops_dev.extend_from_host_slice(ops_c)?;
        let mut col_dev =
            Buffer::try_with_capacity_in(chip.col_wires.len(), scope.clone()).unwrap();
        col_dev.extend_from_host_slice(&chip.col_wires)?;
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
        // Fused: one op-DAG pass writes the columns AND accumulates this chip's
        // byte/range lookups into the shared shard histograms — replaces the separate
        // `generate_trace_device` + dependency pass for this chip.
        let chip = sub_witgen_chip();
        debug_assert_eq!(chip.n_cols(), NUM_SUB_COLS_SUPERVISOR);
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let n_events =
            if height == 0 { 0 } else { inputs.len() / chip.program.num_inputs as usize };
        super::generate_trace_and_lookups(
            chip,
            super::WitgenBatch { inputs, n_events, height },
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
        // Run the lookup kernel (not the column kernel) to accumulate this chip's
        // byte/range multiplicities into the SHARED shard histograms (matches host
        // `generate_dependencies`); the prover reads them back once across all chips.
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.sub_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }

        let inputs = pack_sub_inputs(&events[..n_events]);
        super::accumulate_lookups(sub_witgen_chip(), &inputs, n_events, range_dev, byte_dev, scope)
            .await
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
