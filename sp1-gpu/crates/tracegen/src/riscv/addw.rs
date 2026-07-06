//! Device main-trace + dependency generation for the trusted `Addw` chip. Uses the
//! `ALUTypeReader` adapter (register-register case): `op_c` is a register, so this is
//! a clean row-independent op-DAG. (Immediate-capable chips that vary `imm_c` per row
//! are not portable through this path — see `ALUTypeReader::witgen`.)

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::{events::AluEvent, ALUTypeRecord};
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    alu::add_sub::addw::{AddwChip, AddwCols, NUM_ADDW_COLS_SUPERVISOR},
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `Addw` row (see [`AddwCols::witgen`]).
const NUM_ADDW_INPUTS: usize = 17;

/// Pack each event's witgen inputs in `AddwCols::witgen` order. ADDW handles both
/// register (ADDW) and immediate (ADDIW) op_c, so `record.c` may be `None`; the
/// `imm_c` flag (input 16) drives the adapter's per-row branch.
pub(crate) fn pack_addw_inputs(events: &[(AluEvent, ALUTypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_ADDW_INPUTS];
    inputs.par_chunks_mut(NUM_ADDW_INPUTS).zip(events.par_iter()).for_each(|(slot, (alu, r))| {
        let a = r.a;
        let b = r.b;
        let (c_pv, c_pt, c_ct) = match r.c {
            Some(c) => (
                c.previous_record().value,
                c.previous_record().timestamp,
                c.current_record().timestamp,
            ),
            None => (0, 0, 0),
        };
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
            c_pv,
            c_pt,
            c_ct,
            r.c.is_none() as u64,
        ]);
    });
    inputs
}

/// Record the `Addw` chip's witgen op-DAG (row-independent) + the column→wire map.
fn record_addw_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_ADDW_INPUTS as u32);
    let mut cols_w = AddwCols::<WireId, SupervisorMode>::default();
    let wire = |i: u32| RecordingWitnessBuilder::input(i);
    AddwCols::<WireId, SupervisorMode>::witgen(
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
        wire(16),
    );
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "Addw gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

impl CudaTracegenAir<F> for AddwChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_addw_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_ADDW_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.addw_events;
        let n_events = if height == 0 { 0 } else { events.len() };

        let inputs = pack_addw_inputs(&events[..n_events]);

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
        let (program, col_wires) = record_addw_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_ADDW_COLS_SUPERVISOR);
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let n_events = if height == 0 { 0 } else { inputs.len() / program.num_inputs as usize };
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
        let events = &input.addw_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }

        let (program, _col_wires) = record_addw_program();
        let inputs = pack_addw_inputs(&events[..n_events]);
        super::accumulate_lookups(&program, &inputs, n_events, range_dev, byte_dev, scope).await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::events::{AluEvent, MemoryReadRecord, MemoryRecordEnum};
    use sp1_core_executor::{ALUTypeRecord, ExecutionRecord, Opcode};
    use sp1_core_machine::alu::add_sub::addw::AddwChip;
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

    /// Device-vs-CPU trace equality for the `Addw` chip over random register-register
    /// events — validates `AddwCols::witgen` (incl. `ALUTypeReader::witgen`) against
    /// the CPU `populate` path (which is unchanged), one thread per row.
    #[tokio::test]
    async fn test_addw_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let mut rng = StdRng::seed_from_u64(0xADD_0);
            let addw_events = (0..1000)
                .map(|i| {
                    let b = rng.gen::<u32>() as u64;
                    let c = rng.gen::<u32>() as u64;
                    let a = (b as u32).wrapping_add(c as u32) as u64;
                    let alu = AluEvent::new(
                        (i as u64) * 8 + 8,
                        (i as u64) * 4 + 4,
                        Opcode::ADDW,
                        a,
                        b,
                        c,
                        false,
                    );
                    // op_a/op_b/op_c are register indices (< field order); operand
                    // values live in `b`/`c` and the memory records.
                    // Mix register (ADDW) and immediate (ADDIW) op_c to exercise the
                    // adapter's per-row imm_c branch (the bug the e2e bench caught).
                    let imm = i % 2 == 0;
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
                .collect::<Vec<_>>();

            let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
                addw_events: addw_events.clone(),
                ..Default::default()
            });

            let chip = AddwChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let gpu_trace = chip
                .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&trace, &gpu_trace, &addw_events);
        })
        .await
        .unwrap();
    }
}
