//! Device main-trace + dependency generation for the trusted `ShiftRight` chip
//! (SRL/SRA/SRLW/SRAW + immediate). Mirror of [`super::sll`] with sign extension;
//! reuses the same shift primitives. Padding rows use a non-zero template.

use core::borrow::BorrowMut;

use rayon::prelude::*;
use slop_algebra::AbstractField;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::{events::AluEvent, ALUTypeRecord};
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    alu::sr::{ShiftRightChip, ShiftRightCols, NUM_SHIFT_RIGHT_COLS_SUPERVISOR},
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `ShiftRight` row (see [`ShiftRightCols::witgen`]).
const NUM_SR_INPUTS: usize = 19;

pub(crate) fn pack_sr_inputs(events: &[(AluEvent, ALUTypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_SR_INPUTS];
    inputs.par_chunks_mut(NUM_SR_INPUTS).zip(events.par_iter()).for_each(|(slot, (alu, r))| {
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
            alu.a,
            alu.b,
            alu.c,
            alu.opcode as u64,
            r.c.is_none() as u64,
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
        ]);
    });
    inputs
}

fn record_sr_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_SR_INPUTS as u32);
    let mut cols_w = ShiftRightCols::<WireId, SupervisorMode>::default();
    let w = |i: u32| RecordingWitnessBuilder::input(i);
    ShiftRightCols::<WireId, SupervisorMode>::witgen(
        &mut rec, &mut cols_w, w(0), w(1), w(2), w(3), w(4), w(5), w(6), w(7), w(8), w(9), w(10),
        w(11), w(12), w(13), w(14), w(15), w(16), w(17), w(18),
    );
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "ShiftRight gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

impl CudaTracegenAir<F> for ShiftRightChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_sr_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_SHIFT_RIGHT_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.shift_right_events;
        let n_events = if height == 0 { 0 } else { events.len() };

        let inputs = pack_sr_inputs(&events[..n_events]);

        let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone()).unwrap();
        ops_dev.extend_from_host_slice(&ops_c)?;
        let mut col_dev = Buffer::try_with_capacity_in(col_wires.len(), scope.clone()).unwrap();
        col_dev.extend_from_host_slice(&col_wires)?;
        let mut in_dev = Buffer::try_with_capacity_in(inputs.len().max(1), scope.clone()).unwrap();
        in_dev.extend_from_host_slice(&inputs)?;

        // Padding rows use a non-zero template: v_01=16, v_012=256, v_0123=65536.
        let mut trace = {
            let mut tmpl = vec![F::zero(); n_cols];
            {
                let cols: &mut ShiftRightCols<F, SupervisorMode> = tmpl.as_mut_slice().borrow_mut();
                cols.v_01 = F::from_canonical_u32(16);
                cols.v_012 = F::from_canonical_u32(256);
                cols.v_0123 = F::from_canonical_u32(65536);
            }
            let mut init = vec![F::zero(); n_cols * height];
            for col in 0..n_cols {
                if tmpl[col] != F::zero() {
                    for r in 0..height {
                        init[col * height + r] = tmpl[col];
                    }
                }
            }
            let mut buf = Buffer::try_with_capacity_in(init.len().max(1), scope.clone()).unwrap();
            buf.extend_from_host_slice(&init)?;
            Tensor::<F, TaskScope>::from(buf).reshape([n_cols, height])
        };

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
        // Fused column+lookup pass. ShiftRight padding rows are NOT all-zero: the CPU
        // padding template sets v_01=16, v_012=256, v_0123=65536, so initialize the
        // device trace with that template (broadcast to all rows) before the kernel
        // overwrites event rows — same as `generate_trace_device`, but the fused kernel
        // also accumulates this chip's byte/range lookups into the shared histograms.
        let (program, col_wires) = record_sr_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_SHIFT_RIGHT_COLS_SUPERVISOR);
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let n_events = if height == 0 { 0 } else { inputs.len() / program.num_inputs as usize };

        let trace = {
            let mut tmpl = vec![F::zero(); n_cols];
            {
                let cols: &mut ShiftRightCols<F, SupervisorMode> = tmpl.as_mut_slice().borrow_mut();
                cols.v_01 = F::from_canonical_u32(16);
                cols.v_012 = F::from_canonical_u32(256);
                cols.v_0123 = F::from_canonical_u32(65536);
            }
            let mut init = vec![F::zero(); n_cols * height];
            for col in 0..n_cols {
                if tmpl[col] != F::zero() {
                    for r in 0..height {
                        init[col * height + r] = tmpl[col];
                    }
                }
            }
            let mut buf = Buffer::try_with_capacity_in(init.len().max(1), scope.clone()).unwrap();
            buf.extend_from_host_slice(&init)?;
            Tensor::<F, TaskScope>::from(buf).reshape([n_cols, height])
        };

        super::generate_trace_and_lookups_into(
            &program, &col_wires, &inputs, n_events, height, trace, hist, scope,
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
        let events = &input.shift_right_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }

        let (program, _col_wires) = record_sr_program();
        let inputs = pack_sr_inputs(&events[..n_events]);
        super::accumulate_lookups(&program, &inputs, n_events, range_dev, byte_dev, scope).await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::events::{AluEvent, MemoryReadRecord, MemoryRecordEnum};
    use sp1_core_executor::{ALUTypeRecord, ExecutionRecord, Opcode};
    use sp1_core_machine::alu::sr::ShiftRightChip;
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

    /// Device-vs-CPU trace equality for `ShiftRight` over all 4 opcodes (SRL/SRA/
    /// SRLW/SRAW), mixed register/immediate, and random shift amounts — exercises
    /// sign extension (signed msb), word masking, and the variable limb splits.
    #[tokio::test]
    async fn test_shift_right_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let mut rng = StdRng::seed_from_u64(0x5217);
            let ops = [Opcode::SRL, Opcode::SRA, Opcode::SRLW, Opcode::SRAW];
            let shift_right_events = (0..1600)
                .map(|i| {
                    let opcode = ops[i % 4];
                    let b = rng.gen::<u64>();
                    let c = rng.gen::<u64>();
                    let a = match opcode {
                        Opcode::SRL => b >> (c & 0x3f),
                        Opcode::SRA => ((b as i64) >> (c & 0x3f)) as u64,
                        Opcode::SRLW => ((b as u32) >> (c & 0x1f)) as u64,
                        _ => (((b as i32) >> (c & 0x1f)) as i64) as u64,
                    };
                    let alu = AluEvent::new(
                        (i as u64) * 8 + 8,
                        (i as u64) * 4 + 4,
                        opcode,
                        a,
                        b,
                        c,
                        false,
                    );
                    let imm = i % 3 == 0;
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
                shift_right_events: shift_right_events.clone(),
                ..Default::default()
            });

            let chip = ShiftRightChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let gpu_trace = chip
                .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&trace, &gpu_trace, &shift_right_events);
        })
        .await
        .unwrap();
    }
}
