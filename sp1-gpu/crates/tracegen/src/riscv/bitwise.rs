//! Device main-trace + dependency generation for the trusted `Bitwise` chip (AND/OR/
//! XOR). The FIRST mixed chip on the device path: it exercises all three conditional-
//! execution primitives — per-row `imm_c` (register vs immediate `op_c`, via guard +
//! field_select in `ALUTypeReader::witgen`), per-row `byte_opcode` (via the generic
//! byte-table lookup), and the `is_xor/is_or/is_and` selectors.

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::{
    events::{AluEvent, ByteRecord},
    ALUTypeRecord, ByteOpcode,
};
use sp1_core_machine::{
    air::{
        byte_lookups_from_histograms, columns_as_wires, RecordingWitnessBuilder, WireId,
        BYTE_HIST_ROWS, RANGE_HIST_ROWS,
    },
    alu::bitwise::{BitwiseChip, BitwiseCols, NUM_BITWISE_COLS_SUPERVISOR},
    bytes::columns::NUM_BYTE_MULT_COLS,
    SupervisorMode,
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `Bitwise` row (see [`BitwiseCols::witgen`]).
const NUM_BITWISE_INPUTS: usize = 19;

/// Pack each event's witgen inputs in `BitwiseCols::witgen` order. `op_c` may be an
/// immediate (no register read): on those rows the `c` memory fields are unused
/// (any value), so we pack zeros.
fn pack_bitwise_inputs(events: &[(AluEvent, ALUTypeRecord)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_BITWISE_INPUTS];
    inputs.par_chunks_mut(NUM_BITWISE_INPUTS).zip(events.par_iter()).for_each(|(slot, (alu, r))| {
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
            alu.a, // result operand
            alu.b,
            alu.c,
            ByteOpcode::from(alu.opcode) as u64, // byte_opcode (AND=0/OR=1/XOR=2)
            r.c.is_none() as u64,                // imm_c
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

/// Record the `Bitwise` chip's witgen op-DAG (row-independent) + the column→wire map.
fn record_bitwise_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_BITWISE_INPUTS as u32);
    let mut cols_w = BitwiseCols::<WireId, SupervisorMode>::default();
    let w = |i: u32| RecordingWitnessBuilder::input(i);
    BitwiseCols::<WireId, SupervisorMode>::witgen(
        &mut rec, &mut cols_w, w(0), w(1), w(2), w(3), w(4), w(5), w(6), w(7), w(8), w(9), w(10),
        w(11), w(12), w(13), w(14), w(15), w(16), w(17), w(18),
    );
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "Bitwise gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

impl CudaTracegenAir<F> for BitwiseChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_bitwise_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_BITWISE_COLS_SUPERVISOR);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.bitwise_events;
        let n_events = if height == 0 { 0 } else { events.len() };

        let inputs = pack_bitwise_inputs(&events[..n_events]);

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
        output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<(), CopyError> {
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.bitwise_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }

        let (program, _col_wires) = record_bitwise_program();
        let ops_c = program.to_c();
        let inputs = pack_bitwise_inputs(&events[..n_events]);

        let mut ops_dev = Buffer::try_with_capacity_in(ops_c.len(), scope.clone()).unwrap();
        ops_dev.extend_from_host_slice(&ops_c)?;
        let mut in_dev = Buffer::try_with_capacity_in(inputs.len(), scope.clone()).unwrap();
        in_dev.extend_from_host_slice(&inputs)?;

        let range_len = RANGE_HIST_ROWS;
        let byte_len = BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS;
        let mut range_buf = Buffer::try_with_capacity_in(range_len, scope.clone()).unwrap();
        range_buf.extend_from_host_slice(&vec![0u32; range_len])?;
        let mut byte_buf = Buffer::try_with_capacity_in(byte_len, scope.clone()).unwrap();
        byte_buf.extend_from_host_slice(&vec![0u32; byte_len])?;
        let mut range_dev = DeviceBuffer::from_raw(range_buf);
        let mut byte_dev = DeviceBuffer::from_raw(byte_buf);

        unsafe {
            const BLOCK: usize = 64;
            let grid = n_events.div_ceil(BLOCK);
            let args = args!(
                ops_dev.as_ptr(),
                ops_c.len(),
                program.num_inputs,
                in_dev.as_ptr(),
                n_events,
                range_dev.as_mut_ptr(),
                byte_dev.as_mut_ptr()
            );
            scope
                .launch_kernel(TaskScope::witgen_lookup_kernel(), grid, BLOCK, &args, 0)
                .unwrap();
        }

        let range_hist: Vec<u32> = range_dev.to_host()?;
        let byte_hist: Vec<u32> = byte_dev.to_host()?;
        let map = byte_lookups_from_histograms(&range_hist, &byte_hist);
        output.add_byte_lookup_events_from_maps(vec![&map]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::events::{AluEvent, MemoryReadRecord, MemoryRecordEnum};
    use sp1_core_executor::{ALUTypeRecord, ExecutionRecord, Opcode};
    use sp1_core_machine::alu::bitwise::BitwiseChip;
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

    /// Device-vs-CPU trace equality for the `Bitwise` chip over MIXED register/
    /// immediate events and all three opcodes — exercises guard + field_select
    /// (imm_c) and the per-row byte-table lookup end-to-end in a real chip.
    #[tokio::test]
    async fn test_bitwise_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let mut rng = StdRng::seed_from_u64(0xB17);
            let bitwise_events = (0..1000)
                .map(|i| {
                    let opcode = [Opcode::XOR, Opcode::OR, Opcode::AND][i % 3];
                    let b = rng.gen::<u64>();
                    let c = rng.gen::<u64>();
                    let a = match opcode {
                        Opcode::XOR => b ^ c,
                        Opcode::OR => b | c,
                        _ => b & c,
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
                    // Half the rows use an immediate op_c (no register read).
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
                bitwise_events: bitwise_events.clone(),
                ..Default::default()
            });

            let chip = BitwiseChip::<SupervisorMode>::default();

            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let gpu_trace = chip
                .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&trace, &gpu_trace, &bitwise_events);
        })
        .await
        .unwrap();
    }
}
