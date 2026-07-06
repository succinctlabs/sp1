//! Device main-trace + dependency generation for the `MemoryBump` chip (register
//! timestamp refresh rows). Narrow chip, zero padding, byte-lookup-only
//! dependencies — full fused device path like the ALU chips.

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::events::MemoryRecordEnum;
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    memory::{MemoryBumpChip, MemoryBumpCols, NUM_MEMORY_BUMP_COLS},
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `MemoryBump` row (see [`MemoryBumpCols::witgen`]).
const NUM_MEMORY_BUMP_INPUTS: usize = 5;

/// Pack each `(record, addr, is_refresh)` bump-memory event.
pub(crate) fn pack_memory_bump_inputs(events: &[(MemoryRecordEnum, u64, bool)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_MEMORY_BUMP_INPUTS];
    inputs.par_chunks_mut(NUM_MEMORY_BUMP_INPUTS).zip(events.par_iter()).for_each(
        |(slot, &(event, addr, is_refresh))| {
            slot.copy_from_slice(&[
                event.prev_value(),
                event.previous_record().timestamp,
                event.current_record().timestamp,
                is_refresh as u64,
                addr,
            ]);
        },
    );
    inputs
}

pub(crate) fn record_memory_bump_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_MEMORY_BUMP_INPUTS as u32);
    let mut cols_w = MemoryBumpCols::<WireId>::default();
    let w = |i: u32| RecordingWitnessBuilder::input(i);
    MemoryBumpCols::<WireId>::witgen(&mut rec, &mut cols_w, w(0), w(1), w(2), w(3), w(4));
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "MemoryBump gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

impl CudaTracegenAir<F> for MemoryBumpChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_memory_bump_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_MEMORY_BUMP_COLS);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.bump_memory_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        let inputs = pack_memory_bump_inputs(&events[..n_events]);

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
        let (program, col_wires) = record_memory_bump_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_MEMORY_BUMP_COLS);
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
        let events = &input.bump_memory_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }
        let (program, _col_wires) = record_memory_bump_program();
        let inputs = pack_memory_bump_inputs(&events[..n_events]);
        super::accumulate_lookups(&program, &inputs, n_events, range_dev, byte_dev, scope).await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core_executor::events::{MemoryReadRecord, MemoryRecordEnum};
    use sp1_core_executor::{ByteOpcode, ExecutionRecord};
    use sp1_core_machine::air::{
        interpret_c_columns, interpret_c_lookups, BYTE_HIST_ROWS, RANGE_HIST_ROWS,
    };
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    use sp1_core_machine::memory::{MemoryBumpChip, NUM_MEMORY_BUMP_COLS};
    use sp1_hypercube::air::MachineAir;

    use crate::F;

    /// Bump events: half refresh (raw timestamp), half top-truncated. The truncated
    /// timestamp `(ts >> 24) << 24` must still EXCEED prev_timestamp (the timestamp
    /// gadget subtracts them), so prev is kept below `ts`'s 24-bit boundary.
    fn synth_events(n: usize, seed: u64) -> Vec<(MemoryRecordEnum, u64, bool)> {
        let mut rng = StdRng::seed_from_u64(seed);
        (0..n)
            .map(|i| {
                let is_refresh = i % 2 == 0;
                let hi = 1 + (rng.gen::<u64>() & 0xFFFF);
                let prev_timestamp = (hi - 1) << 24 | (rng.gen::<u64>() & 0xFF_FFFF);
                let timestamp = (hi << 24) | (rng.gen::<u64>() & 0xFF_FFFF);
                let record = MemoryRecordEnum::Read(MemoryReadRecord {
                    value: rng.gen::<u64>(),
                    timestamp,
                    prev_timestamp,
                    prev_page_prot_record: None,
                });
                (record, rng.gen_range(1..32u64), is_refresh)
            })
            .collect()
    }

    #[test]
    fn memory_bump_columns_match_host() {
        let events = synth_events(300, 0xB0B0);
        let shard = ExecutionRecord { bump_memory_events: events.clone(), ..Default::default() };
        let chip = MemoryBumpChip::new();
        let trace = MachineAir::<F>::generate_trace(&chip, &shard, &mut ExecutionRecord::default());
        let width = NUM_MEMORY_BUMP_COLS;

        let (program, col_wires) = super::record_memory_bump_program();
        let (_, max_slots) = program.allocate_slots(&col_wires);
        eprintln!(
            "MemoryBump: num_wires={} max_slots={max_slots} n_cols={}",
            program.num_wires(),
            col_wires.len()
        );
        let ops_c = program.to_c();
        let inputs = super::pack_memory_bump_inputs(&events);
        let ni = super::NUM_MEMORY_BUMP_INPUTS;
        for row in 0..events.len() {
            let row_in = &inputs[row * ni..(row + 1) * ni];
            let cols: Vec<F> = interpret_c_columns(&ops_c, ni as u32, row_in, &col_wires);
            assert_eq!(
                &trace.values[row * width..(row + 1) * width],
                &cols[..],
                "column mismatch at row {row}"
            );
        }
    }

    #[test]
    fn memory_bump_lookups_match_generate_dependencies() {
        let events = synth_events(300, 0xB0B1);
        let shard = ExecutionRecord { bump_memory_events: events.clone(), ..Default::default() };
        let chip = MemoryBumpChip::new();

        let mut dep_out = ExecutionRecord::default();
        MachineAir::<F>::generate_dependencies(&chip, &shard, &mut dep_out);
        let mut ref_range = vec![0u32; RANGE_HIST_ROWS];
        let mut ref_byte = vec![0u32; BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS];
        for (lookup, mult) in dep_out.byte_lookups.iter() {
            if lookup.opcode == ByteOpcode::Range {
                ref_range[(lookup.a as usize) + (1 << lookup.b)] = *mult as u32;
            } else {
                let r = ((lookup.b as usize) << 8) + lookup.c as usize;
                ref_byte[r * NUM_BYTE_MULT_COLS + lookup.opcode as usize] = *mult as u32;
            }
        }

        let (program, _col_wires) = super::record_memory_bump_program();
        let ops_c = program.to_c();
        let inputs = super::pack_memory_bump_inputs(&events);
        let mut range_hist = vec![0u32; RANGE_HIST_ROWS];
        let mut byte_hist = vec![0u32; BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS];
        interpret_c_lookups(
            &ops_c,
            program.num_inputs,
            &inputs,
            events.len(),
            &mut range_hist,
            &mut byte_hist,
        );
        assert_eq!(range_hist, ref_range, "range histogram mismatch");
        assert_eq!(byte_hist, ref_byte, "byte histogram mismatch");
    }
}
