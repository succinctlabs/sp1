//! Device main-trace + dependency generation for the `StateBump` chip (clk/pc
//! canonicalization rows). Narrow chip (16 cols), zero padding, byte-lookup-only
//! dependencies — full fused device path like the ALU chips.

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_machine::{
    adapter::bump::{StateBumpChip, StateBumpCols, NUM_STATE_BUMP_COLS},
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `StateBump` row (see [`StateBumpCols::witgen`]).
const NUM_STATE_BUMP_INPUTS: usize = 4;

/// Pack each `(clk, increment, bump2, pc)` bump-state event.
pub(crate) fn pack_state_bump_inputs(events: &[(u64, u64, bool, u64)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_STATE_BUMP_INPUTS];
    inputs.par_chunks_mut(NUM_STATE_BUMP_INPUTS).zip(events.par_iter()).for_each(
        |(slot, &(clk, increment, bump2, pc))| {
            slot.copy_from_slice(&[clk, increment, bump2 as u64, pc]);
        },
    );
    inputs
}

pub(crate) fn record_state_bump_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_STATE_BUMP_INPUTS as u32);
    let mut cols_w = StateBumpCols::<WireId>::default();
    let w = |i: u32| RecordingWitnessBuilder::input(i);
    StateBumpCols::<WireId>::witgen(&mut rec, &mut cols_w, w(0), w(1), w(2), w(3));
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "StateBump gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

impl CudaTracegenAir<F> for StateBumpChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_state_bump_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_STATE_BUMP_COLS);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.bump_state_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        let inputs = pack_state_bump_inputs(&events[..n_events]);

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
        let (program, col_wires) = record_state_bump_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_STATE_BUMP_COLS);
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
        let events = &input.bump_state_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }
        let (program, _col_wires) = record_state_bump_program();
        let inputs = pack_state_bump_inputs(&events[..n_events]);
        super::accumulate_lookups(&program, &inputs, n_events, range_dev, byte_dev, scope).await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core_executor::{ByteOpcode, ExecutionRecord};
    use sp1_core_machine::adapter::bump::{StateBumpChip, NUM_STATE_BUMP_COLS};
    use sp1_core_machine::air::{
        interpret_c_columns, interpret_c_lookups, BYTE_HIST_ROWS, RANGE_HIST_ROWS,
    };
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    use sp1_hypercube::air::MachineAir;

    use crate::F;

    /// clk values are `1 (mod 8)` (executor invariant relied on by the
    /// `(clk_0_16 - 1)/8` canonicity check); increments are multiples of 8; pc is a
    /// 48-bit-aligned address; ~half the rows have `bump2` set and ~1/5 carry
    /// across the 24-bit clk boundary.
    fn synth_events(n: usize, seed: u64) -> Vec<(u64, u64, bool, u64)> {
        let mut rng = StdRng::seed_from_u64(seed);
        (0..n)
            .map(|i| {
                let clk = (rng.gen::<u64>() & 0x00FF_FFFF_FFFF) * 8 + 1;
                let increment = if i % 5 == 0 {
                    // Force a 24-bit carry, keeping increment ≡ 0 (mod 8) so
                    // next_clk stays ≡ 1 (mod 8) (the executor invariant).
                    let base = (1u64 << 24) - (clk & 0xFF_FFFF);
                    base.div_ceil(8) * 8 + 8 * (i as u64 % 7)
                } else {
                    8 * (1 + (rng.gen::<u64>() & 0xFF))
                };
                let bump2 = i % 2 == 0;
                let pc = (rng.gen::<u64>() & 0xFFFF_FFFF_FFFF) & !3;
                (clk, increment, bump2, pc)
            })
            .collect()
    }

    #[test]
    fn state_bump_columns_match_host() {
        let events = synth_events(300, 0x57A7E);
        let shard = ExecutionRecord { bump_state_events: events.clone(), ..Default::default() };
        let chip = StateBumpChip::new();
        let trace = MachineAir::<F>::generate_trace(&chip, &shard, &mut ExecutionRecord::default());
        let width = NUM_STATE_BUMP_COLS;

        let (program, col_wires) = super::record_state_bump_program();
        let (_, max_slots) = program.allocate_slots(&col_wires);
        eprintln!(
            "StateBump: num_wires={} max_slots={max_slots} n_cols={}",
            program.num_wires(),
            col_wires.len()
        );
        let ops_c = program.to_c();
        let inputs = super::pack_state_bump_inputs(&events);
        let ni = super::NUM_STATE_BUMP_INPUTS;
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
    fn state_bump_lookups_match_generate_dependencies() {
        let events = synth_events(300, 0x57A7F);
        let shard = ExecutionRecord { bump_state_events: events.clone(), ..Default::default() };
        let chip = StateBumpChip::new();

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

        let (program, _col_wires) = super::record_state_bump_program();
        let ops_c = program.to_c();
        let inputs = super::pack_state_bump_inputs(&events);
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
