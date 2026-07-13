//! Device main-trace + dependency generation for the `StateBump` chip (clk/pc
//! canonicalization rows). Narrow chip (16 cols), zero padding, byte-lookup-only
//! dependencies — full fused device path like the ALU chips.

use core::borrow::BorrowMut;

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_machine::{
    adapter::bump::{
        StateBumpChip, StateBumpCols, StateBumpWitgenInput, NUM_STATE_BUMP_COLS,
        NUM_STATE_BUMP_WITGEN_INPUTS,
    },
    air::{columns_as_wires, record_witgen_inputs, WireId},
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Pack each `(clk, increment, bump2, pc)` bump-state event into one
/// [`StateBumpWitgenInput`] row.
pub(crate) fn pack_state_bump_inputs(events: &[(u64, u64, bool, u64)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_STATE_BUMP_WITGEN_INPUTS];
    inputs.par_chunks_mut(NUM_STATE_BUMP_WITGEN_INPUTS).zip(events.par_iter()).for_each(
        |(chunk, &(clk, increment, bump2, pc))| {
            let slot: &mut StateBumpWitgenInput<u64> = chunk.borrow_mut();
            slot.clk = clk;
            slot.increment = increment;
            slot.bump2 = bump2 as u64;
            slot.pc = pc;
        },
    );
    inputs
}

pub(crate) fn record_state_bump_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let (mut rec, input) = record_witgen_inputs::<StateBumpWitgenInput<WireId>>();
    let mut cols_w = StateBumpCols::<WireId>::default();
    StateBumpCols::<WireId>::witgen(&mut rec, &mut cols_w, &input);
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

/// The chip's cached [`WitgenChip`] descriptor: recorded + lowered ONCE per
/// process (the program is shard-independent), not per shard.
fn state_bump_witgen_chip() -> &'static super::WitgenChip {
    static CHIP: std::sync::OnceLock<super::WitgenChip> = std::sync::OnceLock::new();
    CHIP.get_or_init(|| {
        let (program, col_wires) = record_state_bump_program();
        super::WitgenChip::new(program, col_wires)
    })
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
        // The chip's cached descriptor: recorded + lowered once per process.
        let chip = state_bump_witgen_chip();
        let ops_c = chip.ssa();
        let n_cols = chip.n_cols();
        debug_assert_eq!(n_cols, NUM_STATE_BUMP_COLS);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.bump_state_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        let inputs = pack_state_bump_inputs(&events[..n_events]);

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
        inputs: Vec<u64>,
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let chip = state_bump_witgen_chip();
        debug_assert_eq!(chip.n_cols(), NUM_STATE_BUMP_COLS);
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let n_events =
            if height == 0 { 0 } else { inputs.len() / chip.program.num_inputs as usize };
        super::generate_trace_and_lookups(
            chip,
            super::WitgenBatch { inputs: &inputs, n_events, height },
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
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.bump_state_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }
        let inputs = pack_state_bump_inputs(&events[..n_events]);
        super::accumulate_lookups(
            state_bump_witgen_chip(),
            &inputs,
            n_events,
            range_dev,
            byte_dev,
            scope,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::{ByteOpcode, ExecutionRecord};
    use sp1_core_machine::adapter::bump::{StateBumpChip, NUM_STATE_BUMP_COLS};
    use sp1_core_machine::air::{
        interpret_c_columns, interpret_c_lookups, BYTE_HIST_ROWS, RANGE_HIST_ROWS,
    };
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    use sp1_gpu_cudart::TaskScope;
    use sp1_hypercube::air::MachineAir;

    use crate::{CudaTracegenAir, F};

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
        let ni = sp1_core_machine::adapter::bump::NUM_STATE_BUMP_WITGEN_INPUTS;
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

    /// Device-vs-CPU trace equality on the REAL GPU kernel (the CPU-model tests
    /// above only exercise the interpreters). 300 events is not a power of two, so
    /// the zero padding rows are exercised too.
    #[tokio::test]
    async fn test_state_bump_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let events = synth_events(300, 0x57A80);
            let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
                bump_state_events: events.clone(),
                ..Default::default()
            });

            let chip = StateBumpChip::new();

            let cpu_trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let device_trace = chip
                .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
                .await
                .expect("device tracegen should succeed")
                .to_host()
                .expect("copy trace to host")
                .into_guts();

            crate::tests::test_traces_eq(&cpu_trace, &device_trace, &events);
        })
        .await
        .unwrap();
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

    /// FUSED kernel — the path production dispatch actually takes for this chip
    /// (`supports_device_dependencies` routes it through
    /// `generate_trace_device_with_lookups`, NOT the non-fused SSA kernel the test
    /// above covers): columns must equal host `generate_trace` AND the fused
    /// histograms must equal the standalone lookup kernel's reference.
    #[tokio::test]
    async fn test_state_bump_fused_kernel() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let events = synth_events(300, 0x57A82);
            let shard = ExecutionRecord { bump_state_events: events.clone(), ..Default::default() };
            let chip = StateBumpChip::new();

            let cpu_trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));

            let inputs = super::pack_state_bump_inputs(&events);
            let n_events = events.len();

            // Reference histograms from the standalone lookup kernel.
            let (mut r_ref, mut b_ref) = crate::new_byte_histograms(&scope);
            crate::riscv::accumulate_lookups(
                super::state_bump_witgen_chip(),
                &inputs,
                n_events,
                &mut r_ref,
                &mut b_ref,
                &scope,
            )
            .await
            .unwrap();
            let r_ref_h: Vec<u32> = r_ref.to_host().unwrap();
            let b_ref_h: Vec<u32> = b_ref.to_host().unwrap();

            // Fused: columns + histograms in one op-DAG pass via the trait method.
            let (r_f, b_f) = crate::new_byte_histograms(&scope);
            let hist = crate::LookupHist {
                range: r_f.as_ptr() as *mut u32,
                byte: b_f.as_ptr() as *mut u32,
            };
            let fused_trace = chip
                .generate_trace_device_with_lookups(&shard, inputs, hist, &scope)
                .await
                .expect("fused tracegen should succeed")
                .to_host()
                .expect("copy fused trace to host")
                .into_guts();
            let r_f_h: Vec<u32> = r_f.to_host().unwrap();
            let b_f_h: Vec<u32> = b_f.to_host().unwrap();

            crate::tests::test_traces_eq(&cpu_trace, &fused_trace, &events);
            assert_eq!(r_f_h, r_ref_h, "fused range histogram must match the lookup kernel");
            assert_eq!(b_f_h, b_ref_h, "fused byte histogram must match the lookup kernel");
        })
        .await
        .unwrap();
    }
}
