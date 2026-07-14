//! Device main-trace + dependency generation for the `MemoryBump` chip (register
//! timestamp refresh rows). Narrow chip, zero padding, byte-lookup-only
//! dependencies — full fused device path like the ALU chips.

use core::borrow::BorrowMut;

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::events::MemoryRecordEnum;
use sp1_core_machine::{
    air::{columns_as_wires, record_witgen_inputs, WireId},
    memory::{
        MemoryAccessWitgenInput, MemoryBumpChip, MemoryBumpCols, MemoryBumpWitgenInput,
        NUM_MEMORY_BUMP_COLS, NUM_MEMORY_BUMP_WITGEN_INPUTS,
    },
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Pack each `(record, addr, is_refresh)` bump-memory event into one
/// [`MemoryBumpWitgenInput`] row (the access carries the RAW current timestamp —
/// the witgen truncates it on non-refresh rows).
pub(crate) fn pack_memory_bump_inputs(events: &[(MemoryRecordEnum, u64, bool)]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_MEMORY_BUMP_WITGEN_INPUTS];
    inputs.par_chunks_mut(NUM_MEMORY_BUMP_WITGEN_INPUTS).zip(events.par_iter()).for_each(
        |(chunk, &(event, addr, is_refresh))| {
            let slot: &mut MemoryBumpWitgenInput<u64> = chunk.borrow_mut();
            slot.access = MemoryAccessWitgenInput::from_record(event);
            slot.is_refresh = is_refresh as u64;
            slot.addr = addr;
        },
    );
    inputs
}

pub(crate) fn record_memory_bump_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let (mut rec, input) = record_witgen_inputs::<MemoryBumpWitgenInput<WireId>>();
    let mut cols_w = MemoryBumpCols::<WireId>::default();
    MemoryBumpCols::<WireId>::witgen(&mut rec, &mut cols_w, &input);
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

/// The chip's cached [`WitgenChip`] descriptor: recorded + lowered ONCE per
/// process (the program is shard-independent), not per shard.
pub(crate) fn memory_bump_witgen_chip() -> &'static super::WitgenChip {
    static CHIP: std::sync::OnceLock<super::WitgenChip> = std::sync::OnceLock::new();
    CHIP.get_or_init(|| {
        let (program, col_wires) = record_memory_bump_program();
        super::WitgenChip::new(program, col_wires)
    })
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
        // The chip's cached descriptor: recorded + lowered once per process.
        let chip = memory_bump_witgen_chip();
        let ops_c = chip.ssa();
        let n_cols = chip.n_cols();
        debug_assert_eq!(n_cols, NUM_MEMORY_BUMP_COLS);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.bump_memory_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        let inputs = pack_memory_bump_inputs(&events[..n_events]);

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
        let chip = memory_bump_witgen_chip();
        debug_assert_eq!(chip.n_cols(), NUM_MEMORY_BUMP_COLS);
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
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = &input.bump_memory_events;
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }
        let inputs = pack_memory_bump_inputs(&events[..n_events]);
        super::accumulate_lookups(
            memory_bump_witgen_chip(),
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
    use sp1_core_executor::events::{MemoryReadRecord, MemoryRecordEnum};
    use sp1_core_executor::{ByteOpcode, ExecutionRecord};
    use sp1_core_machine::air::{
        interpret_c_columns, interpret_c_lookups, BYTE_HIST_ROWS, RANGE_HIST_ROWS,
    };
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    use sp1_core_machine::memory::{MemoryBumpChip, NUM_MEMORY_BUMP_COLS};
    use sp1_gpu_cudart::TaskScope;
    use sp1_hypercube::air::MachineAir;

    use crate::{CudaTracegenAir, F};

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
        let ni = sp1_core_machine::memory::NUM_MEMORY_BUMP_WITGEN_INPUTS;
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
    /// above only exercise the interpreters). Reuses `synth_events` (half refresh,
    /// half truncated rows); 300 events is not a power of two, so the zero padding
    /// rows are exercised too.
    #[tokio::test]
    async fn test_memory_bump_generate_trace_device() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let events = synth_events(300, 0xB0B2);
            let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
                bump_memory_events: events.clone(),
                ..Default::default()
            });

            let chip = MemoryBumpChip::new();

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

    /// FUSED kernel — the path production dispatch actually takes for this chip
    /// (`supports_device_dependencies` routes it through
    /// `generate_trace_device_with_lookups`, NOT the non-fused SSA kernel the test
    /// above covers): columns must equal host `generate_trace` AND the fused
    /// histograms must equal the standalone lookup kernel's reference.
    #[tokio::test]
    async fn test_memory_bump_fused_kernel() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let events = synth_events(300, 0xB0B3);
            let shard =
                ExecutionRecord { bump_memory_events: events.clone(), ..Default::default() };
            let chip = MemoryBumpChip::new();

            let cpu_trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));

            let inputs = super::pack_memory_bump_inputs(&events);
            let n_events = events.len();

            // Reference histograms from the standalone lookup kernel.
            let (mut r_ref, mut b_ref) = crate::new_byte_histograms(&scope);
            crate::riscv::accumulate_lookups(
                super::memory_bump_witgen_chip(),
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
                .generate_trace_device_with_lookups(&shard, &inputs, hist, &scope)
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
