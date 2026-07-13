//! Device main-trace + byte-lookup generation for the `MemoryLocal` chip (local
//! memory consistency table). One entry per row
//! (`NUM_LOCAL_MEMORY_ENTRIES_PER_ROW == 1`, so `SingleMemoryLocal` IS the row),
//! zero padding. Like the Syscall tables, host `generate_dependencies` ALSO emits
//! `GlobalInteractionEvent`s per event — those cannot be produced on device, so
//! the prover keeps them on host via `generate_global_dependencies` while the
//! byte lookups fuse into the main-trace kernel here (the witgen op-DAG already
//! records them; `memory_local_lookups_match_generate_dependencies` is the
//! parity proof).

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::events::MemoryLocalEvent;
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    memory::{MemoryLocalChip, SingleMemoryLocal, NUM_MEMORY_LOCAL_INIT_COLS},
};
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per `MemoryLocal` row (see [`SingleMemoryLocal::witgen`]).
const NUM_MEMORY_LOCAL_INPUTS: usize = 5;

pub(crate) fn pack_memory_local_inputs(events: &[&MemoryLocalEvent]) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_MEMORY_LOCAL_INPUTS];
    inputs.par_chunks_mut(NUM_MEMORY_LOCAL_INPUTS).zip(events.par_iter()).for_each(|(slot, e)| {
        slot.copy_from_slice(&[
            e.addr,
            e.initial_mem_access.timestamp,
            e.initial_mem_access.value,
            e.final_mem_access.timestamp,
            e.final_mem_access.value,
        ]);
    });
    inputs
}

pub(crate) fn record_memory_local_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_MEMORY_LOCAL_INPUTS as u32);
    let mut cols_w = SingleMemoryLocal::<WireId>::default();
    let w = |i: u32| RecordingWitnessBuilder::input(i);
    SingleMemoryLocal::<WireId>::witgen(&mut rec, &mut cols_w, w(0), w(1), w(2), w(3), w(4));
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "MemoryLocal gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

/// The chip's cached [`WitgenChip`] descriptor: recorded + lowered ONCE per
/// process (the program is shard-independent), not per shard.
fn memory_local_witgen_chip() -> &'static super::WitgenChip {
    static CHIP: std::sync::OnceLock<super::WitgenChip> = std::sync::OnceLock::new();
    CHIP.get_or_init(|| {
        let (program, col_wires) = record_memory_local_program();
        super::WitgenChip::new(program, col_wires)
    })
}

impl CudaTracegenAir<F> for MemoryLocalChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    // `supports_device_dependencies` (byte lookups fused on device) is decided at
    // the `RiscvAir` level; the `GlobalInteractionEvent`s (memory init receive +
    // finalize send) stay on host via `generate_global_dependencies`.

    async fn generate_trace_device_with_lookups(
        &self,
        input: &Self::Record,
        inputs: Vec<u64>,
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        // Fused: one op-DAG pass writes the columns AND accumulates this chip's
        // byte/range lookups into the shared shard histograms.
        let chip = memory_local_witgen_chip();
        debug_assert_eq!(chip.n_cols(), NUM_MEMORY_LOCAL_INIT_COLS);
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

    async fn generate_device_dependencies(
        &self,
        input: &Self::Record,
        range_dev: &mut DeviceBuffer<u32>,
        byte_dev: &mut DeviceBuffer<u32>,
        scope: &TaskScope,
    ) -> Result<(), CopyError> {
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events: Vec<&MemoryLocalEvent> = input.get_local_mem_events().collect();
        let n_events = if height == 0 { 0 } else { events.len() };
        if n_events == 0 {
            return Ok(());
        }
        let inputs = pack_memory_local_inputs(&events[..n_events]);
        super::accumulate_lookups(
            memory_local_witgen_chip(),
            &inputs,
            n_events,
            range_dev,
            byte_dev,
            scope,
        )
        .await
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        // The chip's cached descriptor: recorded + lowered once per process.
        let chip = memory_local_witgen_chip();
        let ops_c = chip.ssa();
        let n_cols = chip.n_cols();
        debug_assert_eq!(n_cols, NUM_MEMORY_LOCAL_INIT_COLS);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events: Vec<&MemoryLocalEvent> = input.get_local_mem_events().collect();
        let n_events = if height == 0 { 0 } else { events.len() };
        let inputs = pack_memory_local_inputs(&events[..n_events]);

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
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core_executor::events::{MemoryLocalEvent, MemoryRecord};
    use sp1_core_executor::{ByteOpcode, ExecutionRecord};
    use sp1_core_machine::air::{
        interpret_c_columns, interpret_c_lookups, BYTE_HIST_ROWS, RANGE_HIST_ROWS,
    };
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    use sp1_core_machine::memory::{MemoryLocalChip, NUM_MEMORY_LOCAL_INIT_COLS};
    use sp1_hypercube::air::MachineAir;

    use crate::F;

    fn synth_events(n: usize, seed: u64) -> Vec<MemoryLocalEvent> {
        let mut rng = StdRng::seed_from_u64(seed);
        (0..n)
            .map(|_| {
                let initial_ts = rng.gen::<u64>() & 0xFF_FFFF_FFFF;
                MemoryLocalEvent {
                    addr: rng.gen::<u64>() & 0xFFFF_FFFF_FFFF,
                    initial_mem_access: MemoryRecord {
                        timestamp: initial_ts,
                        value: rng.gen::<u64>(),
                    },
                    final_mem_access: MemoryRecord {
                        timestamp: initial_ts + 1 + (rng.gen::<u64>() & 0xFFFF),
                        value: rng.gen::<u64>(),
                    },
                }
            })
            .collect()
    }

    #[test]
    fn memory_local_columns_match_host() {
        let events = synth_events(300, 0x10CA1);
        let shard =
            ExecutionRecord { cpu_local_memory_access: events.clone(), ..Default::default() };
        let chip = MemoryLocalChip::new();
        let trace = MachineAir::<F>::generate_trace(&chip, &shard, &mut ExecutionRecord::default());
        let width = NUM_MEMORY_LOCAL_INIT_COLS;

        let (program, col_wires) = super::record_memory_local_program();
        let (_, max_slots) = program.allocate_slots(&col_wires);
        eprintln!(
            "MemoryLocal: num_wires={} max_slots={max_slots} n_cols={}",
            program.num_wires(),
            col_wires.len()
        );
        let ops_c = program.to_c();
        let evrefs: Vec<&MemoryLocalEvent> = events.iter().collect();
        let inputs = super::pack_memory_local_inputs(&evrefs);
        let ni = super::NUM_MEMORY_LOCAL_INPUTS;
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

    /// Byte-lookup histogram vs `generate_dependencies` (byte_lookups ONLY — the
    /// global interaction events this chip also emits are out of the device model's
    /// scope and stay on host).
    #[test]
    fn memory_local_lookups_match_generate_dependencies() {
        let events = synth_events(300, 0x10CA2);
        let shard =
            ExecutionRecord { cpu_local_memory_access: events.clone(), ..Default::default() };
        let chip = MemoryLocalChip::new();

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

        let (program, _col_wires) = super::record_memory_local_program();
        let ops_c = program.to_c();
        let evrefs: Vec<&MemoryLocalEvent> = events.iter().collect();
        let inputs = super::pack_memory_local_inputs(&evrefs);
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

    /// The FUSED production entry point (`generate_trace_device_with_lookups`) must
    /// produce columns identical to the CPU trace AND a histogram identical to the
    /// standalone lookup pass (`generate_device_dependencies`) — the device leg of
    /// the globals-on-host split (the host leg is covered by the core machine's
    /// `global_dependencies_are_the_global_subset` test).
    #[tokio::test]
    async fn test_memory_local_fused_kernel() {
        use crate::CudaTracegenAir;
        use slop_tensor::Tensor;
        use sp1_core_machine::memory::MemoryLocalChip;
        use sp1_gpu_cudart::TaskScope;
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let events = synth_events(300, 0x10CA3);
            let shard =
                ExecutionRecord { cpu_local_memory_access: events.clone(), ..Default::default() };
            let chip = MemoryLocalChip::new();
            let cpu_trace = Tensor::<F>::from(MachineAir::<F>::generate_trace(
                &chip,
                &shard,
                &mut ExecutionRecord::default(),
            ));

            // Reference histogram via the standalone lookup pass.
            let (mut r_ref, mut b_ref) = crate::new_byte_histograms(&scope);
            chip.generate_device_dependencies(&shard, &mut r_ref, &mut b_ref, &scope)
                .await
                .unwrap();
            let r_ref_h: Vec<u32> = r_ref.to_host().unwrap();
            let b_ref_h: Vec<u32> = b_ref.to_host().unwrap();

            // Fused: the production entry point, inputs packed as the prover packs them.
            let evrefs: Vec<&MemoryLocalEvent> = shard.get_local_mem_events().collect();
            let packed = super::pack_memory_local_inputs(&evrefs);
            let (r_f, b_f) = crate::new_byte_histograms(&scope);
            let hist = crate::LookupHist {
                range: r_f.as_ptr() as *mut u32,
                byte: b_f.as_ptr() as *mut u32,
            };
            let fused_trace = chip
                .generate_trace_device_with_lookups(&shard, packed, hist, &scope)
                .await
                .expect("fused tracegen should succeed")
                .to_host()
                .expect("copy fused trace to host")
                .into_guts();
            let r_f_h: Vec<u32> = r_f.to_host().unwrap();
            let b_f_h: Vec<u32> = b_f.to_host().unwrap();

            crate::tests::test_traces_eq(&cpu_trace, &fused_trace, &events);
            assert_eq!(r_f_h, r_ref_h, "fused range histogram must match the lookup pass");
            assert_eq!(b_f_h, b_ref_h, "fused byte histogram must match the lookup pass");
        })
        .await
        .unwrap();
    }
}
