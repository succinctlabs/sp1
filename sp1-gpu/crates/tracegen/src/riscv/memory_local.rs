//! Device main-trace generation for the `MemoryLocal` chip (local memory
//! consistency table). One entry per row (`NUM_LOCAL_MEMORY_ENTRIES_PER_ROW == 1`,
//! so `SingleMemoryLocal` IS the row), zero padding. IMPORTANT: like the Syscall
//! tables, `generate_dependencies` emits `GlobalInteractionEvent`s per event, so
//! the DEVICE DEPENDENCY PATH MUST STAY OFF — host `generate_dependencies` still
//! runs; only the main trace moves to device.

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::events::MemoryLocalEvent;
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    memory::{MemoryLocalChip, SingleMemoryLocal, NUM_MEMORY_LOCAL_INIT_COLS},
};
use sp1_gpu_cudart::{args, DeviceMle, TaskScope, WitgenInterpKernel};
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

impl CudaTracegenAir<F> for MemoryLocalChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    // NO `supports_device_dependencies`: `generate_dependencies` emits
    // `GlobalInteractionEvent`s (memory init receive + finalize send) that the
    // device byte-lookup path cannot produce; dependencies stay on host.

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_memory_local_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_MEMORY_LOCAL_INIT_COLS);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events: Vec<&MemoryLocalEvent> = input.get_local_mem_events().collect();
        let n_events = if height == 0 { 0 } else { events.len() };
        let inputs = pack_memory_local_inputs(&events[..n_events]);

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
        println!(
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
}
