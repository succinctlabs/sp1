//! Device main-trace generation for `MemoryGlobalInit` / `MemoryGlobalFinalize`
//! (one `MemoryGlobalChip` type, two kinds). The chip's host tracegen is the ONLY
//! core tracegen with a sort + sequential-neighbor pass; the device port moves that
//! into PACKING (sort host-side, hand each row its `prev_addr` + `index`), making
//! rows independent for the one-thread-per-row kernel. IMPORTANT:
//! `generate_dependencies` also emits `GlobalInteractionEvent`s and bumps
//! `public_values.global_*_count`, so the DEVICE DEPENDENCY PATH MUST STAY OFF.

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::events::MemoryInitializeFinalizeEvent;
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId},
    memory::{MemoryChipType, MemoryGlobalChip, MemoryInitCols, NUM_MEMORY_INIT_COLS},
};
use sp1_gpu_cudart::{args, DeviceMle, TaskScope, WitgenInterpKernel};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per row (see [`MemoryInitCols::witgen`]).
const NUM_MEMORY_GLOBAL_INPUTS: usize = 5;

/// Pack the SORTED events: each row gets `[addr, value, timestamp, prev_addr,
/// index]`, where `prev_addr` is the previous sorted event's address (row 0: the
/// shard public value `previous_init/finalize_addr`) — the sequential-neighbor
/// dependency resolved at pack time.
pub(crate) fn pack_memory_global_inputs(
    sorted_events: &[MemoryInitializeFinalizeEvent],
    previous_addr: u64,
) -> Vec<u64> {
    let mut inputs: Vec<u64> = vec![0u64; sorted_events.len() * NUM_MEMORY_GLOBAL_INPUTS];
    inputs.par_chunks_mut(NUM_MEMORY_GLOBAL_INPUTS).enumerate().for_each(|(i, slot)| {
        let e = &sorted_events[i];
        let prev_addr = if i == 0 { previous_addr } else { sorted_events[i - 1].addr };
        slot.copy_from_slice(&[e.addr, e.value, e.timestamp, prev_addr, i as u64]);
    });
    inputs
}

pub(crate) fn record_memory_global_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_MEMORY_GLOBAL_INPUTS as u32);
    let mut cols_w = MemoryInitCols::<WireId>::default();
    let w = |i: u32| RecordingWitnessBuilder::input(i);
    MemoryInitCols::<WireId>::witgen(&mut rec, &mut cols_w, w(0), w(1), w(2), w(3), w(4));
    let program = rec.finish();
    assert!(
        program.num_wires() <= super::WITGEN_MAX_WIRES,
        "MemoryGlobal gadget needs {} wires > kernel capacity {}",
        program.num_wires(),
        super::WITGEN_MAX_WIRES
    );
    let col_wires: Vec<u32> = columns_as_wires(&cols_w).iter().map(|w| w.0).collect();
    (program, col_wires)
}

/// The chip's sorted event list + row-0 previous address for one shard.
fn sorted_events_and_prev(
    input: &sp1_core_executor::ExecutionRecord,
    kind: MemoryChipType,
) -> (Vec<MemoryInitializeFinalizeEvent>, u64) {
    let (events, previous_addr) = match kind {
        MemoryChipType::Initialize => {
            (input.global_memory_initialize_events.clone(), input.public_values.previous_init_addr)
        }
        MemoryChipType::Finalize => (
            input.global_memory_finalize_events.clone(),
            input.public_values.previous_finalize_addr,
        ),
    };
    let mut events = events;
    events.sort_by_key(|event| event.addr);
    (events, previous_addr)
}

impl CudaTracegenAir<F> for MemoryGlobalChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    // NO `supports_device_dependencies`: `generate_dependencies` emits
    // `GlobalInteractionEvent`s + public-value count bumps; dependencies stay host.

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_memory_global_program();
        let ops_c = program.to_c();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_MEMORY_INIT_COLS);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let (events, previous_addr) = sorted_events_and_prev(input, self.kind);
        let n_events = if height == 0 { 0 } else { events.len() };
        let inputs = pack_memory_global_inputs(&events[..n_events], previous_addr);

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
    use sp1_core_executor::events::MemoryInitializeFinalizeEvent;
    use sp1_core_executor::{ByteOpcode, ExecutionRecord};
    use sp1_core_machine::air::{
        interpret_c_columns, interpret_c_lookups, BYTE_HIST_ROWS, RANGE_HIST_ROWS,
    };
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    use sp1_core_machine::memory::{MemoryChipType, MemoryGlobalChip, NUM_MEMORY_INIT_COLS};
    use sp1_hypercube::air::MachineAir;

    use crate::F;

    /// Strictly-increasing distinct addresses (the sorted-unique invariant the chip
    /// asserts via `prev_addr < addr`); the FIRST event is address 0 so row 0
    /// exercises the non-comparison path (`prev_addr == 0 && index == 0`) and row 1
    /// exercises `prev_valid == 0` (`prev_addr == 0 && index != 0`).
    fn synth_shard(n: usize, seed: u64) -> ExecutionRecord {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut addr = 0u64;
        let events: Vec<MemoryInitializeFinalizeEvent> = (0..n)
            .map(|i| {
                let e = MemoryInitializeFinalizeEvent {
                    addr,
                    // Address 0 must hold value 0 (chip constraint on row 0).
                    value: if i == 0 { 0 } else { rng.gen::<u64>() },
                    timestamp: rng.gen::<u64>() & 0xFF_FFFF_FFFF,
                };
                addr += 1 + (rng.gen::<u64>() & 0xFFFF_FFFF);
                e
            })
            .collect();
        ExecutionRecord { global_memory_initialize_events: events, ..Default::default() }
    }

    #[test]
    fn memory_global_columns_match_host() {
        let shard = synth_shard(300, 0x91060);
        let chip = MemoryGlobalChip::new(MemoryChipType::Initialize);
        let trace = MachineAir::<F>::generate_trace(&chip, &shard, &mut ExecutionRecord::default());
        let width = NUM_MEMORY_INIT_COLS;

        let (program, col_wires) = super::record_memory_global_program();
        let (_, max_slots) = program.allocate_slots(&col_wires);
        eprintln!(
            "MemoryGlobal: num_wires={} max_slots={max_slots} n_cols={}",
            program.num_wires(),
            col_wires.len()
        );
        let ops_c = program.to_c();
        let (events, prev) = super::sorted_events_and_prev(&shard, MemoryChipType::Initialize);
        let inputs = super::pack_memory_global_inputs(&events, prev);
        let ni = super::NUM_MEMORY_GLOBAL_INPUTS;
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

    /// Byte-lookup histogram vs `generate_dependencies` byte_lookups (the global
    /// interaction events + public-value count bumps this chip also produces are
    /// out of the device model's scope; deps stay host).
    #[test]
    fn memory_global_lookups_match_generate_dependencies() {
        let shard = synth_shard(300, 0x91061);
        let chip = MemoryGlobalChip::new(MemoryChipType::Initialize);

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

        let (program, _col_wires) = super::record_memory_global_program();
        let ops_c = program.to_c();
        let (events, prev) = super::sorted_events_and_prev(&shard, MemoryChipType::Initialize);
        let inputs = super::pack_memory_global_inputs(&events, prev);
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
