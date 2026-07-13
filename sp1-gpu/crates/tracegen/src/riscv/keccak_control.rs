//! Device main-trace + dependency generation for the SUPERVISOR-mode
//! `KeccakPermuteControl` chip — the controller that receives the KECCAK_PERMUTE
//! syscall and holds the precompile's memory interactions: clk split +
//! `SyscallAddrOperation` on the state address + 25 `AddrAddOperation` word
//! addresses + 25 read / 25 write `MemoryAccessCols` + the 25 final-value words.
//! One row per KECCAK_PERMUTE event; padding rows are all-zero.
//!
//! Dependencies are byte/range lookups only (`generate_dependencies` populates the
//! same gadgets and collects their blu events; the Keccak/syscall interactions are
//! AIR-level sends/receives, not dependency events), so the fused device path is
//! available. Like DivRem/Keccak, the chip is FUSED-ONLY: the 634-column width
//! makes the pinned lowering impossible (columns floor 634 >> 256 slots), but the
//! STREAMING lowering's transient footprint fits the streaming kernel tier.

use core::borrow::BorrowMut;

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_tensor::Tensor;
use sp1_core_executor::{
    events::{KeccakPermuteEvent, PrecompileEvent},
    ExecutionRecord, SyscallCode,
};
use sp1_core_machine::{
    air::{columns_as_wires, record_witgen_inputs, WireId, WitProgram, WitnessBuilder},
    memory::{MemoryAccessCols, MemoryAccessWitgenInput},
    operations::{AddrAddOperation, SyscallAddrOperation},
    syscall::precompiles::keccak256::{
        controller::{
            KeccakControlWriteWitgenInput, KeccakPermuteControlCols,
            KeccakPermuteControlWitgenInput, NUM_KECCAK_CONTROL_WITGEN_INPUTS,
        },
        KeccakPermuteControlChip,
    },
    SupervisorMode,
};
use sp1_gpu_cudart::{DeviceBuffer, DeviceMle, TaskScope};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Collect this shard's KECCAK_PERMUTE events (the supervisor chip processes all
/// of them; user-mode shards give this chip zero rows via `num_rows`).
fn collect_events(input: &ExecutionRecord) -> Vec<&KeccakPermuteEvent> {
    input
        .get_precompile_events(SyscallCode::KECCAK_PERMUTE)
        .iter()
        .map(
            |(_, event)| {
                if let PrecompileEvent::KeccakPermute(event) = event {
                    event
                } else {
                    unreachable!()
                }
            },
        )
        .collect()
}

/// Pack each KECCAK_PERMUTE event into one [`KeccakPermuteControlWitgenInput`] row.
pub(crate) fn pack_keccak_control_inputs(input: &ExecutionRecord) -> Vec<u64> {
    let events = collect_events(input);
    let mut inputs: Vec<u64> = vec![0u64; events.len() * NUM_KECCAK_CONTROL_WITGEN_INPUTS];
    inputs.par_chunks_mut(NUM_KECCAK_CONTROL_WITGEN_INPUTS).zip(events.par_iter()).for_each(
        |(chunk, event)| {
            let slot: &mut KeccakPermuteControlWitgenInput<u64> = chunk.borrow_mut();
            slot.clk = event.clk;
            slot.state_addr = event.state_addr;
            for i in 0..25 {
                let r = &event.state_read_records[i];
                slot.reads[i] = MemoryAccessWitgenInput {
                    prev_value: r.value,
                    prev_ts: r.prev_timestamp,
                    cur_ts: r.timestamp,
                };
                let w = &event.state_write_records[i];
                slot.writes[i] = KeccakControlWriteWitgenInput {
                    access: MemoryAccessWitgenInput {
                        prev_value: w.prev_value,
                        prev_ts: w.prev_timestamp,
                        cur_ts: w.timestamp,
                    },
                    value: w.value,
                };
            }
        },
    );
    inputs
}

fn record_keccak_control_program() -> (WitProgram, Vec<u32>) {
    let (mut rec, input) = record_witgen_inputs::<KeccakPermuteControlWitgenInput<WireId>>();
    // SAFETY: KeccakPermuteControlCols is #[repr(C)] over Copy WireId (a u32
    // newtype; SupervisorMode's SliceProtCols are empty); the zeroed pattern is a
    // valid WireId(0) placeholder and every field is assigned below (the
    // column-equality tests would catch a missed one).
    let mut cols: KeccakPermuteControlCols<WireId, SupervisorMode> = unsafe { core::mem::zeroed() };

    let clk = input.clk;
    let addr = input.state_addr;
    let clk_high = rec.bits(clk, 24, 32);
    cols.clk_high = rec.nat_to_field(clk_high);
    let clk_low = rec.bits(clk, 0, 24);
    cols.clk_low = rec.nat_to_field(clk_low);
    // This precompile accesses 25 words = 200 bytes.
    SyscallAddrOperation::<WireId>::witgen(&mut rec, &mut cols.state_addr, addr, 200);
    let one = rec.const_nat(1);
    cols.is_real = rec.nat_to_field(one);

    for i in 0..25 {
        let off = rec.const_nat(8 * i as u64);
        AddrAddOperation::<WireId>::witgen(&mut rec, &mut cols.addrs[i], addr, off);
    }
    for i in 0..25 {
        let r = &input.reads[i];
        MemoryAccessCols::<WireId>::witgen(
            &mut rec,
            &mut cols.initial_memory_access[i],
            r.prev_value,
            r.prev_ts,
            r.cur_ts,
        );
    }
    for i in 0..25 {
        let w = &input.writes[i];
        MemoryAccessCols::<WireId>::witgen(
            &mut rec,
            &mut cols.final_memory_access[i],
            w.access.prev_value,
            w.access.prev_ts,
            w.access.cur_ts,
        );
        for limb in 0..4 {
            let l = rec.bits(w.value, 16 * limb as u32, 16);
            cols.final_value[i][limb] = rec.nat_to_field(l);
        }
    }

    let col_wires: Vec<u32> = columns_as_wires(&cols).iter().map(|cw| cw.0).collect();
    let program = rec.finish();
    // FUSED-ONLY via the streaming lowering (the 634-column pinned floor rules out
    // the pinned kernel): assert the streaming gate in
    // `generate_trace_and_lookups_slots_into` will actually take the streaming tier.
    let (_, s_max, epi) = program.allocate_slots_streaming(&col_wires);
    assert!(
        (s_max as usize) <= super::WITGEN_MAX_WIRES && epi.is_empty(),
        "KeccakPermuteControl streaming lowering needs {s_max} slots (epilogue {}) — does \
         not fit the streaming kernel tier",
        epi.len()
    );
    (program, col_wires)
}

/// The chip's cached [`WitgenChip`](super::WitgenChip) descriptor: recorded +
/// lowered ONCE per process (the program is shard-independent), not per shard.
fn keccak_control_witgen_chip() -> &'static super::WitgenChip {
    static CHIP: std::sync::OnceLock<super::WitgenChip> = std::sync::OnceLock::new();
    CHIP.get_or_init(|| {
        let (program, col_wires) = record_keccak_control_program();
        super::WitgenChip::new(program, col_wires)
    })
}

/// Lookup-only variant of the cached descriptor: an EMPTY column map, so the
/// pinned slot allocation does NOT pin the column wires (the 634-column pinned
/// footprint doesn't fit; transients-only does). The lookup kernel executes the
/// same op order, so the emitted lookups are identical.
fn keccak_control_lookup_chip() -> &'static super::WitgenChip {
    static CHIP: std::sync::OnceLock<super::WitgenChip> = std::sync::OnceLock::new();
    CHIP.get_or_init(|| {
        let (program, _col_wires) = record_keccak_control_program();
        super::WitgenChip::new(program, Vec::new())
    })
}

impl CudaTracegenAir<F> for KeccakPermuteControlChip<SupervisorMode> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    /// Non-fused path unsupported: the pinned lowering cannot fit (columns floor
    /// 634 > the 256-slot cap) — the chip ONLY fits via the streaming fused path.
    /// Production always routes through `generate_trace_device_with_lookups`
    /// because `supports_device_dependencies` is true.
    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("KeccakPermuteControl device tracegen is fused-only (streaming lowering)")
    }

    /// Fused device path — the one the PROVER calls (the iter-067 lesson: without
    /// this override the enum dispatch hits the trait-default `unimplemented!()`).
    async fn generate_trace_device_with_lookups(
        &self,
        input: &Self::Record,
        inputs: Vec<u64>,
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let chip = keccak_control_witgen_chip();
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let n_events =
            if height == 0 { 0 } else { inputs.len() / chip.program.num_inputs as usize };
        // Zero padding (host `write_bytes(0)`); the streaming kernel writes event rows.
        let trace = Tensor::<F, TaskScope>::zeros_in([chip.n_cols(), height], scope.clone());
        super::generate_trace_and_lookups_slots_into(
            chip,
            super::WitgenBatch { inputs: &inputs, n_events, height },
            trace,
            hist,
            scope,
        )
        .await
    }

    fn supports_device_dependencies(&self) -> bool {
        // Byte/range lookups only; the Keccak/syscall interactions are AIR-level
        // sends/receives, NOT dependency events (no `GlobalInteractionEvent`s).
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
        let inputs = pack_keccak_control_inputs(input);
        let n_events =
            if height == 0 { 0 } else { inputs.len() / NUM_KECCAK_CONTROL_WITGEN_INPUTS };
        if n_events == 0 {
            return Ok(());
        }
        // Lookup-only pass: use the descriptor whose column map is empty (see
        // `keccak_control_lookup_chip`) — its pinned allocation never pins the
        // column wires.
        super::accumulate_lookups_slots(
            keccak_control_lookup_chip(),
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
    use sp1_core_executor::events::{
        KeccakPermuteEvent, MemoryReadRecord, MemoryWriteRecord, PrecompileEvent, SyscallEvent,
    };
    use sp1_core_executor::{ByteOpcode, ExecutionRecord, SyscallCode};
    use sp1_core_machine::air::{
        interpret_c_columns, interpret_c_lookups, interpret_c_slots_streaming_columns,
        BYTE_HIST_ROWS, RANGE_HIST_ROWS,
    };
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    use sp1_core_machine::syscall::precompiles::keccak256::{
        controller::num_keccak_permute_control_cols_supervisor, KeccakPermuteControlChip,
    };
    use sp1_core_machine::SupervisorMode;
    use sp1_hypercube::air::MachineAir;

    use crate::F;

    /// `n` untrapped KECCAK_PERMUTE events with full 25-word read/write records.
    fn synth_shard(n: usize, seed: u64) -> ExecutionRecord {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut record = ExecutionRecord::default();
        for e in 0..n {
            let clk = (e as u64 + 1) * 1_000_000 + 17;
            // Valid syscall addr: >= 2^16, 8-aligned, headroom below 2^48.
            let state_addr = ((rng.gen::<u64>() & 0x7F_FFFF_FFFF) | 0x1_0000) & !7;
            let pre_state: [u64; 25] = core::array::from_fn(|_| rng.gen::<u64>());
            let post_state: [u64; 25] = core::array::from_fn(|_| rng.gen::<u64>());
            let state_read_records = (0..25)
                .map(|i| {
                    let prev_timestamp = clk - 1 - (rng.gen::<u64>() & 0xFFFF);
                    MemoryReadRecord {
                        value: pre_state[i],
                        timestamp: clk,
                        prev_timestamp,
                        prev_page_prot_record: None,
                    }
                })
                .collect::<Vec<_>>();
            let state_write_records = (0..25)
                .map(|i| MemoryWriteRecord {
                    value: post_state[i],
                    timestamp: clk + 1,
                    prev_value: pre_state[i],
                    prev_timestamp: clk,
                    prev_page_prot_record: None,
                })
                .collect::<Vec<_>>();
            let event = KeccakPermuteEvent {
                clk,
                pre_state,
                post_state,
                state_read_records,
                state_write_records,
                state_addr,
                local_mem_access: Vec::new(),
                page_prot_records: Default::default(),
                local_page_prot_access: Vec::new(),
            };
            let syscall_event = SyscallEvent {
                pc: 4,
                next_pc: 8,
                clk,
                should_send: true,
                syscall_code: SyscallCode::KECCAK_PERMUTE,
                syscall_id: SyscallCode::KECCAK_PERMUTE.syscall_id(),
                arg1: state_addr,
                arg2: 0,
                exit_code: 0,
                sig_return_pc_record: None,
                trap_result: None,
                trap_error: None,
            };
            record.precompile_events.add_event(
                SyscallCode::KECCAK_PERMUTE,
                syscall_event,
                PrecompileEvent::KeccakPermute(event),
            );
        }
        record
    }

    /// Columns from the recorded op-DAG must equal the HOST trace bit-for-bit on
    /// the SSA and STREAMING interpreters (the pinned form cannot fit — asserted in
    /// the record fn). Also prints the slot-footprint decision numbers.
    #[test]
    fn keccak_control_columns_match_host() {
        let shard = synth_shard(37, 0x4ECC01);
        let chip = KeccakPermuteControlChip::<SupervisorMode>::default();
        let trace = MachineAir::<F>::generate_trace(&chip, &shard, &mut ExecutionRecord::default());
        let width = num_keccak_permute_control_cols_supervisor();

        let (program, col_wires) = super::record_keccak_control_program();
        assert_eq!(col_wires.len(), width);
        let lowering = program.lower_streaming(&col_wires);
        eprintln!(
            "KeccakPermuteControl: num_wires={} n_cols={} streaming_max_slots={} \
             epilogue={}",
            program.num_wires(),
            col_wires.len(),
            lowering.max_slots,
            lowering.epilogue.len(),
        );

        let ni = sp1_core_machine::syscall::precompiles::keccak256::controller::NUM_KECCAK_CONTROL_WITGEN_INPUTS;
        let ops_c = program.to_c();

        let inputs = super::pack_keccak_control_inputs(&shard);
        let n_events = inputs.len() / ni;
        for row in 0..n_events {
            let row_in = &inputs[row * ni..(row + 1) * ni];
            let cols: Vec<F> = interpret_c_columns(&ops_c, ni as u32, row_in, &col_wires);
            assert_eq!(
                &trace.values[row * width..(row + 1) * width],
                &cols[..],
                "column mismatch at row {row}"
            );
            let streamed: Vec<F> =
                interpret_c_slots_streaming_columns(&lowering, ni as u32, row_in, width);
            assert_eq!(cols, streamed, "streaming column mismatch at row {row}");
        }
        // Padding rows are all-zero on the host too.
        use slop_algebra::AbstractField;
        for row in n_events..trace.values.len() / width {
            assert!(
                trace.values[row * width..(row + 1) * width].iter().all(|&v| v == F::zero()),
                "padding row {row} not all-zero"
            );
        }
    }

    /// Byte/range-lookup histogram vs `generate_dependencies` (the iter-041 trap):
    /// the SyscallAddr 13-bit check, the 75 AddrAdd u16 range checks, and the 50
    /// memory-access timestamp checks must all match.
    #[test]
    fn keccak_control_lookups_match_generate_dependencies() {
        let shard = synth_shard(29, 0x4ECC02);
        let chip = KeccakPermuteControlChip::<SupervisorMode>::default();

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

        let (program, _col_wires) = super::record_keccak_control_program();
        let ops_c = program.to_c();
        let inputs = super::pack_keccak_control_inputs(&shard);
        let n_events = inputs.len() / sp1_core_machine::syscall::precompiles::keccak256::controller::NUM_KECCAK_CONTROL_WITGEN_INPUTS;
        let mut range_hist = vec![0u32; RANGE_HIST_ROWS];
        let mut byte_hist = vec![0u32; BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS];
        interpret_c_lookups(
            &ops_c,
            program.num_inputs,
            &inputs,
            n_events,
            &mut range_hist,
            &mut byte_hist,
        );
        assert_eq!(range_hist, ref_range, "range histogram mismatch");
        assert_eq!(byte_hist, ref_byte, "byte histogram mismatch");
    }
}
