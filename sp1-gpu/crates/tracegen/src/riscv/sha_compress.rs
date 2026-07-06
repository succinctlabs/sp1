//! Device main-trace + dependency generation for the `ShaCompress` precompile.
//! 80 rows per event in three phases (8 init / 64 compress / 8 finalize) with the
//! SHA-256 working variables threaded across the compression rows. The device port
//! resolves BOTH at pack time: the packer replays the compression host-side (cheap
//! integer ops) and hands each row its own a..h/w/K/memory-record inputs, so rows
//! are independent for the one-thread-per-row kernel.
//!
//! Trapped events' rows and PADDING rows are not all-zero for this chip (they keep
//! the cyclic octet/octet_num/index/k pattern): trapped rows pack as is_real=0
//! (the octet/index/k columns are exempt from the is_real masking), and the device
//! trace is INITIALIZED host-side with the padding pattern before the kernel
//! overwrites the event rows (like DivRem's non-zero padding template, but cyclic).

use rayon::prelude::*;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::{
    events::{PrecompileEvent, ShaCompressEvent},
    ExecutionRecord, SyscallCode, TrapError,
};
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId, WitnessBuilder},
    syscall::precompiles::sha256::{
        ShaCompressChip, ShaCompressCols, NUM_SHA_COMPRESS_COLS, SHA_COMPRESS_K,
    },
};
use sp1_gpu_cudart::{DeviceBuffer, DeviceMle, TaskScope};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of witgen inputs per ShaCompress ROW (see [`ShaCompressCols::witgen`]).
const NUM_SHA_COMPRESS_INPUTS: usize = 21;

/// One SHA-256 compression round (the host `event_to_rows` state update).
fn round(h_array: &mut [u32; 8], w_j: u32, k_j: u32) {
    let [a, b, c, d, e, f, g, h] = *h_array;
    let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
    let ch = (e & f) ^ ((!e) & g);
    let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(w_j).wrapping_add(k_j);
    let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
    let maj = (a & b) ^ (a & c) ^ (b & c);
    let temp2 = s0.wrapping_add(maj);
    *h_array = [temp1.wrapping_add(temp2), a, b, c, d.wrapping_add(temp1), e, f, g];
}

/// Pack 80 input rows per event, replaying the compression host-side.
pub(crate) fn pack_sha_compress_inputs(
    events: &[(Option<TrapError>, &ShaCompressEvent)],
) -> Vec<u64> {
    let rs = NUM_SHA_COMPRESS_INPUTS;
    let mut inputs: Vec<u64> = vec![0u64; events.len() * 80 * rs];
    inputs.par_chunks_mut(80 * rs).zip(events.par_iter()).for_each(
        |(chunk, (trap_error, event))| {
            if trap_error.is_some() {
                // Trapped rows keep only index (+ K on compression indices); the
                // witgen's exempt columns reproduce the host's octet/index/k
                // pattern while is_real = 0 masks everything else.
                for (i, slot) in chunk.chunks_mut(rs).enumerate() {
                    slot[3] = i as u64; // index
                    let octet_num = i / 8;
                    if octet_num != 0 && octet_num != 9 {
                        slot[4] = SHA_COMPRESS_K[(octet_num - 1) * 8 + i % 8] as u64;
                    }
                }
                return;
            }
            let pack_row = |slot: &mut [u64],
                            index: u64,
                            k: u32,
                            mem_prev_value: u64,
                            mem_prev_ts: u64,
                            mem_ts: u64,
                            mem_value: u32,
                            hs: &[u32; 8],
                            w_j: u32,
                            og: u32,
                            fin: u32| {
                slot.copy_from_slice(&[
                    event.clk,
                    event.w_ptr,
                    event.h_ptr,
                    index,
                    k as u64,
                    mem_prev_value,
                    mem_prev_ts,
                    mem_ts,
                    mem_value as u64,
                    hs[0] as u64,
                    hs[1] as u64,
                    hs[2] as u64,
                    hs[3] as u64,
                    hs[4] as u64,
                    hs[5] as u64,
                    hs[6] as u64,
                    hs[7] as u64,
                    w_j as u64,
                    og as u64,
                    fin as u64,
                    1, // is_real
                ]);
            };
            // Init: a..h are the 8 h-words being read.
            let init_h: [u32; 8] = core::array::from_fn(|i| event.h_read_records[i].value as u32);
            for j in 0..8usize {
                let r = &event.h_read_records[j];
                pack_row(
                    &mut chunk[j * rs..(j + 1) * rs],
                    j as u64,
                    0,
                    r.value,
                    r.prev_timestamp,
                    r.timestamp,
                    r.value as u32,
                    &init_h,
                    0,
                    0,
                    0,
                );
            }
            // Compress: a..h is the working state BEFORE round j.
            let mut h_array = event.h;
            for j in 0..64usize {
                let r = &event.w_i_read_records[j];
                pack_row(
                    &mut chunk[(j + 8) * rs..(j + 9) * rs],
                    (j + 8) as u64,
                    SHA_COMPRESS_K[j],
                    r.value,
                    r.prev_timestamp,
                    r.timestamp,
                    r.value as u32,
                    &h_array,
                    event.w[j],
                    0,
                    0,
                );
                round(&mut h_array, event.w[j], SHA_COMPRESS_K[j]);
            }
            // Finalize: a..h are the final working vars; write og_h[j] + h[j].
            for j in 0..8usize {
                let r = &event.h_write_records[j];
                pack_row(
                    &mut chunk[(j + 72) * rs..(j + 73) * rs],
                    (j + 72) as u64,
                    0,
                    r.prev_value,
                    r.prev_timestamp,
                    r.timestamp,
                    r.value as u32,
                    &h_array,
                    0,
                    event.h[j],
                    h_array[j],
                );
            }
        },
    );
    inputs
}

/// Pack straight from a record (the `pack_device_lookup_inputs` arm).
pub(crate) fn pack_for_record(input: &ExecutionRecord) -> Vec<u64> {
    pack_sha_compress_inputs(&collect_events(input))
}

fn collect_events(input: &ExecutionRecord) -> Vec<(Option<TrapError>, &ShaCompressEvent)> {
    input
        .get_precompile_events(SyscallCode::SHA_COMPRESS)
        .iter()
        .map(|(syscall_event, event)| {
            let event = if let PrecompileEvent::ShaCompress(event) = event {
                event
            } else {
                unreachable!()
            };
            (syscall_event.trap_error, event)
        })
        .collect()
}

pub(crate) fn record_sha_compress_program() -> (sp1_core_machine::air::WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_SHA_COMPRESS_INPUTS as u32);
    let mut cols_w = ShaCompressCols::<WireId>::default();
    let w = |i: u32| RecordingWitnessBuilder::input(i);
    let is_real = w(20);
    rec.push_guard(is_real);
    ShaCompressCols::<WireId>::witgen(
        &mut rec,
        &mut cols_w,
        w(0),
        w(1),
        w(2),
        w(3),
        w(4),
        w(5),
        w(6),
        w(7),
        w(8),
        w(9),
        w(10),
        w(11),
        w(12),
        w(13),
        w(14),
        w(15),
        w(16),
        w(17),
        w(18),
        w(19),
        is_real,
    );
    rec.pop_guard();
    // Mask every column by is_real EXCEPT octet/octet_num/index/k, which trapped
    // rows keep (the host writes them even for trapped events).
    let base = &cols_w as *const ShaCompressCols<WireId> as usize;
    let pos = |p: *const WireId| (p as usize - base) / core::mem::size_of::<WireId>();
    let mut exempt = vec![false; NUM_SHA_COMPRESS_COLS];
    for i in 0..8 {
        exempt[pos(&cols_w.octet[i])] = true;
    }
    for i in 0..10 {
        exempt[pos(&cols_w.octet_num[i])] = true;
    }
    exempt[pos(&cols_w.index)] = true;
    exempt[pos(&cols_w.k[0])] = true;
    exempt[pos(&cols_w.k[1])] = true;

    let zero = rec.const_nat(0);
    let zero_f = rec.nat_to_field(zero);
    let col_wires: Vec<u32> = columns_as_wires(&cols_w)
        .to_vec()
        .into_iter()
        .enumerate()
        .map(|(i, cw)| if exempt[i] { cw.0 } else { rec.field_select(is_real, cw, zero_f).0 })
        .collect();
    let program = rec.finish();
    (program, col_wires)
}

/// Host-side cyclic padding pattern for row `row` (mirrors `generate_trace_into`'s
/// padded-row loop): one-hot octet/octet_num, index, and K during compression.
fn padding_row(row: usize, cols: &mut ShaCompressCols<F>) {
    use slop_algebra::AbstractField;
    let cycle = row % 80;
    let octet_num = cycle / 8;
    let octet = cycle % 8;
    cols.octet_num[octet_num] = F::one();
    cols.octet[octet] = F::one();
    cols.index = F::from_canonical_u32(cycle as u32);
    if octet_num != 0 && octet_num != 9 {
        let k = SHA_COMPRESS_K[(octet_num - 1) * 8 + octet];
        cols.k = [F::from_canonical_u32(k & 0xFFFF), F::from_canonical_u32(k >> 16)];
    }
}

impl CudaTracegenAir<F> for ShaCompressChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        use core::borrow::BorrowMut;
        let (program, col_wires) = record_sha_compress_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_SHA_COMPRESS_COLS);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let events = collect_events(input);
        let n_rows = if height == 0 { 0 } else { events.len() * 80 };
        let inputs = pack_sha_compress_inputs(&events);

        // Initialize the trace with the CYCLIC padding pattern for rows beyond the
        // events (host `generate_trace_into` sets octet/octet_num/index/k there);
        // the kernel overwrites the event rows.
        let mut init = vec![F::default(); n_cols * height];
        {
            let mut row_buf = vec![F::default(); n_cols];
            for row in n_rows..height {
                for v in row_buf.iter_mut() {
                    *v = F::default();
                }
                let cols: &mut ShaCompressCols<F> = row_buf.as_mut_slice().borrow_mut();
                padding_row(row, cols);
                for (c, &v) in row_buf.iter().enumerate() {
                    init[c * height + row] = v;
                }
            }
        }
        let mut buf = Buffer::try_with_capacity_in(init.len().max(1), scope.clone()).unwrap();
        buf.extend_from_host_slice(&init)?;
        let trace = Tensor::<F, TaskScope>::from(buf).reshape([n_cols, height]);

        super::generate_columns_slots_into(
            &program, &col_wires, &inputs, n_rows, height, trace, scope,
        )
        .await
    }

    /// Fused path — the one the PROVER calls when `supports_device_dependencies`
    /// (the iter-067 lesson: without this override the enum dispatch hits the
    /// trait-default `unimplemented!()`). Pre-initializes the cyclic padding
    /// pattern before the fused slot kernel overwrites the event rows.
    async fn generate_trace_device_with_lookups(
        &self,
        input: &Self::Record,
        inputs: Vec<u64>,
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        use core::borrow::BorrowMut;
        let (program, col_wires) = record_sha_compress_program();
        let n_cols = col_wires.len();
        debug_assert_eq!(n_cols, NUM_SHA_COMPRESS_COLS);
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        let n_rows = if height == 0 { 0 } else { inputs.len() / program.num_inputs as usize };

        let mut init = vec![F::default(); n_cols * height];
        {
            let mut row_buf = vec![F::default(); n_cols];
            for row in n_rows..height {
                for v in row_buf.iter_mut() {
                    *v = F::default();
                }
                let cols: &mut ShaCompressCols<F> = row_buf.as_mut_slice().borrow_mut();
                padding_row(row, cols);
                for (c, &v) in row_buf.iter().enumerate() {
                    init[c * height + row] = v;
                }
            }
        }
        let mut buf = Buffer::try_with_capacity_in(init.len().max(1), scope.clone()).unwrap();
        buf.extend_from_host_slice(&init)?;
        let trace = Tensor::<F, TaskScope>::from(buf).reshape([n_cols, height]);

        super::generate_trace_and_lookups_slots_into(
            &program, &col_wires, &inputs, n_rows, height, trace, hist, scope,
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
        let events = collect_events(input);
        let n_rows = if height == 0 { 0 } else { events.len() * 80 };
        if n_rows == 0 {
            return Ok(());
        }
        let (program, col_wires) = record_sha_compress_program();
        let inputs = pack_sha_compress_inputs(&events);
        super::accumulate_lookups_slots(
            &program, &col_wires, &inputs, n_rows, range_dev, byte_dev, scope,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core_executor::events::{
        MemoryReadRecord, MemoryWriteRecord, PrecompileEvent, ShaCompressEvent, SyscallEvent,
    };
    use sp1_core_executor::{ByteOpcode, ExecutionRecord, SyscallCode};
    use sp1_core_machine::air::{
        interpret_c_columns, interpret_c_lookups, interpret_c_slots_columns, BYTE_HIST_ROWS,
        RANGE_HIST_ROWS,
    };
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    use sp1_core_machine::syscall::precompiles::sha256::{
        ShaCompressChip, NUM_SHA_COMPRESS_COLS, SHA_COMPRESS_K,
    };
    use sp1_hypercube::air::MachineAir;

    use crate::F;

    fn read(rng: &mut StdRng, clk: u64) -> MemoryReadRecord {
        MemoryReadRecord {
            value: rng.gen::<u32>() as u64,
            timestamp: clk,
            prev_timestamp: clk - 1 - (rng.gen::<u64>() & 0xFFFF),
            prev_page_prot_record: None,
        }
    }

    fn synth_shard(n: usize, seed: u64) -> ExecutionRecord {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut record = ExecutionRecord::default();
        for ev in 0..n {
            let clk = (ev as u64 + 1) * 1_000_000 + 1;
            let w_ptr = (rng.gen::<u64>() & 0xFFFF_FFFF) & !7;
            let h_ptr = (rng.gen::<u64>() & 0xFFFF_FFFF) & !7;
            let h_read_records: [MemoryReadRecord; 8] =
                core::array::from_fn(|_| read(&mut rng, clk));
            let h: [u32; 8] = core::array::from_fn(|i| h_read_records[i].value as u32);
            let w: Vec<u32> = (0..64).map(|_| rng.gen::<u32>()).collect();
            let w_i_read_records: Vec<MemoryReadRecord> =
                (0..64).map(|_| read(&mut rng, clk)).collect();
            // Run the compression to get the final h values for the write records.
            let mut h_array = h;
            for j in 0..64 {
                super::round(&mut h_array, w[j], SHA_COMPRESS_K[j]);
            }
            let h_write_records: [MemoryWriteRecord; 8] =
                core::array::from_fn(|j| MemoryWriteRecord {
                    prev_timestamp: clk - 1,
                    prev_page_prot_record: None,
                    prev_value: h_read_records[j].value,
                    timestamp: clk + 100 + j as u64,
                    value: h[j].wrapping_add(h_array[j]) as u64,
                });
            let event = ShaCompressEvent {
                clk,
                w_ptr,
                h_ptr,
                w,
                h,
                h_read_records,
                w_i_read_records,
                h_write_records,
                local_mem_access: Vec::new(),
                page_prot_access: Default::default(),
                local_page_prot_access: Vec::new(),
            };
            let syscall_event = SyscallEvent {
                pc: 4,
                next_pc: 8,
                clk,
                should_send: true,
                syscall_code: SyscallCode::SHA_COMPRESS,
                syscall_id: SyscallCode::SHA_COMPRESS.syscall_id(),
                arg1: w_ptr,
                arg2: h_ptr,
                exit_code: 0,
                sig_return_pc_record: None,
                trap_result: None,
                trap_error: None,
            };
            record.precompile_events.add_event(
                SyscallCode::SHA_COMPRESS,
                syscall_event,
                PrecompileEvent::ShaCompress(event),
            );
        }
        record
    }

    /// Columns from the recorded op-DAG must equal the host trace for all 80 rows
    /// per event (init/compress/finalize phases, working-var threading resolved at
    /// pack time), on both the SSA and the slot-resolved interpreters.
    #[test]
    fn sha_compress_columns_match_host() {
        let shard = synth_shard(3, 0x5C03);
        let chip = ShaCompressChip;
        let trace = MachineAir::<F>::generate_trace(&chip, &shard, &mut ExecutionRecord::default());
        let width = NUM_SHA_COMPRESS_COLS;

        let (program, col_wires) = super::record_sha_compress_program();
        let (slot, max_slots) = program.allocate_slots(&col_wires);
        eprintln!(
            "ShaCompress: num_wires={} max_slots={max_slots} n_cols={}",
            program.num_wires(),
            col_wires.len()
        );
        let ops_c = program.to_c();
        let ops_slots = program.to_c_slots(&slot);
        let ni = super::NUM_SHA_COMPRESS_INPUTS;
        let input_slots = &slot[..ni];
        let col_slots: Vec<u32> = col_wires.iter().map(|&w| slot[w as usize]).collect();
        let events = super::collect_events(&shard);
        let inputs = super::pack_sha_compress_inputs(&events);
        let n_rows = events.len() * 80;
        for row in 0..n_rows {
            let row_in = &inputs[row * ni..(row + 1) * ni];
            let cols: Vec<F> = interpret_c_columns(&ops_c, ni as u32, row_in, &col_wires);
            assert_eq!(
                &trace.values[row * width..(row + 1) * width],
                &cols[..],
                "column mismatch at row {row} (cycle {})",
                row % 80
            );
            let flat: Vec<F> = interpret_c_slots_columns(
                &ops_slots,
                ni as u32,
                row_in,
                input_slots,
                &col_slots,
                max_slots,
            );
            assert_eq!(cols, flat, "slot-flat column mismatch at row {row}");
        }
        // Also check the host's PADDED rows against the padding-pattern helper the
        // device path uploads (they are NOT all-zero for this chip).
        use core::borrow::BorrowMut;
        let padded = trace.values.len() / width;
        for row in n_rows..padded {
            let mut row_buf = vec![F::default(); width];
            let cols: &mut sp1_core_machine::syscall::precompiles::sha256::ShaCompressCols<F> =
                row_buf.as_mut_slice().borrow_mut();
            super::padding_row(row, cols);
            assert_eq!(
                &trace.values[row * width..(row + 1) * width],
                &row_buf[..],
                "padding mismatch at row {row}"
            );
        }
    }

    /// Byte-lookup histogram vs `generate_dependencies` across all three phases.
    #[test]
    fn sha_compress_lookups_match_generate_dependencies() {
        let shard = synth_shard(3, 0x5C04);
        let chip = ShaCompressChip;

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

        let (program, _col_wires) = super::record_sha_compress_program();
        let ops_c = program.to_c();
        let events = super::collect_events(&shard);
        let inputs = super::pack_sha_compress_inputs(&events);
        let n_rows = events.len() * 80;
        let mut range_hist = vec![0u32; RANGE_HIST_ROWS];
        let mut byte_hist = vec![0u32; BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS];
        interpret_c_lookups(
            &ops_c,
            program.num_inputs,
            &inputs,
            n_rows,
            &mut range_hist,
            &mut byte_hist,
        );
        assert_eq!(range_hist, ref_range, "range histogram mismatch");
        assert_eq!(byte_hist, ref_byte, "byte histogram mismatch");
    }
}
