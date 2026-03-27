use std::{borrow::BorrowMut, mem::MaybeUninit};

use hashbrown::HashMap;
use itertools::Itertools;
use slop_algebra::PrimeField32;
use slop_maybe_rayon::prelude::{
    IndexedParallelIterator, ParallelIterator, ParallelSlice, ParallelSliceMut,
};
use sp1_core_executor::{
    events::{Blake3CompressEvent, ByteLookupEvent, ByteRecord, MemoryRecordEnum, PrecompileEvent},
    ExecutionRecord, Program, SyscallCode,
};
use sp1_hypercube::air::MachineAir;

use super::{
    columns::{Blake3CompressCols, NUM_BLAKE3_COMPRESS_COLS},
    Blake3CompressChip, COMPUTE_START, FINALIZE_ROWS, FINALIZE_START, G_INDEX,
    MSG_READ_ROWS, MSG_READ_START, MSG_SCHEDULE, OPERATION_COUNT, ROUND_COUNT, ROWS_PER_INVOCATION,
    STATE_INIT_ROWS, STATE_INIT_START,
};
use crate::utils::{next_multiple_of_32, u32_to_half_word};

impl<F: PrimeField32> MachineAir<F> for Blake3CompressChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "Blake3Compress"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows =
            input.get_precompile_events(SyscallCode::BLAKE3_COMPRESS_INNER).len()
                * ROWS_PER_INVOCATION;
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let padded_nb_rows =
            <Blake3CompressChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = input.get_precompile_events(SyscallCode::BLAKE3_COMPRESS_INNER);
        let num_event_rows = events.len() * ROWS_PER_INVOCATION;

        unsafe {
            let padding_start = num_event_rows * NUM_BLAKE3_COMPRESS_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_BLAKE3_COMPRESS_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_BLAKE3_COMPRESS_COLS)
        };

        let invocation_area = NUM_BLAKE3_COMPRESS_COLS * ROWS_PER_INVOCATION;

        values.par_chunks_mut(invocation_area).enumerate().for_each(|(idx, rows)| {
            let mut blu = Vec::new();
            let event = &events[idx].1;
            let event = if let PrecompileEvent::Blake3CompressInner(event) = event {
                event
            } else {
                unreachable!()
            };
            unsafe {
                core::ptr::write_bytes(rows.as_mut_ptr(), 0, invocation_area);
            }
            self.event_to_rows(event, rows, &mut blu);
        });
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = input.get_precompile_events(SyscallCode::BLAKE3_COMPRESS_INNER);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                let mut rows = vec![F::zero(); NUM_BLAKE3_COMPRESS_COLS * ROWS_PER_INVOCATION];
                events.iter().for_each(|(_, event)| {
                    let event = if let PrecompileEvent::Blake3CompressInner(event) = event {
                        event
                    } else {
                        unreachable!()
                    };
                    self.event_to_rows::<F>(event, &mut rows, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::BLAKE3_COMPRESS_INNER).is_empty()
        }
    }
}

impl Blake3CompressChip {
    fn event_to_rows<F: PrimeField32>(
        &self,
        event: &Blake3CompressEvent,
        rows: &mut [F],
        blu: &mut impl ByteRecord,
    ) {
        let clk_high = (event.clk >> 24) as u32;
        let clk_low = (event.clk & 0xFFFFFF) as u32;

        // Convenience: fill common fields for a row.
        macro_rules! fill_common {
            ($cols:expr, $row_idx:expr, $state:expr, $msg:expr) => {
                $cols.clk_high = F::from_canonical_u32(clk_high);
                $cols.clk_low = F::from_canonical_u32(clk_low);
                $cols.state_ptr = [
                    F::from_canonical_u16((event.state_ptr & 0xFFFF) as u16),
                    F::from_canonical_u16(((event.state_ptr >> 16) & 0xFFFF) as u16),
                    F::from_canonical_u16(((event.state_ptr >> 32) & 0xFFFF) as u16),
                ];
                $cols.msg_ptr = [
                    F::from_canonical_u16((event.msg_ptr & 0xFFFF) as u16),
                    F::from_canonical_u16(((event.msg_ptr >> 16) & 0xFFFF) as u16),
                    F::from_canonical_u16(((event.msg_ptr >> 32) & 0xFFFF) as u16),
                ];
                $cols.index = F::from_canonical_u32($row_idx as u32);
                for _i in 0..16 {
                    $cols.state[_i] = u32_to_half_word($state[_i]);
                    $cols.msg[_i] = u32_to_half_word($msg[_i]);
                }
            };
        }

        // ── Phase 1: state_init (rows 0–15) ──────────────────────────────────
        for i in 0..STATE_INIT_ROWS {
            let row_idx = STATE_INIT_START + i;
            let start = row_idx * NUM_BLAKE3_COMPRESS_COLS;
            let end = (row_idx + 1) * NUM_BLAKE3_COMPRESS_COLS;
            let cols: &mut Blake3CompressCols<F> = rows[start..end].borrow_mut();

            fill_common!(cols, row_idx, event.state_in, event.msg);
            cols.is_state_init = F::one();
            cols.phase_idx[i] = F::one();

            cols.mem_addr_state_init.populate(blu, event.state_ptr, i as u64 * 8);
            cols.mem_addr = cols.mem_addr_state_init.value;
            cols.mem.populate(MemoryRecordEnum::Read(event.state_read_records[i]), blu);
            cols.mem_value = u32_to_half_word(event.state_read_records[i].value as u32);

            // Passthrough: next_state = state (no G function on this row).
            for k in 0..16 {
                cols.next_state[k] = cols.state[k];
            }

            cols.is_real = F::one();
        }

        // ── Phase 2: msg_read (rows 16–31) ───────────────────────────────────
        for j in 0..MSG_READ_ROWS {
            let row_idx = MSG_READ_START + j;
            let start = row_idx * NUM_BLAKE3_COMPRESS_COLS;
            let end = (row_idx + 1) * NUM_BLAKE3_COMPRESS_COLS;
            let cols: &mut Blake3CompressCols<F> = rows[start..end].borrow_mut();

            fill_common!(cols, row_idx, event.state_in, event.msg);
            cols.is_msg_read = F::one();
            cols.phase_idx[j] = F::one();

            cols.mem_addr_msg_read.populate(blu, event.msg_ptr, j as u64 * 8);
            cols.mem_addr = cols.mem_addr_msg_read.value;
            cols.mem.populate(MemoryRecordEnum::Read(event.msg_read_records[j]), blu);
            cols.mem_value = u32_to_half_word(event.msg_read_records[j].value as u32);

            // Passthrough: next_state = state (no G function on this row).
            for k in 0..16 {
                cols.next_state[k] = cols.state[k];
            }

            cols.is_real = F::one();
        }

        // ── Phase 3: compute (rows 32–87, one G call per row) ────────────────
        let mut current_state = event.state_in;

        for round in 0..ROUND_COUNT {
            for op in 0..OPERATION_COUNT {
                let g_call_idx = round * OPERATION_COUNT + op;
                let row_idx = COMPUTE_START + g_call_idx;
                let start = row_idx * NUM_BLAKE3_COMPRESS_COLS;
                let end = (row_idx + 1) * NUM_BLAKE3_COMPRESS_COLS;
                let cols: &mut Blake3CompressCols<F> = rows[start..end].borrow_mut();

                fill_common!(cols, row_idx, current_state, event.msg);
                cols.is_compute = F::one();
                cols.round[round] = F::one();
                cols.op[op] = F::one();

                let [ai, bi, ci, di] = G_INDEX[op];
                let mx_val = event.msg[MSG_SCHEDULE[round][2 * op]];
                let my_val = event.msg[MSG_SCHEDULE[round][2 * op + 1]];

                let a = current_state[ai];
                let b = current_state[bi];
                let c = current_state[ci];
                let d = current_state[di];

                cols.ga = u32_to_half_word(a);
                cols.gb = u32_to_half_word(b);
                cols.gc = u32_to_half_word(c);
                cols.gd = u32_to_half_word(d);
                cols.mx = u32_to_half_word(mx_val);
                cols.my = u32_to_half_word(my_val);

                // Step 1: a' = a + b + mx
                let a_add_b_val = cols.a_add_b.populate(blu, a, b);
                let a_prime = cols.a_add_b_add_mx.populate(blu, a_add_b_val, mx_val);
                // Step 2: d' = d ^ a'
                let d_xor_a_val = cols.d_xor_a.populate_xor_u32(blu, d, a_prime);
                // Step 3: d'' = d' rotr 16 (pure limb swap)
                let d_pp = d_xor_a_val.rotate_right(16);
                // Step 4: c' = c + d''
                let c_prime = cols.c_add_d.populate(blu, c, d_pp);
                // Step 5: b' = b ^ c'
                let b_xor_c_val = cols.b_xor_c.populate_xor_u32(blu, b, c_prime);
                cols.b_xor_c_limbs = u32_to_half_word(b_xor_c_val);
                // Step 6: b'' = b' rotr 12
                let b_pp = cols.b_rotr12.populate(blu, b_xor_c_val, 12);
                // Step 7: a'' = a' + b'' + my
                let a2_add_b2_val = cols.a2_add_b2.populate(blu, a_prime, b_pp);
                let a_pp = cols.a2_add_b2_add_my.populate(blu, a2_add_b2_val, my_val);
                // Step 8: d''' = d'' ^ a''
                let d_xor_a2_val = cols.d_xor_a2.populate_xor_u32(blu, d_pp, a_pp);
                cols.d_xor_a2_limbs = u32_to_half_word(d_xor_a2_val);
                // Step 9: d'''' = d''' rotr 8
                let d_4p = cols.d_rotr8.populate(blu, d_xor_a2_val, 8);
                // Step 10: c'' = c' + d''''
                let c_pp = cols.c_add_d2.populate(blu, c_prime, d_4p);
                // Step 11: b''' = b'' ^ c''
                let b_xor_c2_val = cols.b_xor_c2.populate_xor_u32(blu, b_pp, c_pp);
                cols.b_xor_c2_limbs = u32_to_half_word(b_xor_c2_val);
                // Step 12: b'''' = b''' rotr 7
                let b_4p = cols.b_rotr7.populate(blu, b_xor_c2_val, 7);

                // Update state for next G call.
                current_state[ai] = a_pp;
                current_state[bi] = b_4p;
                current_state[ci] = c_pp;
                current_state[di] = d_4p;

                // next_state = post-G state for this row's op.
                // (The unchanged positions keep the pre-G values; cols.state is pre-G.)
                for k in 0..16 {
                    cols.next_state[k] = u32_to_half_word(current_state[k]);
                }

                cols.is_real = F::one();
            }
        }

        // ── Phase 4: finalize (rows 88–103) ──────────────────────────────────
        for i in 0..FINALIZE_ROWS {
            let row_idx = FINALIZE_START + i;
            let start = row_idx * NUM_BLAKE3_COMPRESS_COLS;
            let end = (row_idx + 1) * NUM_BLAKE3_COMPRESS_COLS;
            let cols: &mut Blake3CompressCols<F> = rows[start..end].borrow_mut();

            fill_common!(cols, row_idx, current_state, event.msg);
            cols.is_finalize = F::one();
            cols.phase_idx[i] = F::one();

            cols.mem_addr_finalize.populate(blu, event.state_ptr, i as u64 * 8);
            cols.mem_addr = cols.mem_addr_finalize.value;
            cols.mem.populate(MemoryRecordEnum::Write(event.state_write_records[i]), blu);
            cols.mem_value = u32_to_half_word(event.state_write_records[i].value as u32);

            // Passthrough: next_state = state (no G function on this row).
            for k in 0..16 {
                cols.next_state[k] = cols.state[k];
            }

            cols.is_real = F::one();
        }
    }
}
