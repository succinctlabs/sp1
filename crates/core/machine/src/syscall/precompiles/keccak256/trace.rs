use std::borrow::BorrowMut;

use p3_field::PrimeField32;
use p3_keccak_air::{generate_trace_rows, NUM_KECCAK_COLS, NUM_ROUNDS};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use sp1_core_executor::{
    events::{ByteLookupEvent, KeccakPermuteEvent, PrecompileEvent, SyscallEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_stark::air::MachineAir;

use crate::utils::zeroed_f_vec;

use super::{
    columns::{KeccakMemCols, NUM_KECCAK_MEM_COLS},
    KeccakPermuteChip, STATE_SIZE,
};
use sp1_core_executor::events::ByteRecord;

impl<F: PrimeField32> MachineAir<F> for KeccakPermuteChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "KeccakPermute".to_string()
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size = 8;

        let blu_events: Vec<Vec<ByteLookupEvent>> = input
            .get_precompile_events(SyscallCode::KECCAK_PERMUTE)
            .par_chunks(chunk_size)
            .map(|ops: &[(SyscallEvent, PrecompileEvent)]| {
                // The blu map stores shard -> map(byte lookup event -> multiplicity).
                let mut blu = Vec::new();
                let mut chunk = zeroed_f_vec::<F>(NUM_KECCAK_MEM_COLS * NUM_ROUNDS);
                ops.iter().for_each(|(_, op)| {
                    if let PrecompileEvent::KeccakPermute(event) = op {
                        Self::populate_chunk(event, &mut chunk, &mut blu);
                    } else {
                        unreachable!();
                    }
                });
                blu
            })
            .collect();
        for blu in blu_events {
            output.add_byte_lookup_events(blu);
        }
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let events = input.get_precompile_events(SyscallCode::KECCAK_PERMUTE);
        let num_events = events.len();
        let num_rows = (num_events * NUM_ROUNDS).next_power_of_two();
        let chunk_size = 8;
        let values = vec![0u32; num_rows * NUM_KECCAK_MEM_COLS];
        let mut values = unsafe { std::mem::transmute::<Vec<u32>, Vec<F>>(values) };

        let dummy_keccak_rows = generate_trace_rows::<F>(vec![[0; STATE_SIZE]]);
        let mut dummy_chunk = Vec::new();
        for i in 0..NUM_ROUNDS {
            let dummy_row = dummy_keccak_rows.row(i);
            let mut row = [F::zero(); NUM_KECCAK_MEM_COLS];
            row[..NUM_KECCAK_COLS].copy_from_slice(dummy_row.collect::<Vec<_>>().as_slice());
            dummy_chunk.extend_from_slice(&row);
        }

        values
            .chunks_mut(chunk_size * NUM_KECCAK_MEM_COLS * NUM_ROUNDS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_ROUNDS * NUM_KECCAK_MEM_COLS).enumerate().for_each(
                    |(j, rounds)| {
                        let idx = i * chunk_size + j;
                        if idx < num_events {
                            let mut new_byte_lookup_events = Vec::new();
                            if let PrecompileEvent::KeccakPermute(event) = &events[idx].1 {
                                Self::populate_chunk(event, rounds, &mut new_byte_lookup_events);
                            } else {
                                unreachable!();
                            }
                        } else {
                            rounds.copy_from_slice(&dummy_chunk[..rounds.len()]);
                        }
                    },
                );
            });

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(values, NUM_KECCAK_MEM_COLS);

        // Write the nonce to the trace.
        for i in 0..trace.height() {
            let cols: &mut KeccakMemCols<F> =
                trace.values[i * NUM_KECCAK_MEM_COLS..(i + 1) * NUM_KECCAK_MEM_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::KECCAK_PERMUTE).is_empty()
        }
    }
}

impl KeccakPermuteChip {
    pub fn populate_chunk<F: PrimeField32>(
        event: &KeccakPermuteEvent,
        chunk: &mut [F],
        new_byte_lookup_events: &mut Vec<ByteLookupEvent>,
    ) {
        let start_clk = event.clk;
        let shard = event.shard;

        let p3_keccak_trace = generate_trace_rows::<F>(vec![event.pre_state]);

        // Create all the rows for the permutation.
        for i in 0..NUM_ROUNDS {
            let p3_keccak_row = p3_keccak_trace.row(i);
            let row = &mut chunk[i * NUM_KECCAK_MEM_COLS..(i + 1) * NUM_KECCAK_MEM_COLS];
            // Copy p3_keccak_row into start of cols
            row[..NUM_KECCAK_COLS].copy_from_slice(p3_keccak_row.collect::<Vec<_>>().as_slice());
            let cols: &mut KeccakMemCols<F> = row.borrow_mut();

            cols.shard = F::from_canonical_u32(shard);
            cols.clk = F::from_canonical_u32(start_clk);
            cols.state_addr = F::from_canonical_u32(event.state_addr);
            cols.is_real = F::one();

            // If this is the first row, then populate read memory accesses
            if i == 0 {
                for (j, read_record) in event.state_read_records.iter().enumerate() {
                    cols.state_mem[j].populate_read(*read_record, new_byte_lookup_events);
                    new_byte_lookup_events
                        .add_u8_range_checks(shard, &read_record.value.to_le_bytes());
                }
                cols.do_memory_check = F::one();
                cols.receive_ecall = F::one();
            }

            // If this is the last row, then populate write memory accesses
            if i == NUM_ROUNDS - 1 {
                for (j, write_record) in event.state_write_records.iter().enumerate() {
                    cols.state_mem[j].populate_write(*write_record, new_byte_lookup_events);
                    new_byte_lookup_events
                        .add_u8_range_checks(shard, &write_record.value.to_le_bytes());
                }
                cols.do_memory_check = F::one();
            }
        }
    }
}
