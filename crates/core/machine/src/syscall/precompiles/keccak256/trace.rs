use std::{borrow::BorrowMut, mem::MaybeUninit};

use slop_algebra::PrimeField32;
use slop_keccak_air::{generate_trace_rows, NUM_KECCAK_COLS, NUM_ROUNDS};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use sp1_core_executor::{
    events::{ByteLookupEvent, KeccakPermuteEvent, PrecompileEvent, SyscallEvent},
    ExecutionRecord, Program, SyscallCode,
};
use sp1_hypercube::air::MachineAir;

use crate::utils::{next_multiple_of_32, zeroed_f_vec};

use super::{
    columns::{KeccakMemCols, NUM_KECCAK_MEM_COLS},
    KeccakPermuteChip, STATE_SIZE,
};
use sp1_core_executor::events::ByteRecord;

impl<F: PrimeField32> MachineAir<F> for KeccakPermuteChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        "KeccakPermute"
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
                ops.iter().for_each(|(syscall_event, op)| {
                    if let PrecompileEvent::KeccakPermute(event) = op {
                        if syscall_event.trap_error.is_none() {
                            Self::populate_chunk(event, &mut chunk, &mut blu);
                        }
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

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.get_precompile_events(SyscallCode::KECCAK_PERMUTE).len() * NUM_ROUNDS;
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let padded_nb_rows = <KeccakPermuteChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = input.get_precompile_events(SyscallCode::KECCAK_PERMUTE);
        let num_events = events.len();
        let chunk_size = 8;
        let num_event_rows = events.len() * NUM_ROUNDS;

        unsafe {
            let padding_start = num_event_rows * NUM_KECCAK_MEM_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_KECCAK_MEM_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * NUM_KECCAK_MEM_COLS)
        };

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
                                if events[idx].0.trap_error.is_none() {
                                    Self::populate_chunk(
                                        event,
                                        rounds,
                                        &mut new_byte_lookup_events,
                                    );
                                } else {
                                    rounds.copy_from_slice(&dummy_chunk[..rounds.len()]);
                                }
                            } else {
                                unreachable!();
                            }
                        } else {
                            rounds.copy_from_slice(&dummy_chunk[..rounds.len()]);
                        }
                    },
                );
            });
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
        _: &mut Vec<ByteLookupEvent>,
    ) {
        let p3_keccak_trace = generate_trace_rows::<F>(vec![event.pre_state]);

        // Create all the rows for the permutation.
        for i in 0..NUM_ROUNDS {
            let p3_keccak_row = p3_keccak_trace.row(i);
            let row = &mut chunk[i * NUM_KECCAK_MEM_COLS..(i + 1) * NUM_KECCAK_MEM_COLS];
            // Copy p3_keccak_row into start of cols
            row[..NUM_KECCAK_COLS].copy_from_slice(p3_keccak_row.collect::<Vec<_>>().as_slice());
            let cols: &mut KeccakMemCols<F> = row.borrow_mut();
            cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);
            cols.state_addr = [
                F::from_canonical_u16((event.state_addr & 0xFFFF) as u16),
                F::from_canonical_u16((event.state_addr >> 16) as u16),
                F::from_canonical_u16((event.state_addr >> 32) as u16),
            ];
            cols.index = F::from_canonical_u32(i as u32);
            cols.is_real = F::one();
        }
    }
}
