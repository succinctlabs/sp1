use crate::{
    cpu::{MemoryReadRecord, MemoryWriteRecord},
    runtime::{Register, Syscall},
    syscall::precompiles::SyscallContext,
};

use super::{
    mix, Blake2bCompressInnerChip, Blake2bCompressInnerEvent, MIX_INDEX, MSG_ELE_PER_CALL,
    NUM_MIX_ROUNDS, NUM_MSG_WORDS_PER_CALL, OPERATION_COUNT, SIGMA_PERMUTATIONS, STATE_NUM_WORDS,
    STATE_SIZE,
};

impl Syscall for Blake2bCompressInnerChip {
    fn num_extra_cycles(&self) -> u32 {
        (4 * NUM_MIX_ROUNDS * OPERATION_COUNT) as u32
    }

    fn execute(&self, rt: &mut SyscallContext) -> u32 {
        // TODO: These pointers have to be constrained.
        let state_ptr = rt.register_unsafe(Register::X10);
        let message_ptr = rt.register_unsafe(Register::X11);

        let saved_clk = rt.clk;
        let mut message_reads = [[[MemoryReadRecord::default(); NUM_MSG_WORDS_PER_CALL];
            OPERATION_COUNT]; NUM_MIX_ROUNDS];
        let mut state_writes =
            [[[MemoryWriteRecord::default(); STATE_NUM_WORDS]; OPERATION_COUNT]; NUM_MIX_ROUNDS];

        for round in 0..NUM_MIX_ROUNDS {
            for operation in 0..OPERATION_COUNT {
                let state_index = MIX_INDEX[operation];
                let message_index = [
                    SIGMA_PERMUTATIONS[round][2 * operation],
                    SIGMA_PERMUTATIONS[round][2 * operation + 1],
                ];

                let mut input = vec![];
                // Read the input to mix.
                {
                    for index in state_index.iter() {
                        let lo = rt.word_unsafe(state_ptr + (*index as u32 * 2) * 4);
                        let hi = rt.word_unsafe(state_ptr + (*index as u32 * 2) * 4 + 4);
                        input.push(lo as u64 + ((hi as u64) << 32));
                    }
                    for i in 0..MSG_ELE_PER_CALL {
                        let (record_lo, lo) =
                            rt.mr(message_ptr + (message_index[i] as u32 * 2) * 4);
                        let (record_hi, hi) =
                            rt.mr(message_ptr + (message_index[i] as u32 * 2) * 4 + 4);
                        message_reads[round][operation][2 * i] = record_lo;
                        message_reads[round][operation][2 * i + 1] = record_hi;
                        input.push(lo as u64 + ((hi as u64) << 32));
                    }
                }

                // Call mix.
                let results = mix(input.try_into().unwrap());

                // Write the state.
                for i in 0..STATE_SIZE {
                    let lo = results[i] as u32;
                    let hi = (results[i] >> 32) as u32;
                    state_writes[round][operation][2 * i] =
                        rt.mw(state_ptr + (state_index[i] as u32 * 2) * 4, lo);
                    state_writes[round][operation][2 * i + 1] =
                        rt.mw(state_ptr + (state_index[i] as u32 * 2) * 4 + 4, hi);
                }

                // Increment the clock for the next call of mix.
                rt.clk += 4;
            }
        }

        let shard = rt.current_shard();

        rt.record_mut()
            .blake2b_compress_inner_events
            .push(Blake2bCompressInnerEvent {
                shard,
                clk: saved_clk,
                state_ptr,
                message_reads,
                state_writes,
                message_ptr,
            });

        state_ptr
    }
}
