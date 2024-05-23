use p3_keccak_air::{NUM_ROUNDS, RC};

use super::{KeccakPermuteChip, STATE_NUM_WORDS, STATE_SIZE};
use crate::{
    runtime::Syscall,
    syscall::precompiles::{keccak256::KeccakPermuteEvent, SyscallContext},
};

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

impl Syscall for KeccakPermuteChip {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        let start_clk = rt.clk;
        let state_ptr = arg1;
        if arg2 != 0 {
            panic!("Expected arg2 to be 0, got {}", arg2);
        }

        let mut state_read_records = Vec::new();
        let mut state_write_records = Vec::new();

        let mut state = Vec::new();

        let (state_records, state_values) = rt.mr_slice(state_ptr, STATE_NUM_WORDS);
        state_read_records.extend_from_slice(&state_records);

        for values in state_values.chunks_exact(2) {
            let least_sig = values[0];
            let most_sig = values[1];
            state.push(least_sig as u64 + ((most_sig as u64) << 32));
        }

        let saved_state = state.clone();

        for i in 0..NUM_ROUNDS {
            let mut array: [u64; 5 * 5] = [0; 5 * 5];

            // Theta
            for x in 0..5 {
                for y_count in 0..5 {
                    let y = y_count * 5;
                    array[x] ^= state[x + y];
                }
            }

            for x in 0..5 {
                for y_count in 0..5 {
                    let y = y_count * 5;
                    state[y + x] ^= array[(x + 4) % 5] ^ array[(x + 1) % 5].rotate_left(1);
                }
            }

            // Rho and pi
            let mut last = state[1];
            for x in 0..24 {
                array[0] = state[PI[x]];
                state[PI[x]] = last.rotate_left(RHO[x]);
                last = array[0];
            }

            // Chi
            for y_step in 0..5 {
                let y = y_step * 5;

                array[..5].copy_from_slice(&state[y..(5 + y)]);

                for x in 0..5 {
                    state[y + x] = array[x] ^ ((!array[(x + 1) % 5]) & (array[(x + 2) % 5]));
                }
            }

            // Iota
            state[0] ^= RC[i];
        }

        // Increment the clk by 1 before writing because we read from memory at start_clk.
        rt.clk += 1;
        let mut values_to_write = Vec::new();
        for i in 0..STATE_SIZE {
            let most_sig = ((state[i] >> 32) & 0xFFFFFFFF) as u32;
            let least_sig = (state[i] & 0xFFFFFFFF) as u32;
            values_to_write.push(least_sig);
            values_to_write.push(most_sig);
        }

        let write_records = rt.mw_slice(state_ptr, values_to_write.as_slice());
        state_write_records.extend_from_slice(&write_records);

        // Push the Keccak permute event.
        let shard = rt.current_shard();
        let channel = rt.current_channel();
        rt.record_mut()
            .keccak_permute_events
            .push(KeccakPermuteEvent {
                shard,
                channel,
                clk: start_clk,
                pre_state: saved_state.as_slice().try_into().unwrap(),
                post_state: state.as_slice().try_into().unwrap(),
                state_read_records,
                state_write_records,
                state_addr: state_ptr,
            });

        None
    }
}
