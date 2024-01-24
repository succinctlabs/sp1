use crate::{
    precompiles::keccak256::{constants::RC, KeccakPermuteEvent, NUM_ROUNDS},
    runtime::{AccessPosition, Register, Runtime},
};

use super::KeccakPermuteChip;

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

impl KeccakPermuteChip {
    pub fn execute(rt: &mut Runtime) -> (u32, u32, u32) {
        let t0 = Register::X5;
        let a0 = Register::X10;

        // The number of cycles it takes to perform this precompile.
        const NB_KECCAK_PERMUTE_CYCLES: u32 = NUM_ROUNDS as u32 * 4;

        // Temporarily set the clock to the number of cycles it takes to perform
        // this precompile as reading `(pre|post)image_ptr` happens on this clock.
        rt.clk += NB_KECCAK_PERMUTE_CYCLES;
        let state_ptr = rt.register(a0);

        // Set the CPU table values with some dummy values.
        let (fa, fb, fc) = (state_ptr, rt.rr(t0, AccessPosition::B), 0);
        rt.rw(a0, fa);

        // We'll save the current record and restore it later so that the CPU
        // event gets emitted correctly.
        let t = rt.record;

        // Set the clock back to the original value and begin executing the
        // precompile.
        rt.clk -= NB_KECCAK_PERMUTE_CYCLES;

        let saved_clk = rt.clk;
        let mut state_read_records = Vec::new();
        let mut state_write_records = Vec::new();

        // Read `preimage_ptr` from register a0 or x5.
        let mut state = Vec::new();
        for i in (0..(25 * 2)).step_by(2) {
            let least_sig = rt.mr(state_ptr + i * 4, AccessPosition::Memory);
            state_read_records.push(rt.record.memory);
            let most_sig = rt.mr(state_ptr + (i + 1) * 4, AccessPosition::Memory);
            state_read_records.push(rt.record.memory);
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

        rt.clk += NB_KECCAK_PERMUTE_CYCLES;
        for i in 0..25 {
            let most_sig = ((state[i] >> 32) & 0xFFFFFFFF) as u32;
            let least_sig = (state[i] & 0xFFFFFFFF) as u32;
            rt.mr(state_ptr + (2 * i as u32) * 4, AccessPosition::Memory);
            rt.mw(
                state_ptr + (2 * i as u32) * 4,
                least_sig,
                AccessPosition::Memory,
            );
            state_write_records.push(rt.record.memory);
            rt.mr(state_ptr + (2 * i as u32 + 1) * 4, AccessPosition::Memory);
            rt.mw(
                state_ptr + (2 * i as u32 + 1) * 4,
                most_sig,
                AccessPosition::Memory,
            );
            state_write_records.push(rt.record.memory);
        }

        // Push the Keccak permute event.
        rt.segment.keccak_permute_events.push(KeccakPermuteEvent {
            clk: saved_clk,
            pre_state: saved_state.as_slice().try_into().unwrap(),
            post_state: state.as_slice().try_into().unwrap(),
            state_read_records: state_read_records.as_slice().try_into().unwrap(),
            state_write_records: state_write_records.as_slice().try_into().unwrap(),
            state_addr: state_ptr,
        });

        // Restore the original record.
        rt.record = t;

        (fa, fb, fc)
    }
}
