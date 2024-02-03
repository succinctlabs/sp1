use crate::{
    cpu::{MemoryReadRecord, MemoryWriteRecord},
    precompiles::{poseidon2::Poseidon2ExternalEvent, PrecompileRuntime},
    runtime::Register,
};

use super::{columns::POSEIDON2_DEFAULT_EXTERNAL_ROUNDS, Poseidon2ExternalChip};

/// Poseidon2 external precompile execution. `NUM_WORDS_STATE` is the number of words in the state.
impl<const NUM_WORDS_STATE: usize> Poseidon2ExternalChip<NUM_WORDS_STATE> {
    // TODO: How do I calculate this? I just copied and pasted these from sha as a starting point.
    pub const NUM_CYCLES: u32 = (8 * POSEIDON2_DEFAULT_EXTERNAL_ROUNDS * NUM_WORDS_STATE) as u32;

    pub fn execute(rt: &mut PrecompileRuntime) -> (u32, Poseidon2ExternalEvent<NUM_WORDS_STATE>) {
        // Read `w_ptr` from register a0.
        let state_ptr = rt.register_unsafe(Register::X10);

        // Set the clock back to the original value and begin executing the
        // precompile.
        let saved_clk = rt.clk;
        let saved_state_ptr = state_ptr;
        let mut state_read_records =
            [[MemoryReadRecord::default(); NUM_WORDS_STATE]; POSEIDON2_DEFAULT_EXTERNAL_ROUNDS];
        let mut state_write_records =
            [[MemoryWriteRecord::default(); NUM_WORDS_STATE]; POSEIDON2_DEFAULT_EXTERNAL_ROUNDS];

        for round in 0..POSEIDON2_DEFAULT_EXTERNAL_ROUNDS {
            // Read the state.
            for i in 0..NUM_WORDS_STATE {
                let (record, value) = rt.mr(state_ptr + (i as u32) * 4);
                state_read_records[round][i] = record;
                // TODO: Remove this debugging statement.
                println!("clk: {} value: {}", rt.clk, value);
                // hx[i] = value;
                rt.clk += 4;
            }

            // TODO: This is where we'll do some operations and calculate the next value.

            // Write the state.
            for i in 0..NUM_WORDS_STATE {
                // Adding back 100 + i as specified in the test program.
                let record = rt.mw(state_ptr.wrapping_add((i as u32) * 4), 100 + i as u32);
                state_write_records[round][i] = record;
                rt.clk += 4;
            }
        }

        (
            state_ptr,
            Poseidon2ExternalEvent {
                clk: saved_clk,
                state_ptr: saved_state_ptr,
                state_reads: state_read_records,
                state_writes: state_write_records,
            },
        )
    }
}
