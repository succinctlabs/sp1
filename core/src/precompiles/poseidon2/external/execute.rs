use p3_field::{Field, PrimeField32};

use crate::{
    cpu::{MemoryReadRecord, MemoryWriteRecord},
    precompiles::{
        poseidon2::{external_linear_permute_mut, Poseidon2ExternalEvent},
        PrecompileRuntime,
    },
    runtime::Register,
};

use super::{
    Poseidon2External1Chip, P2_EXTERNAL_ROUND_COUNT, P2_ROUND_CONSTANTS, P2_SBOX_EXPONENT, P2_WIDTH,
};

/// The first external round in Poseidon2.
///
/// TODO: Much of this logic can be shared with the last external round.
impl<F: Field> Poseidon2External1Chip<F>
where
    F: Field + PrimeField32,
{
    pub const NUM_CYCLES: u32 = (8 * P2_EXTERNAL_ROUND_COUNT * P2_WIDTH) as u32;

    pub fn execute(rt: &mut PrecompileRuntime) -> u32 {
        let state_ptr = rt.register_unsafe(Register::X10);

        // Set the clock back to the original value and begin executing the precompile.
        let saved_clk = rt.clk;
        let saved_state_ptr = state_ptr;
        let mut state_read_records =
            [[MemoryReadRecord::default(); P2_WIDTH]; P2_EXTERNAL_ROUND_COUNT];
        let mut state_write_records =
            [[MemoryWriteRecord::default(); P2_WIDTH]; P2_EXTERNAL_ROUND_COUNT];

        for round in 0..P2_EXTERNAL_ROUND_COUNT {
            // Read the state.
            let mut state = [F::zero(); P2_WIDTH];
            for i in 0..P2_WIDTH {
                let (record, value) = rt.mr(state_ptr + (i as u32) * 4);
                state_read_records[round][i] = record;
                rt.clk += 4;
                state[i] = F::from_canonical_u32(value);
            }

            // Step 1: Add the round constant to the state.
            for i in 0..P2_WIDTH {
                state[i] += F::from_wrapped_u32(P2_ROUND_CONSTANTS[round][i]);
            }
            // Step 2: Apply the S-box to the state.
            for i in 0..P2_WIDTH {
                state[i] = state[i].exp_u64(P2_SBOX_EXPONENT as u64);
            }
            // Step 3: External linear permute.
            external_linear_permute_mut::<F, P2_WIDTH>(&mut state);

            // Write the state.
            for i in 0..P2_WIDTH {
                let result = state[i].as_canonical_u32();
                let record = rt.mw(state_ptr.wrapping_add((i as u32) * 4), result);
                state_write_records[round][i] = record;
                rt.clk += 4;
            }
        }

        rt.segment_mut()
            .poseidon2_external_1_events
            .push(Poseidon2ExternalEvent {
                clk: saved_clk,
                state_ptr: saved_state_ptr,
                state_reads: state_read_records,
                state_writes: state_write_records,
            });

        state_ptr
    }
}
