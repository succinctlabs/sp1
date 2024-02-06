use p3_field::{Field, PrimeField32};

use crate::{
    cpu::{MemoryReadRecord, MemoryWriteRecord},
    precompiles::{
        poseidon2::{
            external::columns::POSEIDON2_SBOX_EXPONENT, external_linear_permute_mut,
            Poseidon2ExternalEvent,
        },
        PrecompileRuntime,
    },
    runtime::Register,
};

use super::{
    columns::{POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS, POSEIDON2_ROUND_CONSTANTS},
    Poseidon2ExternalChip,
};

/// The first external round in Poseidon2.
///
/// TODO: Much of this logic can be shared with the last external round.
impl<F: Field, const WIDTH: usize> Poseidon2ExternalChip<F, WIDTH>
where
    F: Field + PrimeField32,
{
    pub const NUM_CYCLES: u32 = (8 * POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS * WIDTH) as u32;

    pub fn execute(rt: &mut PrecompileRuntime) -> (u32, Poseidon2ExternalEvent<WIDTH>) {
        let state_ptr = rt.register_unsafe(Register::X10);

        // Set the clock back to the original value and begin executing the
        // precompile.
        let saved_clk = rt.clk;
        let saved_state_ptr = state_ptr;
        let mut state_read_records =
            [[MemoryReadRecord::default(); WIDTH]; POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS];
        let mut state_write_records =
            [[MemoryWriteRecord::default(); WIDTH]; POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS];

        for round in 0..POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS {
            // Read the state.
            let mut state = [F::zero(); WIDTH];
            for i in 0..WIDTH {
                let (record, value) = rt.mr(state_ptr + (i as u32) * 4);
                state_read_records[round][i] = record;
                // TODO: Remove this debugging statement.
                println!("clk: {} value: {}", rt.clk, value);
                rt.clk += 4;
                state[i] = F::from_canonical_u32(value);
            }

            // Step 1: Add the round constant to the state.
            for i in 0..WIDTH {
                state[i] += F::from_canonical_u32(POSEIDON2_ROUND_CONSTANTS[round][i]);
            }
            // Step 2: Apply the S-box to the state.
            for i in 0..WIDTH {
                state[i] = state[i].exp_u64(POSEIDON2_SBOX_EXPONENT as u64);
            }
            // Step 3: External linear permute.
            external_linear_permute_mut::<F, WIDTH>(&mut state);

            // Write the state.
            for i in 0..WIDTH {
                let result = state[i].as_canonical_u32();
                let record = rt.mw(state_ptr.wrapping_add((i as u32) * 4), result);
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
