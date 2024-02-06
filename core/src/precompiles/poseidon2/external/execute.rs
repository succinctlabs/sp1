use std::ops::Add;

use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, PrimeField32};

use crate::{
    cpu::{MemoryReadRecord, MemoryWriteRecord},
    precompiles::{
        poseidon2::{external::columns::POSEIDON2_SBOX_EXPONENT, Poseidon2ExternalEvent},
        PrecompileRuntime,
    },
    runtime::Register,
};

use super::{
    columns::{POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS, POSEIDON2_ROUND_CONSTANTS},
    Poseidon2ExternalChip,
};

/// Implements the permutation given by the matrix:
///  ```ignore
///     M4 = [[5, 7, 1, 3],
///           [4, 6, 1, 1],
///           [1, 3, 5, 7],
///           [1, 1, 4, 6]];
///   ```
fn m4_permute_mut<T>(input: &mut [T; 4])
where
    T: Add<Output = T> + Default + Clone,
{
    // Implements the permutation given by the matrix M4 with multiplications unrolled as
    // additions and doublings.
    let mut t_0 = input[0].clone();
    t_0 = t_0 + input[1].clone();
    let mut t_1 = input[2].clone();
    t_1 = t_1 + input[3].clone();
    let mut t_2 = input[1].clone();
    t_2 = t_2.clone() + t_2.clone();
    t_2 = t_2.clone() + t_1.clone();
    let mut t_3 = input[3].clone();
    t_3 = t_3.clone() + t_3.clone();
    t_3 = t_3.clone() + t_0.clone();
    let mut t_4 = t_1.clone();
    t_4 = t_4.clone() + t_4.clone();
    t_4 = t_4.clone() + t_4.clone();
    t_4 = t_4.clone() + t_3.clone();
    let mut t_5 = t_0.clone();
    t_5 = t_5.clone() + t_5.clone();
    t_5 = t_5.clone() + t_5.clone();
    t_5 = t_5.clone() + t_2.clone();
    let mut t_6 = t_3.clone();
    t_6 = t_6.clone() + t_5.clone();
    let mut t_7 = t_2.clone();
    t_7 = t_7.clone() + t_4.clone();
    input[0] = t_6;
    input[1] = t_5;
    input[2] = t_7;
    input[3] = t_4;
}

fn matmul_m4<T, const NUM_WORDS_STATE: usize>(input: &mut [T; NUM_WORDS_STATE])
where
    T: Add<Output = T> + Default + Clone,
{
    input
        .chunks_exact_mut(4)
        .for_each(|x| m4_permute_mut(x.try_into().unwrap()));
}

pub fn external_linear_permute_mut<T, const NUM_WORDS_STATE: usize>(
    input: &mut [T; NUM_WORDS_STATE],
) where
    T: Add<Output = T> + Default + Clone,
{
    match NUM_WORDS_STATE {
        16 => {
            // First, apply Diag(M4, ..., M4).
            matmul_m4(input);

            let t4 = NUM_WORDS_STATE / 4;
            // Four 0's.
            let mut stored = [T::default(), T::default(), T::default(), T::default()];
            for l in 0..4 {
                stored[l] = input[l].clone();
                for j in 1..t4 {
                    stored[l] = stored[l].clone() + input[j * 4 + l].clone();
                }
            }
            for i in 0..NUM_WORDS_STATE {
                input[i] = input[i].clone() + stored[i % 4].clone();
            }
        }
        _ => unimplemented!(),
    }
}

/// Poseidon2 external precompile execution. `NUM_WORDS_STATE` is the number of words in the state.
impl<const NUM_WORDS_STATE: usize> Poseidon2ExternalChip<NUM_WORDS_STATE> {
    // TODO: How do I calculate this? I just copied and pasted these from sha as a starting point.
    pub const NUM_CYCLES: u32 =
        (8 * POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS * NUM_WORDS_STATE) as u32;

    pub fn execute(rt: &mut PrecompileRuntime) -> (u32, Poseidon2ExternalEvent<NUM_WORDS_STATE>) {
        // Read `w_ptr` from register a0.
        let state_ptr = rt.register_unsafe(Register::X10);

        // Set the clock back to the original value and begin executing the
        // precompile.
        let saved_clk = rt.clk;
        let saved_state_ptr = state_ptr;
        let mut state_read_records = [[MemoryReadRecord::default(); NUM_WORDS_STATE];
            POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS];
        let mut state_write_records = [[MemoryWriteRecord::default(); NUM_WORDS_STATE];
            POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS];

        // TODO: Maybe it's better to make this a const generic? Or is that an overkill?
        type F = BabyBear;

        for round in 0..POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS {
            // Read the state.
            let mut state = [F::zero(); NUM_WORDS_STATE];
            for i in 0..NUM_WORDS_STATE {
                let (record, value) = rt.mr(state_ptr + (i as u32) * 4);
                state_read_records[round][i] = record;
                // TODO: Remove this debugging statement.
                println!("clk: {} value: {}", rt.clk, value);
                rt.clk += 4;
                state[i] = F::from_canonical_u32(value);
            }

            // TODO: This is where we'll do some operations and calculate the next value.
            // Step 1: Add the round constant to the state.
            for i in 0..NUM_WORDS_STATE {
                state[i] += F::from_canonical_u32(POSEIDON2_ROUND_CONSTANTS[round][i]);
            }
            // Step 2: Apply the S-box to the state.
            for i in 0..NUM_WORDS_STATE {
                state[i] = state[i].exp_u64(POSEIDON2_SBOX_EXPONENT as u64);
            }
            // Step 3: External linear permute.
            external_linear_permute_mut::<F, NUM_WORDS_STATE>(&mut state);

            // Write the state.
            for i in 0..NUM_WORDS_STATE {
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
