use core::array;
use core::mem::transmute;

use slop_algebra::PrimeField32;
use slop_matrix::dense::RowMajorMatrix;
use slop_maybe_rayon::iter::repeat;
use slop_maybe_rayon::prelude::*;

use crate::columns::{KeccakCols, NUM_KECCAK_COLS};
use crate::constants::{R, RC};
use crate::{BITS_PER_LIMB, NUM_ROUNDS, RC_BIT_POSITIONS, U64_LIMBS};

pub fn generate_trace_rows<F: PrimeField32>(inputs: Vec<[u64; 25]>) -> RowMajorMatrix<F> {
    let num_rows = (inputs.len() * NUM_ROUNDS).next_power_of_two();
    let mut trace =
        RowMajorMatrix::new(vec![F::zero(); num_rows * NUM_KECCAK_COLS], NUM_KECCAK_COLS);
    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<KeccakCols<F>>() };
    assert!(prefix.is_empty(), "alignment should match");
    assert!(suffix.is_empty(), "alignment should match");
    assert_eq!(rows.len(), num_rows);

    let num_padding_inputs = num_rows.div_ceil(NUM_ROUNDS) - inputs.len();
    let padded_inputs = inputs.into_par_iter().chain(repeat([0; 25]).take(num_padding_inputs));

    rows.par_chunks_mut(NUM_ROUNDS).zip(padded_inputs).for_each(|(round_rows, input)| {
        generate_trace_rows_for_perm(round_rows, input);
    });

    trace
}

fn generate_trace_rows_for_perm<F: PrimeField32>(rows: &mut [KeccakCols<F>], input: [u64; 25]) {
    let transmuted: [[u64; 5]; 5] = unsafe { transmute(input) };
    let mut state = array::from_fn(|x| array::from_fn(|y| transmuted[y][x]));

    for (round, row) in rows.iter_mut().enumerate() {
        generate_trace_row_for_round(row, round, &mut state);
    }
}

fn generate_trace_row_for_round<F: PrimeField32>(
    row: &mut KeccakCols<F>,
    round: usize,
    state: &mut [[u64; 5]; 5],
) {
    row.step_flags[round] = F::one();

    for (x, column) in state.iter().enumerate() {
        for (y, lane) in column.iter().enumerate() {
            for limb in 0..U64_LIMBS {
                row.input_limbs[y][x][limb] =
                    F::from_canonical_u16((*lane >> (limb * BITS_PER_LIMB)) as u16);
            }
        }
    }

    let c: [u64; 5] = state.map(|column| column.into_iter().fold(0, |acc, lane| acc ^ lane));
    for (x, parity) in c.iter().enumerate() {
        for z in 0..64 {
            row.c[x][z] = F::from_bool((parity >> z) & 1 == 1);
        }
    }

    let c_prime: [u64; 5] =
        array::from_fn(|x| c[x] ^ c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1));
    for (x, parity) in c_prime.iter().enumerate() {
        for z in 0..64 {
            row.c_prime[x][z] = F::from_bool((parity >> z) & 1 == 1);
        }
    }

    *state = array::from_fn(|x| array::from_fn(|y| state[x][y] ^ c[x] ^ c_prime[x]));
    for (x, column) in state.iter().enumerate() {
        for (y, lane) in column.iter().enumerate() {
            for z in 0..64 {
                row.a_prime[y][x][z] = F::from_bool((lane >> z) & 1 == 1);
            }
        }
    }

    *state = array::from_fn(|x| {
        array::from_fn(|y| {
            let source_x = (x + 3 * y) % 5;
            let source_y = x;
            state[source_x][source_y].rotate_left(R[source_x][source_y] as u32)
        })
    });

    *state = array::from_fn(|x| {
        array::from_fn(|y| state[x][y] ^ ((!state[(x + 1) % 5][y]) & state[(x + 2) % 5][y]))
    });

    for (index, bit) in RC_BIT_POSITIONS.into_iter().enumerate() {
        row.a_prime_prime_0_0_rc_bits[index] = F::from_bool((state[0][0] >> bit) & 1 == 1);
    }

    state[0][0] ^= RC[round];
    for (x, column) in state.iter().enumerate() {
        for (y, lane) in column.iter().enumerate() {
            for limb in 0..U64_LIMBS {
                row.output_limbs[y][x][limb] =
                    F::from_canonical_u16((*lane >> (limb * BITS_PER_LIMB)) as u16);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_matches_keccak_f() {
        type F = slop_baby_bear::BabyBear;

        let input = array::from_fn(|i| (i as u64).wrapping_mul(0x0123_4567_89ab_cdef));
        let mut expected = input;
        tiny_keccak::keccakf(&mut expected);

        let trace = generate_trace_rows::<F>(vec![input]);
        let (prefix, rows, suffix) = unsafe { trace.values.align_to::<KeccakCols<F>>() };
        assert!(prefix.is_empty());
        assert!(suffix.is_empty());
        let last = &rows[NUM_ROUNDS - 1];

        let output = array::from_fn(|index| {
            let x = index % 5;
            let y = index / 5;
            (0..4).fold(0, |acc, limb| {
                let value = last.output_limbs[y][x][limb].as_canonical_u32() as u64;
                acc | (value << (limb * 16))
            })
        });

        assert_eq!(output, expected);
    }
}
