use alloc::vec;
use alloc::vec::Vec;

use p3_field::{PrimeField, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    cpu::MemoryRecord,
    precompiles::keccak256::{
        columns::{KeccakCols, NUM_KECCAK_COLS},
        NUM_ROUNDS,
    },
    runtime::Segment,
    utils::Chip,
};

use super::{
    constants::rc_value_limb,
    logic::{andn, xor},
    KeccakPermuteChip, BITS_PER_LIMB, U64_LIMBS,
};

impl<F: PrimeField> Chip<F> for KeccakPermuteChip {
    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let num_rows = (segment.keccak_permute_events.len() * NUM_ROUNDS).next_power_of_two();
        let mut trace =
            RowMajorMatrix::new(vec![F::zero(); num_rows * NUM_KECCAK_COLS], NUM_KECCAK_COLS);

        let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<KeccakCols<F>>() };
        assert!(prefix.is_empty(), "Data was not aligned");
        assert!(suffix.is_empty(), "Data was not aligned");
        assert_eq!(rows.len(), num_rows);

        const SEGMENT_NUM: u32 = 1;
        let mut new_field_events = Vec::new();
        for i in 0..segment.keccak_permute_events.len() {
            let mut event_rows = rows[i * NUM_ROUNDS..(i + 1) * NUM_ROUNDS];

            let event = &segment.keccak_permute_events[i];
            let clk = event.clk;

            for j in 0..event.state_read_records.len() {
                let state_current_read = MemoryRecord {
                    value: event.pre_state[j],
                    segment: SEGMENT_NUM,
                    timestamp: clk,
                };
                self.populate_access(
                    &mut rows[0].state_mem[j],
                    state_current_read,
                    event.state_read_records[j],
                    &mut new_field_events,
                );
            }

            generate_trace_rows_for_perm(&mut event_rows, event.state, segment, event.clk);

            for j in 0..event.state_write_records.len() {
                let state_current_write = MemoryRecord {
                    value: event.post_state[j],
                    segment: SEGMENT_NUM,
                    timestamp: clk + NUM_ROUNDS as u32 * 4,
                };
                self.populate_access(
                    &mut rows[0].state_mem[j],
                    state_current_write,
                    event.state_write_records[j],
                    &mut new_field_events,
                );
            }
        }

        trace
    }

    fn name(&self) -> String {
        "KeccakPermute".to_string()
    }
}

/// `rows` will normally consist of 24 rows, with an exception for the final row.
fn generate_trace_rows_for_perm<F: PrimeField64>(
    rows: &mut [KeccakCols<F>],
    input: [u64; 25],
    segment: u32,
    start_clk: u32,
) {
    // Populate the preimage for each row.
    for row in rows.iter_mut() {
        for y in 0..5 {
            for x in 0..5 {
                let input_xy = input[y * 5 + x];
                for limb in 0..U64_LIMBS {
                    row.preimage[y][x][limb] =
                        F::from_canonical_u64((input_xy >> (16 * limb)) & 0xFFFF);
                }
            }
        }
    }

    // Populate the round input for the first round.
    for y in 0..5 {
        for x in 0..5 {
            let input_xy = input[y * 5 + x];
            for limb in 0..U64_LIMBS {
                rows[0].a[y][x][limb] = F::from_canonical_u64((input_xy >> (16 * limb)) & 0xFFFF);
            }
        }
    }

    rows[0].clk = start_clk;
    rows[0].segment = segment;
    generate_trace_row_for_round(&mut rows[0], 0);

    for round in 1..rows.len() {
        // Copy previous row's output to next row's input.
        for y in 0..5 {
            for x in 0..5 {
                for limb in 0..U64_LIMBS {
                    rows[round].a[y][x][limb] = rows[round - 1].a_prime_prime_prime(x, y, limb);
                }
            }
        }

        rows[round].clk = start_clk + round * 4;
        rows[round].segment = segment;
        generate_trace_row_for_round(&mut rows[round], round);
    }
}

fn generate_trace_row_for_round<F: PrimeField64>(row: &mut KeccakCols<F>, round: usize) {
    row.step_flags[round] = F::one();

    // Populate C[x] = xor(A[x, 0], A[x, 1], A[x, 2], A[x, 3], A[x, 4]).
    for x in 0..5 {
        for z in 0..64 {
            let limb = z / BITS_PER_LIMB;
            let bit_in_limb = z % BITS_PER_LIMB;
            let a = [0, 1, 2, 3, 4].map(|i| {
                let a_limb = row.a[i][x][limb].as_canonical_u64() as u16;
                F::from_bool(((a_limb >> bit_in_limb) & 1) != 0)
            });
            row.c[x][z] = xor(a);
        }
    }

    // Populate C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1]).
    for x in 0..5 {
        for z in 0..64 {
            row.c_prime[x][z] = xor([
                row.c[x][z],
                row.c[(x + 4) % 5][z],
                row.c[(x + 1) % 5][(z + 63) % 64],
            ]);
        }
    }

    // Populate A'. To avoid shifting indices, we rewrite
    //     A'[x, y, z] = xor(A[x, y, z], C[x - 1, z], C[x + 1, z - 1])
    // as
    //     A'[x, y, z] = xor(A[x, y, z], C[x, z], C'[x, z]).
    for x in 0..5 {
        for y in 0..5 {
            for z in 0..64 {
                let limb = z / BITS_PER_LIMB;
                let bit_in_limb = z % BITS_PER_LIMB;
                let a_limb = row.a[y][x][limb].as_canonical_u64() as u16;
                let a_bit = F::from_bool(((a_limb >> bit_in_limb) & 1) != 0);
                row.a_prime[x][y][z] = xor([a_bit, row.c[x][z], row.c_prime[x][z]]);
            }
        }
    }

    // Populate A''.
    // A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
    for y in 0..5 {
        for x in 0..5 {
            for limb in 0..U64_LIMBS {
                row.a_prime_prime[y][x][limb] = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                    .rev()
                    .fold(F::zero(), |acc, z| {
                        let bit = xor([
                            row.b(x, y, z),
                            andn(row.b((x + 1) % 5, y, z), row.b((x + 2) % 5, y, z)),
                        ]);
                        acc.double() + bit
                    });
            }
        }
    }

    // For the XOR, we split A''[0, 0] to bits.
    let mut val = 0;
    for limb in 0..U64_LIMBS {
        let val_limb = row.a_prime_prime[0][0][limb].as_canonical_u64();
        val |= val_limb << (limb * BITS_PER_LIMB);
    }
    let val_bits: Vec<bool> = (0..64)
        .scan(val, |acc, _| {
            let bit = (*acc & 1) != 0;
            *acc >>= 1;
            Some(bit)
        })
        .collect();
    for (i, bit) in row.a_prime_prime_0_0_bits.iter_mut().enumerate() {
        *bit = F::from_bool(val_bits[i]);
    }

    // A''[0, 0] is additionally xor'd with RC.
    for limb in 0..U64_LIMBS {
        let rc_lo = rc_value_limb(round, limb);
        row.a_prime_prime_prime_0_0_limbs[limb] =
            F::from_canonical_u16(row.a_prime_prime[0][0][limb].as_canonical_u64() as u16 ^ rc_lo);
    }
}
