use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_matrix::MatrixRowSlices;

use crate::air::CurtaAirBuilder;

use super::{
    columns::{KeccakCols, NUM_KECCAK_COLS},
    constants::rc_value_bit,
    logic::{andn_gen, xor3_gen, xor_gen},
    round_flags::eval_round_flags,
    KeccakPermuteChip, BITS_PER_LIMB, NUM_ROUNDS, STATE_NUM_WORDS, STATE_SIZE, U64_LIMBS,
};

impl<F> BaseAir<F> for KeccakPermuteChip {
    fn width(&self) -> usize {
        NUM_KECCAK_COLS
    }
}

impl<AB> Air<AB> for KeccakPermuteChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        eval_round_flags(builder);

        let main = builder.main();
        let local: &KeccakCols<AB::Var> = main.row_slice(0).borrow();
        let next: &KeccakCols<AB::Var> = main.row_slice(1).borrow();

        // Constrain memory
        for i in 0..STATE_NUM_WORDS as u32 {
            // Note that for the padded columns, local.step_flags elements are all zero.
            builder.constraint_memory_access(
                local.segment,
                local.clk,
                local.state_addr + AB::Expr::from_canonical_u32(i * 4),
                local.state_mem[i as usize],
                local.step_flags[0] + local.step_flags[23],
            );
        }

        // Verify that local.a values are equal to the memory values when local.step_flags[0] == 1
        // Memory values are 32 bit values (encoded as 4 8-bit columns).
        // local.a values are 64 bit values (encoded as 4 16 bit columns).
        for i in 0..STATE_SIZE as u32 {
            let most_sig_word = local.state_mem[(i * 2) as usize].value;
            let least_sig_word = local.state_mem[(i * 2 + 1) as usize].value;
            let memory_limbs = vec![
                least_sig_word.0[0]
                    + least_sig_word.0[1] * AB::Expr::from_canonical_u32(2u32.pow(8)),
                least_sig_word.0[2]
                    + least_sig_word.0[3] * AB::Expr::from_canonical_u32(2u32.pow(8)),
                most_sig_word.0[0] + most_sig_word.0[1] * AB::Expr::from_canonical_u32(2u32.pow(8)),
                most_sig_word.0[2] + most_sig_word.0[3] * AB::Expr::from_canonical_u32(2u32.pow(8)),
            ];

            let y_idx = i / 5;
            let x_idx = i % 5;
            let a_value_limbs = local.a[y_idx as usize][x_idx as usize];
            for i in 0..U64_LIMBS {
                builder
                    .when(local.step_flags[0])
                    .assert_eq(memory_limbs[i].clone(), a_value_limbs[i]);
            }
        }

        // The export flag must be 0 or 1.
        builder.assert_bool(local.export);

        // If this is not the final step, the export flag must be off.
        let final_step = local.step_flags[NUM_ROUNDS - 1];
        let not_final_step = AB::Expr::one() - final_step;
        builder
            .when(not_final_step.clone())
            .assert_zero(local.export);

        // If this is not the final step, the local and next preimages must match.
        for y in 0..5 {
            for x in 0..5 {
                for limb in 0..U64_LIMBS {
                    builder
                        .when_transition()
                        .when(not_final_step.clone())
                        .when(local.is_real)
                        .assert_eq(local.preimage[y][x][limb], next.preimage[y][x][limb]);
                }
            }
        }

        // C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1]).
        for x in 0..5 {
            for z in 0..64 {
                let xor = xor3_gen::<AB::Expr>(
                    local.c[x][z].into(),
                    local.c[(x + 4) % 5][z].into(),
                    local.c[(x + 1) % 5][(z + 63) % 64].into(),
                );
                let c_prime = local.c_prime[x][z];
                builder.when(local.is_real).assert_eq(c_prime, xor);
            }
        }

        // Check that the input limbs are consistent with A' and D.
        // A[x, y, z] = xor(A'[x, y, z], D[x, y, z])
        //            = xor(A'[x, y, z], C[x - 1, z], C[x + 1, z - 1])
        //            = xor(A'[x, y, z], C[x, z], C'[x, z]).
        // The last step is valid based on the identity we checked above.
        // It isn't required, but makes this check a bit cleaner.
        for y in 0..5 {
            for x in 0..5 {
                let get_bit = |z| {
                    let a_prime: AB::Var = local.a_prime[y][x][z];
                    let c: AB::Var = local.c[x][z];
                    let c_prime: AB::Var = local.c_prime[x][z];
                    xor3_gen::<AB::Expr>(a_prime.into(), c.into(), c_prime.into())
                };

                for limb in 0..U64_LIMBS {
                    let a_limb = local.a[y][x][limb];
                    let computed_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                        .rev()
                        .fold(AB::Expr::zero(), |acc, z| acc.double() + get_bit(z));
                    builder.when(local.is_real).assert_eq(computed_limb, a_limb);
                }
            }
        }

        // xor_{i=0}^4 A'[x, i, z] = C'[x, z], so for each x, z,
        // diff * (diff - 2) * (diff - 4) = 0, where
        // diff = sum_{i=0}^4 A'[x, i, z] - C'[x, z]
        for x in 0..5 {
            for z in 0..64 {
                let sum: AB::Expr = (0..5).map(|y| local.a_prime[y][x][z].into()).sum();
                let diff = sum - local.c_prime[x][z];
                let four = AB::Expr::from_canonical_u8(4);
                builder
                    .when(local.is_real)
                    .assert_zero(diff.clone() * (diff.clone() - AB::Expr::two()) * (diff - four));
            }
        }

        // A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
        for y in 0..5 {
            for x in 0..5 {
                let get_bit = |z| {
                    let andn = andn_gen::<AB::Expr>(
                        local.b((x + 1) % 5, y, z).into(),
                        local.b((x + 2) % 5, y, z).into(),
                    );
                    xor_gen::<AB::Expr>(local.b(x, y, z).into(), andn)
                };

                for limb in 0..U64_LIMBS {
                    let computed_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                        .rev()
                        .fold(AB::Expr::zero(), |acc, z| acc.double() + get_bit(z));
                    builder
                        .when(local.is_real)
                        .assert_eq(computed_limb, local.a_prime_prime[y][x][limb]);
                }
            }
        }

        // A'''[0, 0] = A''[0, 0] XOR RC
        for limb in 0..U64_LIMBS {
            let computed_a_prime_prime_0_0_limb = (limb * BITS_PER_LIMB
                ..(limb + 1) * BITS_PER_LIMB)
                .rev()
                .fold(AB::Expr::zero(), |acc, z| {
                    acc.double() + local.a_prime_prime_0_0_bits[z]
                });
            let a_prime_prime_0_0_limb = local.a_prime_prime[0][0][limb];
            builder
                .when(local.is_real)
                .assert_eq(computed_a_prime_prime_0_0_limb, a_prime_prime_0_0_limb);
        }

        let get_xored_bit = |i| {
            let mut rc_bit_i = AB::Expr::zero();
            for r in 0..NUM_ROUNDS {
                let this_round = local.step_flags[r];
                let this_round_constant = AB::Expr::from_canonical_u8(rc_value_bit(r, i));
                rc_bit_i += this_round * this_round_constant;
            }

            xor_gen::<AB::Expr>(local.a_prime_prime_0_0_bits[i].into(), rc_bit_i)
        };

        for limb in 0..U64_LIMBS {
            let a_prime_prime_prime_0_0_limb = local.a_prime_prime_prime_0_0_limbs[limb];
            let computed_a_prime_prime_prime_0_0_limb = (limb * BITS_PER_LIMB
                ..(limb + 1) * BITS_PER_LIMB)
                .rev()
                .fold(AB::Expr::zero(), |acc, z| acc.double() + get_xored_bit(z));
            builder.when(local.is_real).assert_eq(
                computed_a_prime_prime_prime_0_0_limb,
                a_prime_prime_prime_0_0_limb,
            );
        }

        // Enforce that this round's output equals the next round's input.
        for x in 0..5 {
            for y in 0..5 {
                for limb in 0..U64_LIMBS {
                    let output = local.a_prime_prime_prime(x, y, limb);
                    let input = next.a[y][x][limb];
                    builder
                        .when_transition()
                        .when(local.is_real)
                        .when(not_final_step.clone())
                        .assert_eq(output, input);
                }
            }
        }

        // Verify that the memory values are the same as a_prime_prime_prime when local.step_flags[23] == 1
        for i in 0..STATE_SIZE as u32 {
            let least_sig_word = local.state_mem[(i * 2) as usize].value;
            let most_sig_word = local.state_mem[(i * 2 + 1) as usize].value;
            let memory_limbs = vec![
                least_sig_word.0[0]
                    + least_sig_word.0[1] * AB::Expr::from_canonical_u32(2u32.pow(8)),
                least_sig_word.0[2]
                    + least_sig_word.0[3] * AB::Expr::from_canonical_u32(2u32.pow(8)),
                most_sig_word.0[0] + most_sig_word.0[1] * AB::Expr::from_canonical_u32(2u32.pow(8)),
                most_sig_word.0[2] + most_sig_word.0[3] * AB::Expr::from_canonical_u32(2u32.pow(8)),
            ];

            let y_idx = i / 5;
            let x_idx = i % 5;
            for i in 0..U64_LIMBS {
                builder.when(local.step_flags[23]).assert_eq(
                    memory_limbs[i].clone(),
                    local.a_prime_prime_prime(x_idx as usize, y_idx as usize, i),
                )
            }
        }
    }
}
