use core::borrow::Borrow;
use std::iter::once;

use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::AbstractField;
use slop_keccak_air::{NUM_ROUNDS, U64_LIMBS};
use slop_matrix::Matrix;
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, SP1AirBuilder},
    InteractionKind,
};

use super::{
    columns::{KeccakMemCols, NUM_KECCAK_MEM_COLS},
    constants::rc_value_bit,
    KeccakPermuteChip, BITS_PER_LIMB,
};

impl<F> BaseAir<F> for KeccakPermuteChip {
    fn width(&self) -> usize {
        NUM_KECCAK_MEM_COLS
    }
}

impl<AB> Air<AB> for KeccakPermuteChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let local = main.row_slice(0);
        let local: &KeccakMemCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);

        // Keccak AIRs from Plonky3.
        let andn_gen = |a: AB::Expr, b: AB::Expr| b.clone() - a * b;
        let xor_gen = |a: AB::Expr, b: AB::Expr| a.clone() + b.clone() - a * b.double();
        let xor3_gen = |a: AB::Expr, b: AB::Expr, c: AB::Expr| xor_gen(a, xor_gen(b, c));

        // Flag constraints.
        let mut sum_flags = AB::Expr::zero();
        let mut computed_index = AB::Expr::zero();
        for i in 0..NUM_ROUNDS {
            builder.assert_bool(local.keccak.step_flags[i]);
            sum_flags = sum_flags.clone() + local.keccak.step_flags[i];
            computed_index = computed_index.clone()
                + AB::Expr::from_canonical_u32(i as u32) * local.keccak.step_flags[i];
        }
        builder.assert_one(sum_flags);
        builder.when(local.is_real).assert_eq(computed_index, local.index);

        // C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1]).
        for x in 0..5 {
            for z in 0..64 {
                builder.assert_bool(local.keccak.c[x][z]);
                let xor = xor3_gen(
                    local.keccak.c[x][z].into(),
                    local.keccak.c[(x + 4) % 5][z].into(),
                    local.keccak.c[(x + 1) % 5][(z + 63) % 64].into(),
                );
                let c_prime = local.keccak.c_prime[x][z];
                builder.assert_eq(c_prime, xor);
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
                    let a_prime: AB::Var = local.keccak.a_prime[y][x][z];
                    let c: AB::Var = local.keccak.c[x][z];
                    let c_prime: AB::Var = local.keccak.c_prime[x][z];
                    xor3_gen(a_prime.into(), c.into(), c_prime.into())
                };

                for limb in 0..U64_LIMBS {
                    let a_limb = local.keccak.a[y][x][limb];
                    let computed_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                        .rev()
                        .fold(AB::Expr::zero(), |acc, z| {
                            builder.assert_bool(local.keccak.a_prime[y][x][z]);
                            acc.double() + get_bit(z)
                        });
                    builder.assert_eq(computed_limb, a_limb);
                }
            }
        }

        // xor_{i=0}^4 A'[x, i, z] = C'[x, z], so for each x, z,
        // diff * (diff - 2) * (diff - 4) = 0, where
        // diff = sum_{i=0}^4 A'[x, i, z] - C'[x, z]
        for x in 0..5 {
            for z in 0..64 {
                let sum: AB::Expr = (0..5).map(|y| local.keccak.a_prime[y][x][z].into()).sum();
                let diff = sum - local.keccak.c_prime[x][z];
                let four = AB::Expr::from_canonical_u8(4);
                builder
                    .assert_zero(diff.clone() * (diff.clone() - AB::Expr::two()) * (diff - four));
            }
        }

        // A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
        for y in 0..5 {
            for x in 0..5 {
                let get_bit = |z| {
                    let andn = andn_gen(
                        local.keccak.b((x + 1) % 5, y, z).into(),
                        local.keccak.b((x + 2) % 5, y, z).into(),
                    );
                    xor_gen(local.keccak.b(x, y, z).into(), andn)
                };

                for limb in 0..U64_LIMBS {
                    let computed_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                        .rev()
                        .fold(AB::Expr::zero(), |acc, z| acc.double() + get_bit(z));
                    builder.assert_eq(computed_limb, local.keccak.a_prime_prime[y][x][limb]);
                }
            }
        }

        // A'''[0, 0] = A''[0, 0] XOR RC
        for limb in 0..U64_LIMBS {
            let computed_a_prime_prime_0_0_limb = (limb * BITS_PER_LIMB
                ..(limb + 1) * BITS_PER_LIMB)
                .rev()
                .fold(AB::Expr::zero(), |acc, z| {
                    builder.assert_bool(local.keccak.a_prime_prime_0_0_bits[z]);
                    acc.double() + local.keccak.a_prime_prime_0_0_bits[z]
                });
            let a_prime_prime_0_0_limb = local.keccak.a_prime_prime[0][0][limb];
            builder.assert_eq(computed_a_prime_prime_0_0_limb, a_prime_prime_0_0_limb);
        }

        let get_xored_bit = |i| {
            let mut rc_bit_i = AB::Expr::zero();
            for r in 0..NUM_ROUNDS {
                let this_round = local.keccak.step_flags[r];
                let this_round_constant = AB::Expr::from_canonical_u8(rc_value_bit(r, i));
                rc_bit_i = rc_bit_i.clone() + this_round * this_round_constant;
            }

            xor_gen(local.keccak.a_prime_prime_0_0_bits[i].into(), rc_bit_i)
        };

        for limb in 0..U64_LIMBS {
            let a_prime_prime_prime_0_0_limb = local.keccak.a_prime_prime_prime_0_0_limbs[limb];
            let computed_a_prime_prime_prime_0_0_limb = (limb * BITS_PER_LIMB
                ..(limb + 1) * BITS_PER_LIMB)
                .rev()
                .fold(AB::Expr::zero(), |acc, z| acc.double() + get_xored_bit(z));
            builder.assert_eq(computed_a_prime_prime_prime_0_0_limb, a_prime_prime_prime_0_0_limb);
        }

        let receive_values = once(local.clk_high)
            .chain(once(local.clk_low))
            .chain(local.state_addr)
            .chain(once(local.index))
            .chain(
                local
                    .keccak
                    .a
                    .into_iter()
                    .flat_map(|two_d| two_d.into_iter().flat_map(|one_d| one_d.into_iter())),
            )
            .map(Into::into)
            .collect::<Vec<_>>();

        // Receive state.
        builder.receive(
            AirInteraction::new(receive_values, local.is_real.into(), InteractionKind::Keccak),
            InteractionScope::Local,
        );

        let send_values = once(local.clk_high.into())
            .chain(once(local.clk_low.into()))
            .chain(local.state_addr.map(Into::into))
            .chain(once(local.index + AB::Expr::one()))
            .chain((0..5).flat_map(|y| {
                (0..5).flat_map(move |x| {
                    (0..4).map(move |limb| local.keccak.a_prime_prime_prime(y, x, limb).into())
                })
            }))
            .collect::<Vec<_>>();

        // Send state.
        builder.send(
            AirInteraction::new(send_values, local.is_real.into(), InteractionKind::Keccak),
            InteractionScope::Local,
        );
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use crate::{io::SP1Stdin, utils};

    use rand::{Rng, SeedableRng};
    use sp1_core_executor::Program;
    use test_artifacts::KECCAK256_ELF;
    use tiny_keccak::Hasher;

    const NUM_TEST_CASES: usize = 45;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_keccak_random() {
        utils::setup_logger();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let mut inputs = Vec::<Vec<u8>>::new();
        let mut outputs = Vec::<[u8; 32]>::new();
        for len in 0..NUM_TEST_CASES {
            let bytes = (0..len * 71).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();
            inputs.push(bytes.clone());

            let mut keccak = tiny_keccak::Keccak::v256();
            keccak.update(&bytes);
            let mut hash = [0u8; 32];
            keccak.finalize(&mut hash);
            outputs.push(hash);
        }

        let mut stdin = SP1Stdin::new();
        stdin.write(&NUM_TEST_CASES);
        for input in inputs.iter() {
            stdin.write(&input);
        }

        let program = Program::from(&KECCAK256_ELF).unwrap();
        let mut public_values = utils::run_test(Arc::new(program), stdin).await.unwrap();

        for i in 0..NUM_TEST_CASES {
            let expected = outputs.get(i).unwrap();
            let actual = public_values.read::<[u8; 32]>();
            assert_eq!(expected, &actual);
        }
    }
}
