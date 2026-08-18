use core::borrow::Borrow;
use std::iter::once;

use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::AbstractField;
use slop_keccak_air::{NUM_ROUNDS, RC_BIT_POSITIONS, U64_LIMBS};
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

fn xor<AB: SP1AirBuilder>(a: AB::Expr, b: AB::Expr) -> AB::Expr {
    a.clone() + b.clone() - a * b.double()
}

fn andn<AB: SP1AirBuilder>(a: AB::Expr, b: AB::Expr) -> AB::Expr {
    b.clone() - a * b
}

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

        let mut sum_flags = AB::Expr::zero();
        let mut computed_index = AB::Expr::zero();
        for round in 0..NUM_ROUNDS {
            builder.assert_bool(local.keccak.step_flags[round]);
            sum_flags = sum_flags.clone() + local.keccak.step_flags[round];
            computed_index = computed_index
                + AB::Expr::from_canonical_usize(round) * local.keccak.step_flags[round];
        }
        builder.assert_one(sum_flags);
        builder.when(local.is_real).assert_eq(computed_index, local.index);

        for x in 0..5 {
            for bit in local.keccak.c[x] {
                builder.assert_bool(bit);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                for bit in local.keccak.a_prime[y][x] {
                    builder.assert_bool(bit);
                }
            }
        }

        for x in 0..5 {
            for z in 0..64 {
                let c_prime = xor::<AB>(
                    local.keccak.c[x][z].into(),
                    xor::<AB>(
                        local.keccak.c[(x + 4) % 5][z].into(),
                        local.keccak.c[(x + 1) % 5][(z + 63) % 64].into(),
                    ),
                );
                builder.assert_bool(local.keccak.c_prime[x][z]);
                builder.assert_eq(c_prime, local.keccak.c_prime[x][z]);
                let sum: AB::Expr = (0..5).map(|y| local.keccak.a_prime[y][x][z].into()).sum();
                let diff = sum - local.keccak.c_prime[x][z];
                let four = AB::Expr::from_canonical_u8(4);
                builder
                    .assert_zero(diff.clone() * (diff.clone() - AB::Expr::two()) * (diff - four));
            }
        }

        let chi_bit = |x: usize, y: usize, z: usize| {
            xor::<AB>(
                local.keccak.b(x, y, z).into(),
                andn::<AB>(
                    local.keccak.b((x + 1) % 5, y, z).into(),
                    local.keccak.b((x + 2) % 5, y, z).into(),
                ),
            )
        };
        let chi_limb = |x: usize, y: usize, limb: usize| {
            (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                .rev()
                .fold(AB::Expr::zero(), |acc, z| acc.double() + chi_bit(x, y, z))
        };

        for (index, z) in RC_BIT_POSITIONS.into_iter().enumerate() {
            builder.assert_bool(local.keccak.a_prime_prime_0_0_rc_bits[index]);
            builder.assert_eq(local.keccak.a_prime_prime_0_0_rc_bits[index], chi_bit(0, 0, z));
        }

        for y in 0..5 {
            for x in 0..5 {
                for limb in 0..U64_LIMBS {
                    let input_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB).rev().fold(
                        AB::Expr::zero(),
                        |acc, z| {
                            let d = xor::<AB>(
                                local.keccak.c[(x + 4) % 5][z].into(),
                                local.keccak.c[(x + 1) % 5][(z + 63) % 64].into(),
                            );
                            acc.double() + xor::<AB>(local.keccak.a_prime[y][x][z].into(), d)
                        },
                    );
                    builder.assert_eq(input_limb, local.keccak.input_limbs[y][x][limb]);

                    let mut output_limb = chi_limb(x, y, limb);
                    if x == 0 && y == 0 {
                        for (index, z) in RC_BIT_POSITIONS.into_iter().enumerate() {
                            if z / BITS_PER_LIMB != limb {
                                continue;
                            }
                            let mut rc_bit = AB::Expr::zero();
                            for round in 0..NUM_ROUNDS {
                                rc_bit = rc_bit
                                    + AB::Expr::from_canonical_u8(rc_value_bit(round, z))
                                        * local.keccak.step_flags[round];
                            }
                            let chi: AB::Expr =
                                local.keccak.a_prime_prime_0_0_rc_bits[index].into();
                            let weight = AB::Expr::from_canonical_u32(1 << (z % BITS_PER_LIMB));
                            output_limb =
                                output_limb + weight * rc_bit * (AB::Expr::one() - chi.double());
                        }
                    }
                    builder.assert_eq(output_limb, local.keccak.output_limbs[y][x][limb]);
                }
            }
        }

        let receive_values = once(local.clk_high)
            .chain(once(local.clk_low))
            .chain(local.state_addr)
            .chain(once(local.index))
            .chain(
                local
                    .keccak
                    .input_limbs
                    .into_iter()
                    .flat_map(|two_d| two_d.into_iter().flat_map(|one_d| one_d.into_iter())),
            )
            .map(Into::into)
            .collect::<Vec<_>>();
        builder.receive(
            AirInteraction::new(receive_values, local.is_real.into(), InteractionKind::Keccak),
            InteractionScope::Local,
        );

        let send_values = once(local.clk_high.into())
            .chain(once(local.clk_low.into()))
            .chain(local.state_addr.map(Into::into))
            .chain(once(local.index + AB::Expr::one()))
            .chain(local.keccak.output_limbs.into_iter().flat_map(|two_d| {
                two_d.into_iter().flat_map(|one_d| one_d.into_iter().map(Into::into))
            }))
            .collect::<Vec<_>>();
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
