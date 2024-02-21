use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_keccak_air::{KeccakAir, U64_LIMBS};
use p3_matrix::MatrixRowSlices;

use crate::{
    air::{SP1AirBuilder, SubAirBuilder},
    memory::MemoryCols,
};

use super::{
    columns::{KeccakCols, NUM_KECCAK_COLS},
    KeccakPermuteChip, STATE_NUM_WORDS, STATE_SIZE,
};

impl<F> BaseAir<F> for KeccakPermuteChip {
    fn width(&self) -> usize {
        NUM_KECCAK_COLS
    }
}

impl<AB> Air<AB> for KeccakPermuteChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &KeccakCols<AB::Var> = main.row_slice(0).borrow();

        builder.assert_eq(
            (local.p3_keccak_cols.step_flags[0] + local.p3_keccak_cols.step_flags[23])
                * local.is_real,
            local.do_memory_check,
        );

        // Constrain memory
        for i in 0..STATE_NUM_WORDS as u32 {
            builder.constraint_memory_access(
                local.shard,
                local.clk,
                local.state_addr + AB::Expr::from_canonical_u32(i * 4),
                &local.state_mem[i as usize],
                local.do_memory_check,
            );
        }

        // Verify that local.a values are equal to the memory values when local.step_flags[0] == 1
        // (for the permutation input) and when local.step_flags[23] == 1 (for the permutation output).
        // Memory values are 32 bit values (encoded as 4 8-bit columns).
        // local.a values are 64 bit values (encoded as 4 16 bit columns).
        let expr_2_pow_8 = AB::Expr::from_canonical_u32(2u32.pow(8));

        for i in 0..STATE_SIZE as u32 {
            let least_sig_word = local.state_mem[(i * 2) as usize].value();
            let most_sig_word = local.state_mem[(i * 2 + 1) as usize].value();
            let memory_limbs = [
                least_sig_word.0[0] + least_sig_word.0[1] * expr_2_pow_8.clone(),
                least_sig_word.0[2] + least_sig_word.0[3] * expr_2_pow_8.clone(),
                most_sig_word.0[0] + most_sig_word.0[1] * expr_2_pow_8.clone(),
                most_sig_word.0[2] + most_sig_word.0[3] * expr_2_pow_8.clone(),
            ];

            let y_idx = i / 5;
            let x_idx = i % 5;

            // When step_flags[0] == 1, then verify memory matches with local.p3_keccak_cols.a
            let a_value_limbs = local.p3_keccak_cols.a[y_idx as usize][x_idx as usize];
            for i in 0..U64_LIMBS {
                builder
                    .when(local.p3_keccak_cols.step_flags[0] * local.is_real)
                    .assert_eq(memory_limbs[i].clone(), a_value_limbs[i]);
            }

            // When step_flags[23] == 1, then verify memory matches with local.p3_keccak_cols.a_prime_prime_prime
            for i in 0..U64_LIMBS {
                builder
                    .when(local.p3_keccak_cols.step_flags[23] * local.is_real)
                    .assert_eq(
                        memory_limbs[i].clone(),
                        local
                            .p3_keccak_cols
                            .a_prime_prime_prime(x_idx as usize, y_idx as usize, i),
                    )
            }
        }

        let mut sub_builder =
            SubAirBuilder::<AB, KeccakAir, AB::Var>::new(builder, self.p3_keccak_col_range.clone());

        // Eval the plonky3 keccak air
        self.p3_keccak.eval(&mut sub_builder);
    }
}

#[cfg(test)]
mod test {
    use crate::{
        utils::{setup_logger, tests::KECCAK256_ELF},
        SP1Prover, SP1Verifier,
    };

    use crate::SP1Stdin;
    use rand::Rng;
    use rand::SeedableRng;
    use tiny_keccak::Hasher;

    const NUM_TEST_CASES: usize = 45;

    #[test]
    fn test_keccak_random() {
        setup_logger();
        // Hash random bytes and compare with the reference implementation.
        //rng from seed
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        // let mut rng = rand::thread_rng();
        let mut inputs = Vec::<Vec<u8>>::new();
        let mut outputs = Vec::<[u8; 32]>::new();
        for len in 0..NUM_TEST_CASES {
            let bytes = (0..len * 71).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();
            // println!("len: {}, bytes {:?}", len, bytes);
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

        let mut proof = SP1Prover::prove(KECCAK256_ELF, stdin).unwrap();
        SP1Verifier::verify(KECCAK256_ELF, &proof).unwrap();

        for i in 0..NUM_TEST_CASES {
            let expected = outputs.get(i).unwrap();
            let actual = proof.stdout.read::<[u8; 32]>();
            assert_eq!(expected, &actual);
        }
    }
}
