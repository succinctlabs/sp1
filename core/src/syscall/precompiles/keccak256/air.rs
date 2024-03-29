use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_keccak_air::{KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS, U64_LIMBS};
use p3_matrix::MatrixRowSlices;

use crate::{
    air::{SP1AirBuilder, SubAirBuilder},
    memory::MemoryCols,
    runtime::SyscallCode,
};

use super::{
    columns::{KeccakMemCols, NUM_KECCAK_MEM_COLS},
    KeccakPermuteChip, STATE_NUM_WORDS, STATE_SIZE,
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

        let local: &KeccakMemCols<AB::Var> = main.row_slice(0).borrow();
        let next: &KeccakMemCols<AB::Var> = main.row_slice(1).borrow();

        // Constrain memory in the first and last cycles
        builder.assert_eq(
            (local.keccak.step_flags[0] + local.keccak.step_flags[23]) * local.is_real,
            local.do_memory_check,
        );

        // Constrain memory
        for i in 0..STATE_NUM_WORDS as u32 {
            builder.constraint_memory_access(
                local.shard,
                local.clk + local.keccak.step_flags[23], // The clk increments by 1 when step_flags[23] == 1
                local.state_addr + AB::Expr::from_canonical_u32(i * 4),
                &local.state_mem[i as usize],
                local.do_memory_check,
            );
        }

        // Receive the syscall in the first row of each 24-cycle
        builder.assert_eq(
            local.receive_ecall,
            local.keccak.step_flags[0] * local.is_real,
        );
        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(SyscallCode::KECCAK_PERMUTE.syscall_id()),
            local.state_addr,
            AB::Expr::zero(),
            local.receive_ecall,
        );

        // Constrain that the inputs stay the same throughout the 24 rows of each cycle
        let mut not_last_in_cycle = local.keccak.step_flags[0].into();
        for i in 1..NUM_ROUNDS - 1 {
            not_last_in_cycle = not_last_in_cycle + local.keccak.step_flags[i];
        }
        builder
            .when_transition()
            .when(not_last_in_cycle.clone() * local.is_real)
            .assert_eq(local.shard, next.shard);
        builder
            .when_transition()
            .when(not_last_in_cycle.clone() * local.is_real)
            .assert_eq(local.clk, next.clk);
        builder
            .when_transition()
            .when(not_last_in_cycle.clone() * local.is_real)
            .assert_eq(local.state_addr, next.state_addr);
        builder
            .when_transition()
            .when(not_last_in_cycle)
            .assert_eq(local.is_real, next.is_real);

        // The last row must be nonreal because NUM_ROUNDS is not a power of 2. This constraint
        // ensures that the table does not end abruptly.
        builder.when_last_row().assert_zero(local.is_real);

        // Verify that local.a values are equal to the memory values in the 0 and 23rd rows of each cycle
        // Memory values are 32 bit values (encoded as 4 8-bit columns).
        // local.a values are 64 bit values (encoded as 4 16 bit columns).
        let expr_2_pow_8 = AB::Expr::from_canonical_u32(2u32.pow(8));
        for i in 0..STATE_SIZE as u32 {
            // Interpret u32 memory words as u16 limbs
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
            let a_value_limbs = local.keccak.a[y_idx as usize][x_idx as usize];
            for i in 0..U64_LIMBS {
                builder
                    .when(local.keccak.step_flags[0] * local.is_real)
                    .assert_eq(memory_limbs[i].clone(), a_value_limbs[i]);
            }

            // When step_flags[23] == 1, then verify memory matches with local.p3_keccak_cols.a_prime_prime_prime
            for i in 0..U64_LIMBS {
                builder
                    .when(local.keccak.step_flags[23] * local.is_real)
                    .assert_eq(
                        memory_limbs[i].clone(),
                        local
                            .keccak
                            .a_prime_prime_prime(x_idx as usize, y_idx as usize, i),
                    )
            }
        }

        let mut sub_builder =
            SubAirBuilder::<AB, KeccakAir, AB::Var>::new(builder, 0..NUM_KECCAK_COLS);

        // Eval the plonky3 keccak air
        self.p3_keccak.eval(&mut sub_builder);
    }
}

#[cfg(feature = "keccak")]
#[cfg(test)]
mod test {
    use crate::SP1Stdin;
    use crate::{
        utils::{setup_logger, tests::KECCAK256_ELF},
        SP1Prover, SP1Verifier,
    };
    use rand::Rng;
    use rand::SeedableRng;
    use tiny_keccak::Hasher;

    const NUM_TEST_CASES: usize = 45;

    #[test]
    fn test_keccak_random() {
        setup_logger();
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

        let mut proof = SP1Prover::prove(KECCAK256_ELF, stdin).unwrap();
        SP1Verifier::verify(KECCAK256_ELF, &proof).unwrap();

        for i in 0..NUM_TEST_CASES {
            let expected = outputs.get(i).unwrap();
            let actual = proof.stdout.read::<[u8; 32]>();
            assert_eq!(expected, &actual);
        }
    }
}
