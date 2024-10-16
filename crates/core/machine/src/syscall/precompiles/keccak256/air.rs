use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_keccak_air::{KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS, U64_LIMBS};
use p3_matrix::Matrix;
use sp1_core_executor::syscalls::SyscallCode;
use sp1_stark::air::{InteractionScope, SP1AirBuilder, SubAirBuilder};

use super::{
    columns::{KeccakMemCols, NUM_KECCAK_MEM_COLS},
    KeccakPermuteChip, STATE_NUM_WORDS, STATE_SIZE,
};
use crate::{
    air::{MemoryAirBuilder, WordAirBuilder},
    memory::MemoryCols,
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

        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &KeccakMemCols<AB::Var> = (*local).borrow();
        let next: &KeccakMemCols<AB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        let first_step = local.keccak.step_flags[0];
        let final_step = local.keccak.step_flags[NUM_ROUNDS - 1];
        let not_final_step = AB::Expr::one() - final_step;

        // Constrain memory in the first and last cycles.
        builder.assert_eq((first_step + final_step) * local.is_real, local.do_memory_check);

        // Constrain memory
        for i in 0..STATE_NUM_WORDS as u32 {
            // At the first cycle, verify that the memory has not changed since it's a memory read.
            builder.when(local.keccak.step_flags[0] * local.is_real).assert_word_eq(
                *local.state_mem[i as usize].value(),
                *local.state_mem[i as usize].prev_value(),
            );

            builder.eval_memory_access(
                local.shard,
                local.clk + final_step, // The clk increments by 1 after a final step
                local.state_addr + AB::Expr::from_canonical_u32(i * 4),
                &local.state_mem[i as usize],
                local.do_memory_check,
            );
        }

        // Receive the syscall in the first row of each 24-cycle
        builder.assert_eq(local.receive_ecall, first_step * local.is_real);
        builder.receive_syscall(
            local.shard,
            local.clk,
            local.nonce,
            AB::F::from_canonical_u32(SyscallCode::KECCAK_PERMUTE.syscall_id()),
            local.state_addr,
            AB::Expr::zero(),
            local.receive_ecall,
            InteractionScope::Local,
        );

        // Constrain that the inputs stay the same throughout the 24 rows of each cycle
        let mut transition_builder = builder.when_transition();
        let mut transition_not_final_builder = transition_builder.when(not_final_step);
        transition_not_final_builder.assert_eq(local.shard, next.shard);
        transition_not_final_builder.assert_eq(local.clk, next.clk);
        transition_not_final_builder.assert_eq(local.state_addr, next.state_addr);
        transition_not_final_builder.assert_eq(local.is_real, next.is_real);

        // The last row must be nonreal because NUM_ROUNDS is not a power of 2. This constraint
        // ensures that the table does not end abruptly.
        builder.when_last_row().assert_zero(local.is_real);

        // Verify that local.a values are equal to the memory values in the 0 and 23rd rows of each
        // cycle Memory values are 32 bit values (encoded as 4 8-bit columns).
        // local.a values are 64 bit values (encoded as 4 16-bit columns).
        let expr_2_pow_8 = AB::Expr::from_canonical_u32(2u32.pow(8));
        for i in 0..STATE_SIZE as u32 {
            // Interpret u32 memory words as u16 limbs
            let least_sig_word = local.state_mem[(i * 2) as usize].value();
            let most_sig_word = local.state_mem[(i * 2 + 1) as usize].value();
            let memory_limbs = [
                least_sig_word[0] + least_sig_word[1] * expr_2_pow_8.clone(),
                least_sig_word[2] + least_sig_word[3] * expr_2_pow_8.clone(),
                most_sig_word[0] + most_sig_word[1] * expr_2_pow_8.clone(),
                most_sig_word[2] + most_sig_word[3] * expr_2_pow_8.clone(),
            ];

            let y_idx = i / 5;
            let x_idx = i % 5;

            // On a first step row, verify memory matches with local.p3_keccak_cols.a
            let a_value_limbs = local.keccak.a[y_idx as usize][x_idx as usize];
            for i in 0..U64_LIMBS {
                builder
                    .when(first_step * local.is_real)
                    .assert_eq(memory_limbs[i].clone(), a_value_limbs[i]);
            }

            // On a final step row, verify memory matches with
            // local.p3_keccak_cols.a_prime_prime_prime
            for i in 0..U64_LIMBS {
                builder.when(final_step * local.is_real).assert_eq(
                    memory_limbs[i].clone(),
                    local.keccak.a_prime_prime_prime(y_idx as usize, x_idx as usize, i),
                )
            }
        }

        // Range check all the values in `state_mem` to be bytes.
        for i in 0..STATE_NUM_WORDS {
            builder.slice_range_check_u8(&local.state_mem[i].value().0, local.do_memory_check);
        }

        let mut sub_builder =
            SubAirBuilder::<AB, KeccakAir, AB::Var>::new(builder, 0..NUM_KECCAK_COLS);

        // Eval the plonky3 keccak air
        self.p3_keccak.eval(&mut sub_builder);
    }
}

#[cfg(test)]
mod test {
    use crate::{
        io::SP1Stdin,
        riscv::RiscvAir,
        utils::{prove, setup_logger, tests::KECCAK256_ELF},
    };
    use sp1_primitives::io::SP1PublicValues;

    use rand::{Rng, SeedableRng};
    use sp1_core_executor::Program;
    use sp1_stark::{
        baby_bear_poseidon2::BabyBearPoseidon2, CpuProver, SP1CoreOpts, StarkGenericConfig,
    };
    use tiny_keccak::Hasher;

    const NUM_TEST_CASES: usize = 45;

    #[test]
    #[ignore]
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

        let config = BabyBearPoseidon2::new();

        let program = Program::from(KECCAK256_ELF).unwrap();
        let (proof, public_values, _) =
            prove::<_, CpuProver<_, _>>(program, &stdin, config, SP1CoreOpts::default(), None)
                .unwrap();
        let mut public_values = SP1PublicValues::from(&public_values);

        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();
        let machine = RiscvAir::machine(config);
        let (_, vk) = machine.setup(&Program::from(KECCAK256_ELF).unwrap());
        let _ =
            tracing::info_span!("verify").in_scope(|| machine.verify(&vk, &proof, &mut challenger));

        for i in 0..NUM_TEST_CASES {
            let expected = outputs.get(i).unwrap();
            let actual = public_values.read::<[u8; 32]>();
            assert_eq!(expected, &actual);
        }
    }
}
