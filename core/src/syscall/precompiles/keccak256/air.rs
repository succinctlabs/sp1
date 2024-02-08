use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_keccak_air::{KeccakAir, U64_LIMBS};
use p3_matrix::MatrixRowSlices;

use crate::{
    air::{CurtaAirBuilder, SubAirBuilder},
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
    AB: CurtaAirBuilder,
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
                local.segment,
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
