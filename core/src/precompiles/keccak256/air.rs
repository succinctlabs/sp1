use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_keccak_air::{KeccakAir, U64_LIMBS};
use p3_matrix::MatrixRowSlices;

use crate::air::{CurtaAirBuilder, SubAirBuilder};

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

        // Constrain memory
        for i in 0..STATE_NUM_WORDS as u32 {
            // Note that for the padded columns, local.step_flags elements are all zero.
            builder.constraint_memory_access(
                local.segment,
                local.clk,
                local.state_addr + AB::Expr::from_canonical_u32(i * 4),
                local.state_mem[i as usize],
                local.p3_keccak_cols.step_flags[0] + local.p3_keccak_cols.step_flags[23],
            );
        }

        // Verify that local.a values are equal to the memory values when local.step_flags[0] == 1
        // Memory values are 32 bit values (encoded as 4 8-bit columns).
        // local.a values are 64 bit values (encoded as 4 16 bit columns).
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
            let a_value_limbs = local.p3_keccak_cols.a[y_idx as usize][x_idx as usize];
            for i in 0..U64_LIMBS {
                builder
                    .when(local.p3_keccak_cols.step_flags[0])
                    .assert_eq(memory_limbs[i].clone(), a_value_limbs[i]);
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
                builder.when(local.p3_keccak_cols.step_flags[23]).assert_eq(
                    memory_limbs[i].clone(),
                    local
                        .p3_keccak_cols
                        .a_prime_prime_prime(x_idx as usize, y_idx as usize, i),
                )
            }
        }

        let mut sub_builder =
            SubAirBuilder::<AB, KeccakAir, AB::Var>::new(builder, self.p3_keccak_col_range.clone());

        self.p3_keccak.eval(&mut sub_builder);
    }
}
