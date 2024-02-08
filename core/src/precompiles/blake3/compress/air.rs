use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field};

use super::columns::{Blake3CompressInnerCols, NUM_BLAKE3_COMPRESS_INNER_COLS};
use super::Blake3CompressInnerChip;
use crate::air::{CurtaAirBuilder, WORD_SIZE};

use core::borrow::Borrow;
use p3_matrix::MatrixRowSlices;

impl<F> BaseAir<F> for Blake3CompressInnerChip {
    fn width(&self) -> usize {
        NUM_BLAKE3_COMPRESS_INNER_COLS
    }
}

impl<AB> Air<AB> for Blake3CompressInnerChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Blake3CompressInnerCols<AB::Var> = main.row_slice(0).borrow();
        let next: &Blake3CompressInnerCols<AB::Var> = main.row_slice(1).borrow();

        self.constrain_control_flow_flags(builder, local, next);

        self.constrain_memory(builder, local);

        self.constraint_external_ops(builder, local);
    }
}

impl Blake3CompressInnerChip {
    fn constrain_control_flow_flags<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressInnerCols<AB::Var>,
        next: &Blake3CompressInnerCols<AB::Var>,
    ) {
        // // If this is the i-th round, then the next row should be the (i+1)-th round.
        // for i in 0..P2_EXTERNAL_ROUND_COUNT {
        //     builder.when_transition().when(next.is_real).assert_eq(
        //         local.is_round_n[i],
        //         next.is_round_n[(i + 1) % P2_EXTERNAL_ROUND_COUNT],
        //     );
        //     builder.assert_bool(local.is_round_n[i]);
        // }

        // // Exactly one of the is_round_n flags is set.
        // {
        //     let sum_is_round_n = {
        //         let mut acc: AB::Expr = AB::F::zero().into();
        //         for i in 0..P2_EXTERNAL_ROUND_COUNT {
        //             acc += local.is_round_n[i].into();
        //         }
        //         acc
        //     };

        //     builder
        //         .when(local.is_real)
        //         .assert_eq(sum_is_round_n, AB::F::from_canonical_usize(1));
        // }

        // // Calculate the current round number.
        // {
        //     let round = {
        //         let mut acc: AB::Expr = AB::F::zero().into();

        //         for i in 0..P2_EXTERNAL_ROUND_COUNT {
        //             acc += local.is_round_n[i] * AB::F::from_canonical_usize(i);
        //         }
        //         acc
        //     };
        //     builder.assert_eq(round, local.round_number);
        // }

        // // Calculate the round constants for this round.
        // {
        //     for i in 0..P2_WIDTH {
        //         let round_constant = {
        //             let mut acc: AB::Expr = AB::F::zero().into();

        //             for j in 0..P2_EXTERNAL_ROUND_COUNT {
        //                 acc += local.is_round_n[j].into()
        //                     * AB::F::from_wrapped_u32(P2_ROUND_CONSTANTS[j][i]);
        //             }
        //             acc
        //         };
        //         builder.assert_eq(round_constant, local.round_constant[i]);
        //     }
        // }
    }

    fn constrain_memory<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressInnerCols<AB::Var>,
    ) {
        // let clk_cycle_reads = AB::Expr::from_canonical_u32(64);
        // let clk_cycle_per_word = 4;
        // for i in 0..P2_WIDTH {
        //     builder.constraint_memory_access(
        //         local.segment,
        //         local.clk + AB::F::from_canonical_usize(i * clk_cycle_per_word),
        //         local.mem_addr[i],
        //         &local.mem_reads[i],
        //         local.is_real,
        //     );
        //     builder.constraint_memory_access(
        //         local.segment,
        //         local.clk
        //             + clk_cycle_reads.clone()
        //             + AB::F::from_canonical_usize(i * clk_cycle_per_word),
        //         local.mem_addr[i],
        //         &local.mem_writes[i],
        //         local.is_real,
        //     );
        // }
    }

    fn constraint_external_ops<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressInnerCols<AB::Var>,
    ) {
        // // Convert each Word into one field element. MemoryRead returns an array of Words, but we
        // // need to perform operations within the field.
        // let input_state = local.mem_reads.map(|read| {
        //     let mut acc: AB::Expr = AB::F::zero().into();
        //     for i in 0..WORD_SIZE {
        //         let shift: AB::Expr = AB::F::from_canonical_usize(1 << (8 * i)).into();
        //         acc += read.access.value[i].into() * shift;
        //     }
        //     acc
        // });

        // builder.assert_bool(local.is_real);

        // AddRcOperation::<AB::F>::eval(
        //     builder,
        //     input_state,
        //     local.is_round_n,
        //     local.round_constant,
        //     local.add_rc,
        //     local.is_real,
        // );

        // SBoxOperation::<AB::F>::eval(builder, local.add_rc.result, local.sbox, local.is_real);

        // ExternalLinearPermuteOperation::<AB::F>::eval(
        //     builder,
        //     local.sbox.acc.map(|x| *x.last().unwrap()),
        //     local.external_linear_permute,
        //     local.is_real,
        // );
    }
}
