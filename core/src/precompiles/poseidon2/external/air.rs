use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field};

use super::add_rc::AddRcOperation;
use super::columns::{
    Poseidon2ExternalCols, NUM_POSEIDON2_EXTERNAL_COLS, P2_EXTERNAL_ROUND_COUNT, P2_ROUND_CONSTANTS,
};
use super::external_linear_permute::ExternalLinearPermuteOperation;
use super::sbox::SBoxOperation;
use super::Poseidon2External1Chip;
use crate::air::{CurtaAirBuilder, WORD_SIZE};

use core::borrow::Borrow;
use p3_matrix::MatrixRowSlices;

impl<F, const N: usize, FIELD: Field> BaseAir<F> for Poseidon2External1Chip<FIELD, N> {
    fn width(&self) -> usize {
        NUM_POSEIDON2_EXTERNAL_COLS
    }
}

impl<AB, const WIDTH: usize, FIELD: Field> Air<AB> for Poseidon2External1Chip<FIELD, WIDTH>
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Poseidon2ExternalCols<AB::Var> = main.row_slice(0).borrow();
        let next: &Poseidon2ExternalCols<AB::Var> = main.row_slice(1).borrow();

        self.constrain_control_flow_flags(builder, local, next);

        self.constrain_memory(builder, local);

        self.constraint_external_ops(builder, local);
    }
}

impl<F: Field, const WIDTH: usize> Poseidon2External1Chip<F, WIDTH> {
    fn constrain_control_flow_flags<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2ExternalCols<AB::Var>,
        next: &Poseidon2ExternalCols<AB::Var>,
    ) {
        // If this is the i-th round, then the next row should be the (i+1)-th round.
        for i in 0..P2_EXTERNAL_ROUND_COUNT {
            builder
                .when_transition()
                .when(next.is_real)
                .assert_eq(local.is_round_n[i], next.is_round_n[i + 1]);
            builder.assert_bool(local.is_round_n[i]);
        }

        // Exactly one of the is_round_n flags is set.
        {
            let sum_is_round_n = {
                let mut acc: AB::Expr = AB::F::zero().into();
                for i in 0..P2_EXTERNAL_ROUND_COUNT {
                    acc += local.is_round_n[i].into();
                }
                acc
            };

            builder
                .when(local.is_real)
                .assert_eq(sum_is_round_n, AB::F::from_canonical_usize(1));
        }

        // Calculate the current round number.
        {
            let round = {
                let mut acc: AB::Expr = AB::F::zero().into();

                for i in 0..P2_EXTERNAL_ROUND_COUNT {
                    acc += local.is_round_n[i] * AB::F::from_canonical_usize(i);
                }
                acc
            };
            builder.assert_eq(round, local.round_number);
        }

        // Calculate the round constants for this round.
        {
            for i in 0..WIDTH {
                let round_constant = {
                    let mut acc: AB::Expr = AB::F::zero().into();

                    for j in 0..P2_EXTERNAL_ROUND_COUNT {
                        acc += local.is_round_n[j].into()
                            * AB::F::from_canonical_u32(P2_ROUND_CONSTANTS[j][i]);
                    }
                    acc
                };
                builder.assert_eq(round_constant, local.round_constant[i]);
            }
        }
    }

    fn constrain_memory<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2ExternalCols<AB::Var>,
    ) {
        let clk_cycle_reads = AB::Expr::from_canonical_u32(64);
        let clk_cycle_per_word = 4;
        for i in 0..WIDTH {
            builder.constraint_memory_access(
                local.segment,
                local.clk + AB::F::from_canonical_usize(i * clk_cycle_per_word),
                local.mem_addr[i],
                &local.mem_reads[i],
                local.is_real,
            );
            builder.constraint_memory_access(
                local.segment,
                local.clk
                    + clk_cycle_reads.clone()
                    + AB::F::from_canonical_usize(i * clk_cycle_per_word),
                local.mem_addr[i],
                &local.mem_writes[i],
                local.is_real,
            );
        }
    }

    fn constraint_external_ops<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2ExternalCols<AB::Var>,
    ) {
        // Convert each Word into one field element. MemoryRead returns an array of Words, but we
        // need to perform operations within the field.
        let input_state = local.mem_reads.map(|read| {
            let mut acc: AB::Expr = AB::F::zero().into();
            for i in 0..WORD_SIZE {
                let shift: AB::Expr = AB::F::from_canonical_usize(1 << (8 * i)).into();
                acc += read.access.value[i].into() * shift;
            }
            acc
        });

        builder.assert_bool(local.is_real);

        AddRcOperation::<AB::F>::eval(
            builder,
            input_state,
            local.is_round_n,
            local.round_constant,
            local.add_rc,
            local.is_real,
        );

        SBoxOperation::<AB::F>::eval(builder, local.add_rc.result, local.sbox, local.is_real);

        ExternalLinearPermuteOperation::<AB::F>::eval(
            builder,
            local.sbox.acc.map(|x| *x.last().unwrap()),
            local.external_linear_permute,
            local.is_real,
        );
    }
}
