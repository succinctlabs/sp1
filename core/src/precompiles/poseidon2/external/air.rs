use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;

use super::add_rc::AddRcOperation;
use super::columns::{
    Poseidon2ExternalCols, NUM_POSEIDON2_EXTERNAL_COLS, POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS,
};
use super::Poseidon2ExternalChip;
use crate::air::CurtaAirBuilder;

use core::borrow::Borrow;
use p3_matrix::MatrixRowSlices;

impl<F, const N: usize> BaseAir<F> for Poseidon2ExternalChip<N> {
    fn width(&self) -> usize {
        NUM_POSEIDON2_EXTERNAL_COLS
    }
}

impl<AB, const NUM_WORDS_STATE: usize> Air<AB> for Poseidon2ExternalChip<NUM_WORDS_STATE>
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

        // self.constrain_finalize_ops(builder, local);
    }
}

impl<const NUM_WORDS_STATE: usize> Poseidon2ExternalChip<NUM_WORDS_STATE> {
    fn constrain_control_flow_flags<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2ExternalCols<AB::Var>,
        next: &Poseidon2ExternalCols<AB::Var>,
    ) {
        // If this is the i-th round, then the next row should be the (i+1)-th round.
        for i in 0..POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS {
            builder.when_transition().when(next.0.is_real).assert_eq(
                local.0.is_round_n[i],
                next.0.is_round_n[(i + 1) % POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS],
            );
            builder.assert_bool(local.0.is_round_n[i]);
        }

        // Calculate the current round number.
        {
            let round = {
                let mut acc: AB::Expr = AB::F::zero().into();

                for i in 0..POSEIDON2_DEFAULT_FIRST_EXTERNAL_ROUNDS {
                    acc += local.0.is_round_n[i] * AB::F::from_canonical_usize(i);
                }
                acc
            };
            builder.assert_eq(round, local.0.round_number);
        }

        // Calculate the round constants for this round.
    }

    fn constrain_memory<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2ExternalCols<AB::Var>,
    ) {
        for round in 0..NUM_WORDS_STATE {
            builder.constraint_memory_access(
                local.0.segment,
                local.0.mem_read_clk[round],
                local.0.mem_addr[round],
                &local.0.mem_reads[round],
                local.0.is_external,
            );
            builder.constraint_memory_access(
                local.0.segment,
                local.0.mem_write_clk[round],
                local.0.mem_addr[round],
                &local.0.mem_writes[round],
                local.0.is_external,
            );
        }
    }

    fn constraint_external_ops<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2ExternalCols<AB::Var>,
    ) {
        let input_state = local.0.mem_reads.map(|read| read.access.value);
        AddRcOperation::<AB::F>::eval(
            builder,
            input_state,
            local.0.is_round_n,
            local.0.round_constant,
            local.0.add_rc,
            local.0.is_external,
        );
    }

    fn _constrain_finalize_ops<AB: CurtaAirBuilder>(
        &self,
        _builder: &mut AB,
        _local: &Poseidon2ExternalCols<AB::Var>,
    ) {
        // TODO: Do I need this? What do we use this for in SHA?
    }
}
