use p3_air::{Air, BaseAir};

use super::columns::{
    Poseidon2ExternalCols, NUM_POSEIDON2_EXTERNAL_COLS, POSEIDON2_DEFAULT_EXTERNAL_ROUNDS,
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

impl<AB, const N: usize> Air<AB> for Poseidon2ExternalChip<N>
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Poseidon2ExternalCols<AB::Var> = main.row_slice(0).borrow();
        let _next: &Poseidon2ExternalCols<AB::Var> = main.row_slice(1).borrow();

        // self.constrain_control_flow_flags(builder, local, next);

        self.constrain_memory(builder, local);

        // self.constrain_compression_ops(builder, local);

        // self.constrain_finalize_ops(builder, local);
    }
}

impl<const NUM_WORDS_STATE: usize> Poseidon2ExternalChip<NUM_WORDS_STATE> {
    fn _constrain_control_flow_flags<AB: CurtaAirBuilder>(
        &self,
        _builder: &mut AB,
        _local: &Poseidon2ExternalCols<AB::Var>,
        _next: &Poseidon2ExternalCols<AB::Var>,
    ) {
    }

    fn constrain_memory<AB: CurtaAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2ExternalCols<AB::Var>,
    ) {
        for round in 0..NUM_WORDS_STATE {
            builder.constraint_memory_access(
                local.0.segment,
                local.0.clk,
                local.0.mem_addr[round],
                &local.0.mem[round],
                local.0.is_external,
            );
        }
    }

    fn _constrain_compression_ops<AB: CurtaAirBuilder>(
        &self,
        _builder: &mut AB,
        _local: &Poseidon2ExternalCols<AB::Var>,
    ) {
    }

    fn _constrain_finalize_ops<AB: CurtaAirBuilder>(
        &self,
        _builder: &mut AB,
        _local: &Poseidon2ExternalCols<AB::Var>,
    ) {
    }
}
