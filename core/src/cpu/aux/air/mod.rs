mod auipc;
mod branch;
mod ecall;
mod jump;
mod memory;

use std::borrow::Borrow;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;

use crate::{
    air::{PublicValues, Word, SP1_PROOF_NUM_PV_ELTS},
    cpu::CpuAuxChip,
    stark::SP1AirBuilder,
};

use super::columns::{CpuAuxCols, NUM_CPU_AUX_COLS};

impl<AB> Air<AB> for CpuAuxChip
where
    AB: SP1AirBuilder + AirBuilderWithPublicValues,
    AB::Var: Sized,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &CpuAuxCols<AB::Var> = (*local).borrow();
        let public_values_slice: [AB::Expr; SP1_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| builder.public_values()[i].into());
        let public_values: &PublicValues<Word<AB::Expr>, AB::Expr> =
            public_values_slice.as_slice().borrow();

        // Receive the instruction from the main cpu chip.
        builder.receive_instruction(
            local.clk,
            local.shard,
            local.channel,
            local.pc,
            local.next_pc,
            local.selectors,
            local.op_a_prev_val,
            local.op_a_val,
            local.op_b_val,
            local.op_c_val,
            local.op_a_0,
            local.is_halt,
            local.is_real,
        );

        // Memory instructions.
        let is_memory_instruction = local.selectors.is_memory_instruction::<AB>();
        self.eval_memory_address_and_access::<AB>(builder, local, is_memory_instruction.clone());
        self.eval_memory_load::<AB>(builder, local);
        self.eval_memory_store::<AB>(builder, local);

        let is_branch_instruction = local.selectors.is_branch_instruction::<AB>();

        // Branch instructions.
        self.eval_branch_ops::<AB>(builder, is_branch_instruction.clone(), local);

        // Jump instructions.
        self.eval_jump_ops::<AB>(builder, local);

        // AUIPC instruction.
        self.eval_auipc(builder, local);

        // ECALL instruction.
        self.eval_ecall(builder, local);

        // COMMIT/COMMIT_DEFERRED_PROOFS ecall instruction.
        self.eval_commit(
            builder,
            local,
            public_values.committed_value_digest.clone(),
            public_values.deferred_proofs_digest.clone(),
        );

        // HALT instruction.
        self.eval_halt(builder, local, public_values);

        // Verify local.next_pc value for sequential instructions.  Note that local.next_pc has
        // already been verified for non sequential in their respective eval functions (e.g. eval_branch_ops,
        // eval_jump_ops, and eval_halt).
        let is_halt = self.is_halt_syscall::<AB>(builder, local);
        builder.assert_eq(is_halt, local.is_halt);
        let is_sequence_instr = AB::Expr::one()
            - (is_branch_instruction
                + local.selectors.is_jal
                + local.selectors.is_jalr
                + local.is_halt);
        builder
            .when(local.is_real)
            .when(is_sequence_instr)
            .assert_eq(local.pc + AB::Expr::from_canonical_u8(4), local.next_pc);
    }
}

impl<F> BaseAir<F> for CpuAuxChip {
    fn width(&self) -> usize {
        NUM_CPU_AUX_COLS
    }
}
