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
    operations::BabyBearWordRangeChecker,
    runtime::Opcode,
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
        self.eval_halt(builder, local);

        // Eval the next_pc for sequence instructions.
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

impl CpuAuxChip {
    /// Constraints related to the AUIPC opcode.
    pub(crate) fn eval_auipc<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuAuxCols<AB::Var>,
    ) {
        // Get the auipc specific columns.
        let auipc_columns = local.opcode_specific_columns.auipc();

        // Verify that the word form of local.pc is correct.
        builder
            .when(local.selectors.is_auipc)
            .assert_eq(auipc_columns.pc.reduce::<AB>(), local.pc);

        // Range check the pc.
        BabyBearWordRangeChecker::<AB::F>::range_check(
            builder,
            auipc_columns.pc,
            auipc_columns.pc_range_checker,
            local.selectors.is_auipc.into(),
        );

        // Verify that op_a == pc + op_b.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.op_a_val,
            auipc_columns.pc,
            local.op_b_val,
            local.shard,
            local.channel,
            auipc_columns.auipc_nonce,
            local.selectors.is_auipc,
        );
    }
}

impl<F> BaseAir<F> for CpuAuxChip {
    fn width(&self) -> usize {
        NUM_CPU_AUX_COLS
    }
}
