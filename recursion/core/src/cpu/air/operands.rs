use p3_field::{AbstractField, Field};
use sp1_core::runtime::MemoryAccessPosition;

use crate::{
    air::{BlockBuilder, SP1RecursionAirBuilder},
    cpu::{CpuChip, CpuCols},
    memory::MemoryCols,
};

impl<F: Field> CpuChip<F> {
    /// Eval the operands.
    pub fn eval_operands<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        // Constraint the case of immediates for the b and c operands.
        builder
            .when(local.instruction.imm_b)
            .assert_block_eq::<AB::Var, AB::Var>(*local.b.value(), local.instruction.op_b);
        builder
            .when(local.instruction.imm_c)
            .assert_block_eq::<AB::Var, AB::Var>(*local.c.value(), local.instruction.op_c);

        // Constraint the operand accesses.
        let a_addr = local.fp.into() + local.instruction.op_a.into();
        builder.recursion_eval_memory_access(
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::A as u32),
            a_addr,
            &local.a,
            local.is_real.into(),
        );
        // If the instruction only reads from operand A, then verify that previous and current values are equal.
        let is_op_a_read_only = self.is_op_a_read_only_instruction::<AB>(local);
        builder
            .when(is_op_a_read_only)
            .assert_block_eq(*local.a.prev_value(), *local.a.value());

        builder.recursion_eval_memory_access(
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::B as u32),
            local.fp.into() + local.instruction.op_b[0].into(),
            &local.b,
            AB::Expr::one() - local.instruction.imm_b.into(),
        );

        builder.recursion_eval_memory_access(
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::C as u32),
            local.fp.into() + local.instruction.op_c[0].into(),
            &local.c,
            AB::Expr::one() - local.instruction.imm_c.into(),
        );
    }
}
