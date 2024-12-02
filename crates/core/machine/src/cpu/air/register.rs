use p3_field::AbstractField;
use sp1_stark::air::SP1AirBuilder;

use crate::{
    air::{MemoryAirBuilder, WordAirBuilder},
    cpu::{columns::CpuCols, CpuChip},
    memory::MemoryCols,
};
use sp1_core_executor::events::MemoryAccessPosition;

impl CpuChip {
    /// Computes whether the opcode is a branch instruction.
    pub(crate) fn eval_registers<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        clk: AB::Expr,
    ) {
        // Load immediates into b and c, if the immediate flags are on.
        builder
            .when(local.instruction.imm_b)
            .assert_word_eq(local.op_b_val(), local.instruction.op_b);
        builder
            .when(local.instruction.imm_c)
            .assert_word_eq(local.op_c_val(), local.instruction.op_c);

        // If they are not immediates, read `b` and `c` from memory.
        builder.eval_memory_access(
            local.shard,
            clk.clone() + AB::F::from_canonical_u32(MemoryAccessPosition::B as u32),
            local.instruction.op_b[0],
            &local.op_b_access,
            AB::Expr::one() - local.instruction.imm_b,
        );

        builder.eval_memory_access(
            local.shard,
            clk.clone() + AB::F::from_canonical_u32(MemoryAccessPosition::C as u32),
            local.instruction.op_c[0],
            &local.op_c_access,
            AB::Expr::one() - local.instruction.imm_c,
        );

        // If we are writing to register 0, then the new value should be zero.
        builder.when(local.instruction.op_a_0).assert_word_zero(*local.op_a_access.value());

        // Write the `a` or the result to the first register described in the instruction unless
        // we are performing a branch or a store.  Note that for syscall instructions, we will eval
        // the memory access for op_a in the syscall instructions chip.  The reason we do that is
        // to eval syscall instructions, op_a prev value is needed.  That value is not needed for all
        // other instructions' eval, and it will be wasteful to put that column in all other instruction
        // chips.
        builder.eval_memory_access(
            local.shard,
            clk + AB::F::from_canonical_u32(MemoryAccessPosition::A as u32),
            local.instruction.op_a,
            &local.op_a_access,
            AB::Expr::one() - local.is_syscall,
        );

        // Always range check the word value in `op_a`, as JUMP instructions may witness
        // an invalid word and write it to memory.
        builder.slice_range_check_u8(&local.op_a_access.access.value.0, local.is_real);

        // If we are performing a branch or a store, then the value of `a` is the previous value.
        builder
            .when(local.op_a_immutable)
            .assert_word_eq(local.op_a_val(), local.op_a_access.prev_value);
    }
}
