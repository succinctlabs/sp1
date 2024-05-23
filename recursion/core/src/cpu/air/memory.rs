use p3_air::AirBuilder;
use p3_field::Field;
use sp1_core::runtime::MemoryAccessPosition;

use crate::{
    air::{BlockBuilder, SP1RecursionAirBuilder},
    cpu::{CpuChip, CpuCols},
    memory::MemoryCols,
};

impl<F: Field, const L: usize> CpuChip<F, L> {
    // Eval the MEMORY instructions.
    pub fn eval_memory<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        let is_memory_instr = self.is_memory_instruction::<AB>(local);
        let index = local.c.value()[0];
        let ptr = local.b.value()[0];
        let memory_addr = ptr + index * local.instruction.size_imm + local.instruction.offset_imm;

        let memory_cols = local.opcode_specific.memory();

        // Check that the memory_cols.memory_addr column equals the computed memory_addr.
        builder
            .when(is_memory_instr.clone())
            .assert_eq(memory_addr, memory_cols.memory_addr);

        builder.recursion_eval_memory_access(
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            memory_cols.memory_addr,
            &memory_cols.memory,
            is_memory_instr,
        );

        // Constraints on the memory column depending on load or store.
        // We read from memory when it is a load.
        builder.when(local.selectors.is_load).assert_block_eq(
            *memory_cols.memory.prev_value(),
            *memory_cols.memory.value(),
        );
        // When there is a store, we ensure that we are writing the value of the a operand to the memory.
        builder
            .when(local.selectors.is_store)
            .assert_block_eq(*local.a.value(), *memory_cols.memory.value());
    }
}
