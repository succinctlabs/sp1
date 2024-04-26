use p3_field::Field;
use sp1_core::runtime::MemoryAccessPosition;

use crate::{
    air::SP1RecursionAirBuilder,
    cpu::{CpuChip, CpuCols},
    memory::MemoryCols,
};

impl<F: Field> CpuChip<F> {
    // Eval the MEMORY instructions.
    pub fn eval_memory<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        // Constraint all the memory access.

        // Evaluate the memory column.
        let load_memory = local.selectors.is_load + local.selectors.is_store;
        let index = local.c.value()[0];
        let ptr = local.b.value()[0];
        let _memory_addr = ptr + index * local.instruction.size_imm + local.instruction.offset_imm;
        // TODO: comment this back in to constraint the memory_addr column.
        // When load_memory is true, then we check that the local.memory_addr column equals the computed
        // memory_addr column from the other columns. Otherwise it is 0.
        // builder.assert_eq(memory_addr * load_memory.clone(), local.memory_addr);

        let memory_cols = local.opcode_specific.memory();

        builder.recursion_eval_memory_access(
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            memory_cols.memory_addr,
            &memory_cols.memory,
            load_memory,
        );

        // Constraints on the memory column depending on load or store.
        // We read from memory when it is a load.
        // builder
        //     .when(local.selectors.is_load)
        //     .assert_block_eq(local.memory.prev_value, *local.memory.value());
        // // When there is a store, we ensure that we are writing the value of the a operand to the memory.
        // builder
        //     .when(local.selectors.is_store)
        //     .assert_block_eq(local.a.value, local.memory.value);
    }
}
