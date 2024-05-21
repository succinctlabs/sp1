use p3_field::{AbstractField, Field};

use crate::{
    air::SP1RecursionAirBuilder,
    cpu::{CpuChip, CpuCols},
    memory::MemoryCols,
    runtime::STACK_SIZE,
};

impl<F: Field> CpuChip<F> {
    /// Eval the ALU instructions.
    pub fn eval_heap_ptr<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        let heap_columns = local.opcode_specific.heap_increment();

        builder.eval_range_check_28bits(
            local.a.value()[0] - AB::Expr::from_canonical_usize(STACK_SIZE + 4),
            heap_columns.diff_16bit_limb,
            heap_columns.diff_12bit_limb,
            local.selectors.is_heap_increment,
        );
    }
}
