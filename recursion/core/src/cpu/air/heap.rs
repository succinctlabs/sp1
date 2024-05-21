use p3_field::{AbstractField, Field};

use crate::{
    air::SP1RecursionAirBuilder,
    cpu::{CpuChip, CpuCols},
    memory::MemoryCols,
    runtime::STACK_SIZE,
};

impl<F: Field> CpuChip<F> {
    /// Eval the heap ptr.
    ///
    /// This function will ensure that the heap size never goes above 2^28.
    pub fn eval_heap_ptr<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        let heap_columns = local.opcode_specific.heap_increment();

        let heap_size = local.a.value()[0] - AB::Expr::from_canonical_usize(STACK_SIZE + 4);

        builder.eval_range_check_28bits(
            heap_size,
            heap_columns.diff_16bit_limb,
            heap_columns.diff_12bit_limb,
            local.selectors.is_heap_expand,
        );
    }
}
