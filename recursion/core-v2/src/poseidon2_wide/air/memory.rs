use p3_field::AbstractField;

use crate::builder::SP1RecursionAirBuilder;
use crate::poseidon2_wide::columns::memory::MemoryPreprocessed;
use crate::poseidon2_wide::{columns::memory::Memory, Poseidon2WideChip, WIDTH};
use crate::AddressValue;

impl<const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    /// Eval the memory related columns.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn eval_mem<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local_memory: &Memory<AB::Var>,
        local_memory_preprocessed: &MemoryPreprocessed<AB::Var>,
        local_output_mult: [AB::Expr; 16],
    ) {
        for i in 0..WIDTH {
            builder.receive_single(
                AddressValue::new(
                    local_memory_preprocessed.input_addr[i],
                    local_memory.input[i],
                ),
                AB::Expr::one(),
            );
            builder.send_single(
                AddressValue::new(
                    local_memory_preprocessed.input_addr[i],
                    local_memory.output[i],
                ),
                local_output_mult[i].clone(),
            );
        }
    }
}
