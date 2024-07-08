use p3_field::AbstractField;

use crate::builder::SP1RecursionAirBuilder;
use crate::poseidon2_wide::columns::permutation::Permutation;
use crate::poseidon2_wide::{
    columns::preprocessed::Poseidon2MemoryPreprocessedCols, Poseidon2WideChip, WIDTH,
};

impl<const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    /// Eval the memory related columns. This should get refactored: the memory preprocessed columns
    /// should not have val as a field.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn eval_mem<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local_permutation: impl Permutation<AB::Var>,
        local_memory_preprocessed: &Poseidon2MemoryPreprocessedCols<AB::Var>,
    ) {
        for i in 0..WIDTH {
            builder.send_single(
                local_memory_preprocessed.memory_prepr[i].addr,
                local_permutation.state()[i],
                local_memory_preprocessed.memory_prepr[i].write_mult,
            );

            builder.receive_single(
                local_memory_preprocessed.memory_prepr[i].addr,
                local_permutation.state()[i],
                local_memory_preprocessed.memory_prepr[i].read_mult,
            );
        }
    }
}
