use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};

use crate::{
    air::{BlockBuilder, SP1RecursionAirBuilder},
    cpu::{CpuChip, CpuCols},
    memory::MemoryCols,
    runtime::DIGEST_SIZE,
};

impl<F: Field> CpuChip<F> {
    /// Eval the COMMIT instructions.
    ///
    /// This method will verify the fp column values and add to the `next_pc` expression.
    pub fn eval_public_values<AB>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        commit_digest: [AB::Expr; DIGEST_SIZE],
    ) where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        let public_values_cols = local.opcode_specific.public_values();
        let is_commit_instruction = self.is_commit_instruction::<AB>(local);

        // Verify the index bitmap.
        let mut bitmap_sum = AB::Expr::zero();
        // They should all be bools.
        for bit in public_values_cols.idx_bitmap.iter() {
            builder
                .when(is_commit_instruction.clone())
                .assert_bool(*bit);
            bitmap_sum += (*bit).into();
        }
        // When the instruction is COMMIT there should be one set bit.
        builder
            .when(is_commit_instruction.clone())
            .assert_one(bitmap_sum.clone());

        // Verify that word_idx corresponds to the set bit in index bitmap.
        for (i, bit) in public_values_cols.idx_bitmap.iter().enumerate() {
            builder
                .when(*bit * is_commit_instruction.clone())
                .assert_block_eq(
                    *local.b.prev_value(),
                    AB::Expr::from_canonical_u32(i as u32).into(),
                );
        }

        let expected_pv_digest_element =
            builder.index_array(&commit_digest, &public_values_cols.idx_bitmap);

        let digest_element = local.a.prev_value();

        // Verify the public_values_digest_word.
        builder
            .when(is_commit_instruction.clone())
            .assert_block_eq(expected_pv_digest_element.into(), *digest_element);
    }
}
