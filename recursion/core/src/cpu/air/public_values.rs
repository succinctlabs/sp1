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
    /// This method will verify the committed public value.
    pub fn eval_commit<AB>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        commit_digest: [AB::Expr; DIGEST_SIZE],
    ) where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        let public_values_cols = local.opcode_specific.public_values();
        let is_commit_instruction = self.is_commit_instruction::<AB>(local);

        // Verify all elements in the index bitmap are bools.
        let mut bitmap_sum = AB::Expr::zero();
        for bit in public_values_cols.idx_bitmap.iter() {
            builder
                .when(is_commit_instruction.clone())
                .assert_bool(*bit);
            bitmap_sum += (*bit).into();
        }
        // When the instruction is COMMIT there should be exactly one set bit.
        builder
            .when(is_commit_instruction.clone())
            .assert_one(bitmap_sum.clone());

        // Verify that idx passed in the b operand corresponds to the set bit in index bitmap.
        for (i, bit) in public_values_cols.idx_bitmap.iter().enumerate() {
            builder
                .when(*bit * is_commit_instruction.clone())
                .assert_block_eq(
                    *local.b.prev_value(),
                    AB::Expr::from_canonical_u32(i as u32).into(),
                );
        }

        // Calculated the expected public value.
        let expected_pv_digest_element =
            builder.index_array(&commit_digest, &public_values_cols.idx_bitmap);

        // Get the committed public value in the program from operand a.
        let digest_element = local.a.prev_value();

        // Verify the public value element.
        builder
            .when(is_commit_instruction.clone())
            .assert_block_eq(expected_pv_digest_element.into(), *digest_element);
    }
}
