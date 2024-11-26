use p3_air::AirBuilder;
use p3_field::AbstractField;
use sp1_stark::{
    air::{BaseAirBuilder, SP1AirBuilder},
    Word,
};

use crate::{
    air::WordAirBuilder,
    cpu::{
        columns::{CpuCols, OpcodeSelectorCols},
        CpuChip,
    },
    operations::BabyBearWordRangeChecker,
};

use sp1_core_executor::{Opcode, DEFAULT_PC_INC, UNUSED_PC};

impl CpuChip {
    /// Computes whether the opcode is a branch instruction.
    pub(crate) fn is_branch_instruction<AB: SP1AirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_beq
            + opcode_selectors.is_bne
            + opcode_selectors.is_blt
            + opcode_selectors.is_bge
            + opcode_selectors.is_bltu
            + opcode_selectors.is_bgeu
    }
}
