use p3_air::AirBuilder;
use p3_field::AbstractField;

use crate::{
    cpu::{aux::columns::CpuAuxCols, CpuAuxChip},
    operations::BabyBearWordRangeChecker,
    runtime::Opcode,
    stark::SP1AirBuilder,
};

impl CpuAuxChip {
    /// Constraints related to the AUIPC opcode.
    pub(crate) fn eval_auipc<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuAuxCols<AB::Var>,
    ) {
        // Get the auipc specific columns.
        let auipc_columns = local.opcode_specific_columns.auipc();

        // Verify that the word form of local.pc is correct.
        builder
            .when(local.selectors.is_auipc)
            .assert_eq(auipc_columns.pc.reduce::<AB>(), local.pc);

        // Range check the pc.
        BabyBearWordRangeChecker::<AB::F>::range_check(
            builder,
            auipc_columns.pc,
            auipc_columns.pc_range_checker,
            local.selectors.is_auipc.into(),
        );

        // Verify that op_a == pc + op_b.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.op_a_val,
            auipc_columns.pc,
            local.op_b_val,
            local.shard,
            local.channel,
            auipc_columns.auipc_nonce,
            local.selectors.is_auipc,
        );
    }
}
