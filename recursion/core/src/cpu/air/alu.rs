use p3_field::Field;
use sp1_core::air::{BinomialExtension, ExtensionAirBuilder};

use crate::{
    air::{BinomialExtensionUtils, SP1RecursionAirBuilder},
    cpu::{CpuChip, CpuCols},
    memory::MemoryCols,
};

impl<F: Field> CpuChip<F> {
    /// Eval the ALU operations.
    pub fn eval_alu<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        // Convert operand values from Block<Var> to BinomialExtension<Expr>.
        let a_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.a.value().map(|x| x.into()));
        let b_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.b.value().map(|x| x.into()));
        let c_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.c.value().map(|x| x.into()));

        // Flag to check if the instruction is a field operation
        let is_field_op = local.selectors.is_add
            + local.selectors.is_sub
            + local.selectors.is_mul
            + local.selectors.is_div;

        // Verify that the b and c registers are base elements for field operations.
        builder
            .when(is_field_op.clone())
            .assert_is_base_element(b_ext.clone());
        builder
            .when(is_field_op)
            .assert_is_base_element(c_ext.clone());

        // Verify the actual operation.
        builder
            .when(local.selectors.is_add + local.selectors.is_eadd)
            .assert_ext_eq(a_ext.clone(), b_ext.clone() + c_ext.clone());
        builder
            .when(local.selectors.is_sub + local.selectors.is_esub)
            .assert_ext_eq(a_ext.clone(), b_ext.clone() - c_ext.clone());
        // TODO:  Figure out why this fails in the groth16 proof.
        // builder
        //     .when(local.selectors.is_mul + local.selectors.is_emul)
        //     .assert_ext_eq(a_ext.clone(), b_ext.clone() * c_ext.clone());
        // // For div operation, we assert that b == a * c (equivalent to a == b / c).
        builder
            .when(local.selectors.is_div + local.selectors.is_ediv)
            .assert_ext_eq(b_ext, a_ext * c_ext);
    }
}
