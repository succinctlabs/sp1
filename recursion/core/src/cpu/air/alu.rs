use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};
use sp1_core::air::{BinomialExtension, ExtensionAirBuilder};

use crate::{
    air::{BinomialExtensionUtils, SP1RecursionAirBuilder},
    cpu::{CpuChip, CpuCols},
    memory::MemoryCols,
};

impl<F: Field, const L: usize> CpuChip<F, L> {
    /// Eval the ALU instructions.
    ///
    /// # Warning
    /// The division constraints allow a = 0/0 for any a.
    pub fn eval_alu<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        let one = AB::Expr::one();
        let is_alu_instruction = self.is_alu_instruction::<AB>(local);

        // Convert operand values from Block<Var> to BinomialExtension<Expr>.
        let a_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.a.value().map(|x| x.into()));
        let b_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.b.value().map(|x| x.into()));
        let c_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.c.value().map(|x| x.into()));

        // Verify that the b and c registers are base elements for field operations.
        builder
            .when(is_alu_instruction.clone())
            .when(one.clone() - local.selectors.is_ext)
            .assert_is_base_element(b_ext.clone());
        builder
            .when(is_alu_instruction)
            .when(one - local.selectors.is_ext)
            .assert_is_base_element(c_ext.clone());

        // Verify the actual operation.
        builder
            .when(local.selectors.is_add)
            .assert_ext_eq(a_ext.clone(), b_ext.clone() + c_ext.clone());
        builder
            .when(local.selectors.is_sub)
            .assert_ext_eq(a_ext.clone(), b_ext.clone() - c_ext.clone());
        builder
            .when(local.selectors.is_mul)
            .assert_ext_eq(a_ext.clone(), b_ext.clone() * c_ext.clone());
        // For div operation, we assert that b == a * c (equivalent to a == b / c).
        builder
            .when(local.selectors.is_div)
            .assert_ext_eq(b_ext, a_ext * c_ext);
    }
}
