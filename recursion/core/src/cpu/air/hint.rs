use p3_field::Field;
use sp1_core::air::ExtensionAirBuilder;

use crate::{
    air::{BinomialExtensionUtils, SP1RecursionAirBuilder},
    cpu::{CpuChip, CpuCols},
    memory::MemoryCols,
};

impl<F: Field> CpuChip<F> {
    /// Eval the ALU instructions.
    pub fn eval_hint_ext2felt<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        builder.when(local.selectors.is_ext_to_felt).assert_ext_eq(
            BinomialExtensionUtils::from_block(local.a.value().map(|x| x.into())),
            BinomialExtensionUtils::from_block(local.b.value().map(|x| x.into())),
        );
    }
}
