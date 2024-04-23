use p3_air::AirBuilderWithPublicValues;
use sp1_core::air::{BaseAirBuilder, ExtensionAirBuilder, MemoryAirBuilder, ProgramAirBuilder};

use crate::air::Block;

pub trait BlockAirBuilder: BaseAirBuilder {
    fn assert_is_field<I: Into<Self::Expr> + Clone>(&mut self, block: &Block<I>) {
        self.assert_zero(block.0[1].clone());
        self.assert_zero(block.0[2].clone());
        self.assert_zero(block.0[3].clone());
    }
}

pub trait SP1RecursionAirBuilder:
    BaseAirBuilder
    + MemoryAirBuilder
    + ProgramAirBuilder
    + ExtensionAirBuilder
    + BlockAirBuilder
    + AirBuilderWithPublicValues
{
}

impl<AB: BaseAirBuilder> BlockAirBuilder for AB {}
impl<AB: BaseAirBuilder + AirBuilderWithPublicValues> SP1RecursionAirBuilder for AB {}
