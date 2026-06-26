mod memory;
mod operation;
mod program;
mod witness;
mod witness_record;
mod word;

pub use memory::*;
pub use operation::*;
pub use program::*;
pub use witness::*;
pub use witness_record::*;
pub use word::*;

use sp1_hypercube::air::{BaseAirBuilder, SP1AirBuilder};

use crate::{
    memory::MemoryAccessColsU8,
    operations::{U16toU8OperationSafe, U16toU8OperationSafeInput},
};

/// A trait which contains methods related to memory interactions in an AIR.
pub trait SP1CoreAirBuilder:
    SP1AirBuilder + WordAirBuilder + MemoryAirBuilder + ProgramAirBuilder + SP1CoreOperationBuilder
{
    fn generate_limbs(
        &mut self,
        memory_access_cols: &[MemoryAccessColsU8<Self::Var>],
        is_real: Self::Expr,
    ) -> Vec<Self::Expr> {
        let u16_to_u8_input = |access: &MemoryAccessColsU8<Self::Var>| {
            U16toU8OperationSafeInput::new(
                access.memory_access.prev_value.0.map(|x| x.into()),
                access.prev_value_u8,
                is_real.clone(),
            )
        };
        // Convert the u16 limbs to u8 limbs using the safe API with range checks.
        let limbs = memory_access_cols
            .iter()
            .flat_map(|access| {
                let input = u16_to_u8_input(access);
                U16toU8OperationSafe::eval(self, input)
            })
            .collect::<Vec<_>>();
        limbs
    }
}

impl<AB: BaseAirBuilder> MemoryAirBuilder for AB {}
impl<AB: BaseAirBuilder> ProgramAirBuilder for AB {}
impl<AB: BaseAirBuilder> WordAirBuilder for AB {}
impl<AB: BaseAirBuilder + SP1CoreOperationBuilder> SP1CoreAirBuilder for AB {}
