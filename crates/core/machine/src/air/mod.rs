mod memory;
mod program;
mod word;

pub use memory::*;
pub use program::*;
pub use word::*;

use sp1_stark::air::{BaseAirBuilder, SP1AirBuilder};

/// A trait which contains methods related to memory interactions in an AIR.
pub trait SP1CoreAirBuilder:
    SP1AirBuilder + WordAirBuilder + MemoryAirBuilder + ProgramAirBuilder
{
}

impl<AB: BaseAirBuilder> MemoryAirBuilder for AB {}
impl<AB: BaseAirBuilder> ProgramAirBuilder for AB {}
impl<AB: BaseAirBuilder> WordAirBuilder for AB {}
impl<AB: BaseAirBuilder + SP1AirBuilder> SP1CoreAirBuilder for AB {}
