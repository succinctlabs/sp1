mod outer;
mod stark;

use sp1_recursion_compiler::ir::{Builder, Config, Ext, Felt};

pub use outer::*;
pub use stark::*;

use crate::CircuitConfig;

pub trait WitnessWriter<C: CircuitConfig>: Sized {
    fn write_bit(&mut self, bit: C::Bit);

    fn write_felt(&mut self, felt: Felt<C::F>);

    fn write_ext(&mut self, ext: Ext<C::F, C::EF>);
}

/// TODO change the name. For now, the name is unique to prevent confusion.
pub trait Witnessable<C: Config> {
    type WitnessVariable;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable;

    fn write(&self) -> Vec<WitnessBlock<C>>;
}
