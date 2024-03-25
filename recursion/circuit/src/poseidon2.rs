use sp1_recursion_compiler::ir::{Builder, Config, Felt};
use sp1_recursion_core::runtime::POSEIDON2_WIDTH;

pub trait Poseidon2CircuitBuilder<C: Config> {
    fn p2_permute_mut(&mut self, state: &mut [Felt<C::F>; POSEIDON2_WIDTH]);
}

impl<C: Config> Poseidon2CircuitBuilder<C> for Builder<C> {
    fn p2_permute_mut(&mut self, state: &mut [Felt<<C as Config>::F>; POSEIDON2_WIDTH]) {
        todo!()
    }
}
