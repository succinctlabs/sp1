//! An implementation of Poseidon2 over BN254.

use crate::prelude::*;
use sp1_recursion_core_v2::poseidon2_wide::WIDTH;

pub trait CircuitBuilder<C: Config> {
    fn poseidon2_permute_v2(&mut self, state: [Felt<C::F>; WIDTH]) -> [Felt<C::F>; WIDTH];
}

impl<C: Config> CircuitBuilder<C> for Builder<C> {
    fn poseidon2_permute_v2(&mut self, array: [Felt<C::F>; WIDTH]) -> [Felt<C::F>; WIDTH] {
        // Make new felts and then pass it along
        let output: [Felt<C::F>; WIDTH] = core::array::from_fn(|_| self.uninit());
        self.operations
            .push(DslIr::CircuitV2Poseidon2PermuteBabyBear(output, array));
        output
    }
}
