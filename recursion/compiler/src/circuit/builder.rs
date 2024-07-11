//! An implementation of Poseidon2 over BN254.

use crate::prelude::*;
use sp1_recursion_core_v2::poseidon2_wide::WIDTH;

pub trait CircuitV2Builder<C: Config> {
    fn exp_reverse_bits_v2(&mut self, input: Felt<C::F>, power_bits: Vec<Var<C::N>>) -> Felt<C::F>;
    fn poseidon2_permute_v2(&mut self, state: [Felt<C::F>; WIDTH]) -> [Felt<C::F>; WIDTH];
}

impl<C: Config> CircuitV2Builder<C> for Builder<C> {
    /// A version of `exp_reverse_bits_len` that uses the ExpReverseBitsLen precompile.
    fn exp_reverse_bits_v2(&mut self, input: Felt<C::F>, power_bits: Vec<Var<C::N>>) -> Felt<C::F> {
        let output: Felt<_> = self.uninit();
        self.operations
            .push(DslIr::CircuitV2ExpReverseBits(output, input, power_bits));
        output
    }
    fn poseidon2_permute_v2(&mut self, array: [Felt<C::F>; WIDTH]) -> [Felt<C::F>; WIDTH] {
        // Make new felts and then pass it along
        let output: [Felt<C::F>; WIDTH] = core::array::from_fn(|_| self.uninit());
        self.operations
            .push(DslIr::CircuitV2Poseidon2PermuteBabyBear(output, array));
        output
    }
}
