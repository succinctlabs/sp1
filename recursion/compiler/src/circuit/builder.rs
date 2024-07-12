//! An implementation of Poseidon2 over BN254.

use p3_field::AbstractField;

use crate::prelude::*;
use sp1_recursion_core_v2::{poseidon2_wide::WIDTH, NUM_BITS};

pub trait CircuitV2Builder<C: Config> {
    fn num2bits_f_circuit(&mut self, num: Felt<C::F>) -> Vec<Var<C::N>>;
    fn exp_reverse_bits_v2(&mut self, input: Felt<C::F>, power_bits: Vec<Var<C::N>>) -> Felt<C::F>;
    fn poseidon2_permute_v2(&mut self, state: [Felt<C::F>; WIDTH]) -> [Felt<C::F>; WIDTH];
}

impl<C: Config> CircuitV2Builder<C> for Builder<C> {
    /// Converts a felt to bits inside a circuit.
    fn num2bits_f_circuit(&mut self, num: Felt<C::F>) -> Vec<Var<C::N>> {
        let output = std::iter::from_fn(|| Some(self.uninit()))
            .take(NUM_BITS)
            .collect::<Vec<_>>();
        self.push(DslIr::CircuitV2HintBitsF(output.clone(), num));

        let sum: Felt<_> = self.eval(C::F::zero());
        for i in 0..NUM_BITS {
            let bit = output[i];
            self.assert_var_eq(bit * (bit - C::N::one()), C::N::zero());
            self.if_eq(bit, C::N::one()).then(|builder| {
                builder.assign(sum, sum + C::F::from_canonical_u32(1 << i));
            });
        }

        self.assert_felt_eq(sum, num);

        output
    }
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
