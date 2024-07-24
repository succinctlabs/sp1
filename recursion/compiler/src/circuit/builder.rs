//! An implementation of Poseidon2 over BN254.

use p3_field::AbstractField;

use crate::prelude::*;
use sp1_recursion_core_v2::{poseidon2_skinny::WIDTH, DIGEST_SIZE, HASH_RATE, NUM_BITS};

pub trait CircuitV2Builder<C: Config> {
    fn num2bits_v2_f(&mut self, num: Felt<C::F>) -> Vec<Felt<C::F>>;
    fn exp_reverse_bits_v2(&mut self, input: Felt<C::F>, power_bits: Vec<Felt<C::F>>)
        -> Felt<C::F>;
    fn poseidon2_permute_v2_skinny(&mut self, state: [Felt<C::F>; WIDTH]) -> [Felt<C::F>; WIDTH];
    fn poseidon2_permute_v2_wide(&mut self, state: [Felt<C::F>; WIDTH]) -> [Felt<C::F>; WIDTH];
    fn poseidon2_hash_v2(&mut self, array: &[Felt<C::F>]) -> [Felt<C::F>; DIGEST_SIZE];
    fn fri_fold_v2(&mut self, input: CircuitV2FriFoldInput<C>) -> CircuitV2FriFoldOutput<C>;
}

impl<C: Config> CircuitV2Builder<C> for Builder<C> {
    /// Converts a felt to bits inside a circuit.
    fn num2bits_v2_f(&mut self, num: Felt<C::F>) -> Vec<Felt<C::F>> {
        let output = std::iter::from_fn(|| Some(self.uninit()))
            .take(NUM_BITS)
            .collect::<Vec<_>>();
        self.push(DslIr::CircuitV2HintBitsF(output.clone(), num));

        let x: SymbolicFelt<_> = output
            .iter()
            .enumerate()
            .map(|(i, &bit)| {
                self.assert_felt_eq(bit * (bit - C::F::one()), C::F::zero());
                bit * C::F::from_canonical_u32(1 << i)
            })
            .sum();

        self.assert_felt_eq(x, num);

        output
    }
    /// A version of `exp_reverse_bits_len` that uses the ExpReverseBitsLen precompile.
    fn exp_reverse_bits_v2(
        &mut self,
        input: Felt<C::F>,
        power_bits: Vec<Felt<C::F>>,
    ) -> Felt<C::F> {
        let output: Felt<_> = self.uninit();
        self.operations
            .push(DslIr::CircuitV2ExpReverseBits(output, input, power_bits));
        output
    }
    /// Applies the Poseidon2 permutation to the given array.
    fn poseidon2_permute_v2_skinny(&mut self, array: [Felt<C::F>; WIDTH]) -> [Felt<C::F>; WIDTH] {
        let output: [Felt<C::F>; WIDTH] = core::array::from_fn(|_| self.uninit());
        self.operations
            .push(DslIr::CircuitV2Poseidon2PermuteBabyBearSkinny(
                output, array,
            ));
        output
    }
    /// Applies the Poseidon2 permutation to the given array using the wide precompile.
    fn poseidon2_permute_v2_wide(&mut self, array: [Felt<C::F>; WIDTH]) -> [Felt<C::F>; WIDTH] {
        let output: [Felt<C::F>; WIDTH] = core::array::from_fn(|_| self.uninit());
        self.operations
            .push(DslIr::CircuitV2Poseidon2PermuteBabyBearWide(output, array));
        output
    }
    /// Applies the Poseidon2 permutation to the given array.
    ///
    /// Reference: [p3_symmetric::PaddingFreeSponge]
    fn poseidon2_hash_v2(&mut self, input: &[Felt<C::F>]) -> [Felt<C::F>; DIGEST_SIZE] {
        // static_assert(RATE < WIDTH)
        let mut state = core::array::from_fn(|_| self.eval(C::F::zero()));
        for input_chunk in input.chunks(HASH_RATE) {
            state[..input_chunk.len()].copy_from_slice(input_chunk);
            state = self.poseidon2_permute_v2_skinny(state);
        }
        state[..DIGEST_SIZE].try_into().unwrap()
    }
    /// Runs FRI fold.
    fn fri_fold_v2(&mut self, input: CircuitV2FriFoldInput<C>) -> CircuitV2FriFoldOutput<C> {
        let mut uninit_array = || {
            std::iter::from_fn(|| Some(self.uninit()))
                .take(NUM_BITS)
                .collect()
        };
        let output = CircuitV2FriFoldOutput {
            alpha_pow_output: uninit_array(),
            ro_output: uninit_array(),
        };
        self.operations
            .push(DslIr::CircuitV2FriFold(output.clone(), input));
        output
    }
}
