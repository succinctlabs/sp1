use p3_field::AbstractField;
use sp1_recursion_core::runtime::NUM_BITS;

use crate::prelude::Array;
use crate::prelude::Builder;
use crate::prelude::Config;
use crate::prelude::DslIR;
use crate::prelude::Felt;
use crate::prelude::Usize;
use crate::prelude::Var;
use crate::verifier::fri::types::DIGEST_SIZE;
use crate::verifier::fri::types::PERMUTATION_WIDTH;

impl<C: Config> Builder<C> {
    /// Throws an error.
    pub fn error(&mut self) {
        self.operations.push(DslIR::Error());
    }

    pub fn log2(&mut self, _: Var<C::N>) -> Var<C::N> {
        todo!()
    }

    /// Converts a usize to a fixed length of bits.
    pub fn num2bits_usize(&mut self, num: impl Into<Usize<C::N>>) -> Array<C, Var<C::N>> {
        // TODO: A separate function for a circuit backend.

        let num = num.into();
        // Allocate an array for the output.
        let output = self.dyn_array::<Var<_>>(NUM_BITS);
        // Hint the bits of the number to the output array.
        self.operations.push(DslIR::HintBitsU(output.clone(), num));

        // Assert that the entries are bits, compute the sum, and compare it to the original number.
        // If the number does not fit in `NUM_BITS`, we will get an error.
        let sum: Var<_> = self.eval(C::N::zero());
        for i in 0..NUM_BITS {
            // Get the bit.
            let bit = self.get(&output, i);
            // Assert that the bit is either 0 or 1.
            self.assert_var_eq(bit * (bit - C::N::one()), C::N::zero());
            // Add `bit * 2^i` to the sum.
            self.assign(sum, sum + bit * C::N::from_canonical_u32(1 << i));
        }
        // Finally, assert that the sum is equal to the original number.
        self.assert_eq::<Usize<_>, _, _>(sum, num);

        output
    }

    /// Converts a var to a fixed length of bits.
    pub fn num2bits_v(&mut self, num: Var<C::N>) -> Array<C, Var<C::N>> {
        // TODO: A separate function for a circuit backend.

        // Allocate an array for the output.
        let output = self.dyn_array::<Var<_>>(NUM_BITS);
        // Hint the bits of the number to the output array.
        self.operations.push(DslIR::HintBitsV(output.clone(), num));

        // Assert that the entries are bits, compute the sum, and compare it to the original number.
        // If the number does not fit in `NUM_BITS`, we will get an error.
        let sum: Var<_> = self.eval(C::N::zero());
        for i in 0..NUM_BITS {
            // Get the bit.
            let bit = self.get(&output, i);
            // Assert that the bit is either 0 or 1.
            self.assert_var_eq(bit * (bit - C::N::one()), C::N::zero());
            // Add `bit * 2^i` to the sum.
            self.assign(sum, sum + bit * C::N::from_canonical_u32(1 << i));
        }
        // Finally, assert that the sum is equal to the original number.
        self.assert_var_eq(sum, num);

        output
    }

    /// Converts a felt to a fixed length of bits.
    pub fn num2bits_f(&mut self, num: Felt<C::F>) -> Array<C, Var<C::N>> {
        // TODO: A separate function for a circuit backend.

        // Allocate an array for the output.
        let output = self.dyn_array::<Var<_>>(NUM_BITS);
        // Hint the bits of the number to the output array.
        self.operations.push(DslIR::HintBitsF(output.clone(), num));

        // Assert that the entries are bits, compute the sum, and compare it to the original number.
        // If the number does not fit in `NUM_BITS`, we will get an error.
        let sum: Felt<_> = self.eval(C::F::zero());
        for i in 0..NUM_BITS {
            // Get the bit.
            let bit = self.get(&output, i);
            // Assert that the bit is either 0 or 1.
            self.assert_var_eq(bit * (bit - C::N::one()), C::N::zero());
            // Add `bit * 2^i` to the sum.
            self.if_eq(bit, C::N::one()).then(|builder| {
                builder.assign(sum, sum + C::F::from_canonical_u32(1 << i));
            });
        }
        // Finally, assert that the sum is equal to the original number.
        self.assert_felt_eq(sum, num);

        output
    }

    /// Applies the Poseidon2 permutation to the given array.
    ///
    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/poseidon2/src/lib.rs#L119
    pub fn poseidon2_permute(&mut self, array: &Array<C, Felt<C::F>>) -> Array<C, Felt<C::F>> {
        let output = match array {
            Array::Fixed(values) => {
                assert_eq!(values.len(), PERMUTATION_WIDTH);
                self.array::<Felt<C::F>, _>(Usize::Const(PERMUTATION_WIDTH))
            }
            Array::Dyn(_, len) => self.array::<Felt<C::F>, _>(*len),
        };
        self.operations
            .push(DslIR::Poseidon2Permute(output.clone(), array.clone()));
        output
    }

    /// Applies the Poseidon2 compression function to the given array.
    ///
    /// Assumes we are doing a 2-1 compression function with 8 element chunks.
    ///
    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/symmetric/src/compression.rs#L35
    pub fn poseidon2_compress(
        &mut self,
        left: &Array<C, Felt<C::F>>,
        right: &Array<C, Felt<C::F>>,
    ) -> Array<C, Felt<C::F>> {
        let output = match left {
            Array::Fixed(values) => {
                assert_eq!(values.len(), DIGEST_SIZE);
                self.array::<Felt<C::F>, _>(Usize::Const(DIGEST_SIZE))
            }
            Array::Dyn(_, _) => {
                let len: Var<C::N> = self.eval(C::N::from_canonical_usize(DIGEST_SIZE));
                self.array::<Felt<C::F>, _>(Usize::Var(len))
            }
        };
        self.operations.push(DslIR::Poseidon2Compress(
            output.clone(),
            left.clone(),
            right.clone(),
        ));
        output
    }

    /// Applies the Poseidon2 hash function to the given array using a padding-free sponge.
    ///
    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/symmetric/src/sponge.rs#L32
    pub fn poseidon2_hash(&mut self, input: Array<C, Felt<C::F>>) -> Array<C, Felt<C::F>> {
        let len = match input {
            Array::Fixed(_) => Usize::Const(PERMUTATION_WIDTH),
            Array::Dyn(_, _) => {
                let len: Var<_> = self.eval(C::N::from_canonical_usize(PERMUTATION_WIDTH));
                Usize::Var(len)
            }
        };
        let state = self.array::<Felt<C::F>, _>(len);
        let start: Usize<C::N> = Usize::Const(0);
        let end = len;
        self.range(start, end).for_each(|_, builder| {
            let new_state = builder.poseidon2_permute(&state);
            builder.assign(state.clone(), new_state);
        });
        state
    }

    /// Materializes a usize into a variable.
    pub fn materialize(&mut self, num: Usize<C::N>) -> Var<C::N> {
        match num {
            Usize::Const(num) => self.eval(C::N::from_canonical_usize(num)),
            Usize::Var(num) => num,
        }
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/baby-bear/src/baby_bear.rs#L306
    pub fn generator(&mut self) -> Felt<C::F> {
        self.eval(C::F::from_canonical_u32(0x78000000))
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/baby-bear/src/baby_bear.rs#L302
    #[allow(unused_variables)]
    pub fn two_adic_generator(&mut self, bits: Usize<C::N>) -> Felt<C::F> {
        let result = self.uninit();
        self.operations.push(DslIR::TwoAdicGenerator(result, bits));
        result
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/util/src/lib.rs#L59
    #[allow(unused_variables)]
    pub fn reverse_bits_len(&mut self, index: Var<C::N>, bit_len: Usize<C::N>) -> Usize<C::N> {
        let result = self.uninit();
        self.operations
            .push(DslIR::ReverseBitsLen(result, Usize::Var(index), bit_len));
        result
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/field/src/field.rs#L79
    #[allow(unused_variables)]
    pub fn exp_usize_f(&mut self, x: Felt<C::F>, power: Usize<C::N>) -> Felt<C::F> {
        let result = self.uninit();
        self.operations.push(DslIR::ExpUsizeF(result, x, power));
        result
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/field/src/field.rs#L79
    #[allow(unused_variables)]
    pub fn exp_usize_v(&mut self, x: Var<C::N>, power: Usize<C::N>) -> Var<C::N> {
        let result = self.uninit();
        self.operations.push(DslIR::ExpUsizeV(result, x, power));
        result
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};
    use sp1_core::{stark::StarkGenericConfig, utils::BabyBearPoseidon2};
    use sp1_recursion_core::runtime::{Runtime, NUM_BITS};

    use p3_field::AbstractField;

    use crate::{
        asm::VmBuilder,
        prelude::{Felt, Usize, Var},
    };

    #[test]
    fn test_num2bits() {
        type SC = BabyBearPoseidon2;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;

        let mut rng = thread_rng();
        let config = SC::default();

        // Initialize a builder.
        let mut builder = VmBuilder::<F, EF>::default();

        // Get a random var with `NUM_BITS` bits.
        let num_val: usize = rng.gen_range(0..(1 << NUM_BITS));

        // Materialize the number as a var
        let num: Var<_> = builder.eval(F::from_canonical_usize(num_val));
        // Materialize the number as a felt
        let num_felt: Felt<_> = builder.eval(F::from_canonical_usize(num_val));
        // Materialize the number as a usize
        let num_usize: Usize<_> = builder.eval(num_val);

        // Get the bits.
        let bits = builder.num2bits_v(num);
        let bits_felt = builder.num2bits_f(num_felt);
        let bits_usize = builder.num2bits_usize(num_usize);

        // Compare the expected bits with the actual bits.
        for i in 0..NUM_BITS {
            // Get the i-th bit of the number.
            let expected_bit = F::from_canonical_usize((num_val >> i) & 1);
            // Compare the expected bit of the var with the actual bit.
            let bit = builder.get(&bits, i);
            builder.assert_var_eq(bit, expected_bit);
            // Compare the expected bit of the felt with the actual bit.
            let bit_felt = builder.get(&bits_felt, i);
            builder.assert_var_eq(bit_felt, expected_bit);
            // Compare the expected bit of the usize with the actual bit.
            let bit_usize = builder.get(&bits_usize, i);
            builder.assert_var_eq(bit_usize, expected_bit);
        }

        let program = builder.compile();

        let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
        runtime.run();
    }
}
