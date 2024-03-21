use p3_field::AbstractField;

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
    pub fn num2bits_v(&mut self, num: Var<C::N>) -> Array<C, Var<C::N>> {
        let output = self.array::<Var<_>, _>(Usize::Const(29));
        self.operations
            .push(DslIR::Num2BitsV(output.clone(), Usize::Var(num)));
        output
    }

    /// Converts a felt to a fixed length of bits.
    pub fn num2bits_f(&mut self, num: Felt<C::F>) -> Array<C, Var<C::N>> {
        let output = self.array::<Var<_>, _>(Usize::Const(29));
        self.operations.push(DslIR::Num2BitsF(output.clone(), num));
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
