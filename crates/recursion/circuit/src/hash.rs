use std::{
    borrow::Borrow,
    iter::{repeat, zip},
};

use itertools::Itertools;
use slop_algebra::{AbstractField, Field};
use slop_bn254::{outer_perm, Bn254Fr, OUTER_CHALLENGER_STATE_WIDTH};
use slop_challenger::IopCtx;
use slop_symmetric::{CryptographicHasher, Permutation};
use sp1_hypercube::{inner_perm, SP1InnerPcs};
use sp1_primitives::{SP1Field, SP1GlobalContext, SP1OuterGlobalContext};
use sp1_recursion_compiler::ir::{Builder, DslIr, Felt, Var};
use sp1_recursion_executor::{DIGEST_SIZE, HASH_RATE, PERMUTATION_WIDTH};

use crate::{
    challenger::{reduce_31, POSEIDON_2_BB_RATE},
    CircuitConfig,
};

pub trait FieldHasher: IopCtx {
    fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest;

    fn hash_slice(input: &[Self::F]) -> Self::Digest;
}

pub trait Poseidon2SP1FieldHasherVariable<C: CircuitConfig> {
    fn poseidon2_permute(
        builder: &mut Builder<C>,
        state: [Felt<SP1Field>; PERMUTATION_WIDTH],
    ) -> [Felt<SP1Field>; PERMUTATION_WIDTH];

    /// Permutes 8 independent states, which must not depend on each other's outputs.
    /// The default lowers to 8 scalar permutations.
    fn poseidon2_permute_batch8(
        builder: &mut Builder<C>,
        states: [[Felt<SP1Field>; PERMUTATION_WIDTH]; 8],
    ) -> [[Felt<SP1Field>; PERMUTATION_WIDTH]; 8] {
        states.map(|state| Self::poseidon2_permute(builder, state))
    }

    /// Applies the Poseidon2 hash function to the given array.
    ///
    /// Reference: [p3_symmetric::PaddingFreeSponge]
    fn poseidon2_hash(
        builder: &mut Builder<C>,
        input: &[Felt<SP1Field>],
    ) -> [Felt<SP1Field>; DIGEST_SIZE] {
        // static_assert(RATE < WIDTH)
        let mut state = core::array::from_fn(|_| builder.eval(SP1Field::zero()));
        for input_chunk in input.chunks(HASH_RATE) {
            state[..input_chunk.len()].copy_from_slice(input_chunk);
            state = Self::poseidon2_permute(builder, state);
        }
        let digest: [Felt<SP1Field>; DIGEST_SIZE] = state[..DIGEST_SIZE].try_into().unwrap();
        digest
    }

    /// Hashes 8 equal-length inputs in lockstep, so the permutations at each absorb step
    /// form an independent 8-lane batch. Lane-wise identical to [`Self::poseidon2_hash`].
    fn poseidon2_hash_batch8(
        builder: &mut Builder<C>,
        inputs: &[Vec<Felt<SP1Field>>; 8],
    ) -> [[Felt<SP1Field>; DIGEST_SIZE]; 8] {
        let len = inputs[0].len();
        assert!(
            inputs.iter().all(|input| input.len() == len),
            "batched hash requires equal input lengths"
        );
        let mut states: [[Felt<SP1Field>; PERMUTATION_WIDTH]; 8] =
            core::array::from_fn(|_| core::array::from_fn(|_| builder.eval(SP1Field::zero())));
        let mut offset = 0;
        while offset < len {
            let chunk = (len - offset).min(HASH_RATE);
            for (state, input) in states.iter_mut().zip(inputs.iter()) {
                state[..chunk].copy_from_slice(&input[offset..offset + chunk]);
            }
            states = Self::poseidon2_permute_batch8(builder, states);
            offset += chunk;
        }
        states.map(|state| state[..DIGEST_SIZE].try_into().unwrap())
    }
}

pub trait FieldHasherVariable<C: CircuitConfig>: FieldHasher {
    type DigestVariable: Clone + Copy;

    fn hash(builder: &mut Builder<C>, input: &[Felt<SP1Field>]) -> Self::DigestVariable;

    fn compress(builder: &mut Builder<C>, input: [Self::DigestVariable; 2])
        -> Self::DigestVariable;

    /// Hashes 8 equal-length inputs, lane-wise identical to [`Self::hash`]. The default
    /// hashes each lane separately; hashers backed by batchable permutations override this.
    fn hash_batch8(
        builder: &mut Builder<C>,
        inputs: &[Vec<Felt<SP1Field>>; 8],
    ) -> [Self::DigestVariable; 8] {
        core::array::from_fn(|lane| Self::hash(builder, &inputs[lane]))
    }

    /// Compresses 8 digest pairs, lane-wise identical to [`Self::compress`]. The default
    /// compresses each lane separately.
    fn compress_batch8(
        builder: &mut Builder<C>,
        inputs: [[Self::DigestVariable; 2]; 8],
    ) -> [Self::DigestVariable; 8] {
        inputs.map(|pair| Self::compress(builder, pair))
    }

    fn assert_digest_eq(builder: &mut Builder<C>, a: Self::DigestVariable, b: Self::DigestVariable);

    // Encountered many issues trying to make the following two parametrically polymorphic.
    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: C::Bit,
        input: [Self::DigestVariable; 2],
    ) -> [Self::DigestVariable; 2];

    fn print_digest(builder: &mut Builder<C>, digest: Self::DigestVariable);
}

impl FieldHasher for SP1GlobalContext {
    fn constant_compress(
        input: [<SP1GlobalContext as IopCtx>::Digest; 2],
    ) -> <SP1GlobalContext as IopCtx>::Digest {
        let mut pre_iter = input.into_iter().flatten().chain(repeat(SP1Field::zero()));
        let mut pre = core::array::from_fn(move |_| pre_iter.next().unwrap());
        inner_perm().permute_mut(&mut pre);
        pre[..DIGEST_SIZE].try_into().unwrap()
    }

    fn hash_slice(input: &[SP1Field]) -> <SP1GlobalContext as IopCtx>::Digest {
        let mut state = [SP1Field::zero(); PERMUTATION_WIDTH];
        for input_chunk in input.chunks(HASH_RATE) {
            state[..input_chunk.len()].copy_from_slice(input_chunk);
            inner_perm().permute_mut(&mut state);
        }
        let digest: [SP1Field; DIGEST_SIZE] = state[..DIGEST_SIZE].try_into().unwrap();
        digest
    }
}

impl<C: CircuitConfig> Poseidon2SP1FieldHasherVariable<C> for SP1InnerPcs {
    fn poseidon2_permute(
        builder: &mut Builder<C>,
        input: [Felt<SP1Field>; PERMUTATION_WIDTH],
    ) -> [Felt<SP1Field>; PERMUTATION_WIDTH] {
        C::poseidon2_permute_v2(builder, input)
    }

    fn poseidon2_permute_batch8(
        builder: &mut Builder<C>,
        states: [[Felt<SP1Field>; PERMUTATION_WIDTH]; 8],
    ) -> [[Felt<SP1Field>; PERMUTATION_WIDTH]; 8] {
        C::poseidon2_permute_v2_batch8(builder, states)
    }
}

impl<C: CircuitConfig> Poseidon2SP1FieldHasherVariable<C> for SP1GlobalContext {
    fn poseidon2_permute(
        builder: &mut Builder<C>,
        input: [Felt<SP1Field>; PERMUTATION_WIDTH],
    ) -> [Felt<SP1Field>; PERMUTATION_WIDTH] {
        C::poseidon2_permute_v2(builder, input)
    }

    fn poseidon2_permute_batch8(
        builder: &mut Builder<C>,
        states: [[Felt<SP1Field>; PERMUTATION_WIDTH]; 8],
    ) -> [[Felt<SP1Field>; PERMUTATION_WIDTH]; 8] {
        C::poseidon2_permute_v2_batch8(builder, states)
    }
}

impl<C: CircuitConfig<Bit = Felt<SP1Field>>> FieldHasherVariable<C> for SP1GlobalContext {
    type DigestVariable = [Felt<SP1Field>; DIGEST_SIZE];

    fn hash(builder: &mut Builder<C>, input: &[Felt<SP1Field>]) -> Self::DigestVariable {
        <Self as Poseidon2SP1FieldHasherVariable<C>>::poseidon2_hash(builder, input)
    }

    fn compress(
        builder: &mut Builder<C>,
        input: [Self::DigestVariable; 2],
    ) -> Self::DigestVariable {
        C::poseidon2_compress_v2(builder, input.into_iter().flatten())
    }

    fn hash_batch8(
        builder: &mut Builder<C>,
        inputs: &[Vec<Felt<SP1Field>>; 8],
    ) -> [Self::DigestVariable; 8] {
        <Self as Poseidon2SP1FieldHasherVariable<C>>::poseidon2_hash_batch8(builder, inputs)
    }

    fn compress_batch8(
        builder: &mut Builder<C>,
        inputs: [[Self::DigestVariable; 2]; 8],
    ) -> [Self::DigestVariable; 8] {
        let states: [[Felt<SP1Field>; PERMUTATION_WIDTH]; 8] = inputs.map(|[left, right]| {
            core::array::from_fn(|i| if i < DIGEST_SIZE { left[i] } else { right[i - DIGEST_SIZE] })
        });
        let post =
            <Self as Poseidon2SP1FieldHasherVariable<C>>::poseidon2_permute_batch8(builder, states);
        post.map(|state| state[..DIGEST_SIZE].try_into().unwrap())
    }

    fn assert_digest_eq(
        builder: &mut Builder<C>,
        a: Self::DigestVariable,
        b: Self::DigestVariable,
    ) {
        // Push the instruction directly instead of passing through `assert_felt_eq` in order to
        //avoid symbolic expression overhead.
        zip(a, b).for_each(|(e1, e2)| builder.push_op(DslIr::AssertEqF(e1, e2)));
    }

    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: <C as CircuitConfig>::Bit,
        input: [Self::DigestVariable; 2],
    ) -> [Self::DigestVariable; 2] {
        let result0: [Felt<SP1Field>; DIGEST_SIZE] = core::array::from_fn(|_| builder.uninit());
        let result1: [Felt<SP1Field>; DIGEST_SIZE] = core::array::from_fn(|_| builder.uninit());

        (0..DIGEST_SIZE).for_each(|i| {
            builder.push_op(DslIr::Select(
                should_swap,
                result0[i],
                result1[i],
                input[0][i],
                input[1][i],
            ));
        });

        [result0, result1]
    }

    fn print_digest(builder: &mut Builder<C>, digest: Self::DigestVariable) {
        for d in digest.iter() {
            builder.print_f(*d);
        }
    }
}

impl<C: CircuitConfig> Poseidon2SP1FieldHasherVariable<C> for SP1OuterGlobalContext {
    fn poseidon2_permute(
        builder: &mut Builder<C>,
        state: [Felt<SP1Field>; PERMUTATION_WIDTH],
    ) -> [Felt<SP1Field>; PERMUTATION_WIDTH] {
        let state: [Felt<_>; PERMUTATION_WIDTH] = state.map(|x| builder.eval(x));
        builder.push_op(DslIr::CircuitPoseidon2PermuteKoalaBear(Box::new(state)));
        state
    }
}

pub const BN254_DIGEST_SIZE: usize = 1;

impl FieldHasher for SP1OuterGlobalContext {
    fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest {
        let mut state = [
            Borrow::<[Bn254Fr; 1]>::borrow(&input[0])[0],
            Borrow::<[Bn254Fr; 1]>::borrow(&input[1])[0],
            Bn254Fr::zero(),
        ];
        outer_perm().permute_mut(&mut state);
        [state[0]; BN254_DIGEST_SIZE].into()
    }

    fn hash_slice(input: &[SP1Field]) -> Self::Digest {
        SP1OuterGlobalContext::default_hasher_and_compressor().0.hash_slice(input)
    }
}

impl<C: CircuitConfig<N = Bn254Fr, Bit = Var<Bn254Fr>>> FieldHasherVariable<C>
    for SP1OuterGlobalContext
{
    type DigestVariable = [Var<Bn254Fr>; BN254_DIGEST_SIZE];

    fn hash(builder: &mut Builder<C>, input: &[Felt<SP1Field>]) -> Self::DigestVariable {
        assert!(C::N::bits() == slop_bn254::Bn254Fr::bits());
        assert!(SP1Field::bits() == sp1_primitives::SP1Field::bits());
        let num_f_elms = C::N::bits() / SP1Field::bits();
        let mut state: [Var<C::N>; OUTER_CHALLENGER_STATE_WIDTH] =
            [builder.eval(C::N::zero()), builder.eval(C::N::zero()), builder.eval(C::N::zero())];
        for block_chunk in &input.iter().chunks(POSEIDON_2_BB_RATE) {
            for (chunk_id, chunk) in (&block_chunk.chunks(num_f_elms)).into_iter().enumerate() {
                let chunk = chunk.copied().collect::<Vec<_>>();
                state[chunk_id] = reduce_31(builder, chunk.as_slice());
            }
            builder.push_op(DslIr::CircuitPoseidon2Permute(state))
        }

        [state[0]; BN254_DIGEST_SIZE]
    }

    fn compress(
        builder: &mut Builder<C>,
        input: [Self::DigestVariable; 2],
    ) -> Self::DigestVariable {
        let state: [Var<C::N>; OUTER_CHALLENGER_STATE_WIDTH] =
            [builder.eval(input[0][0]), builder.eval(input[1][0]), builder.eval(C::N::zero())];
        builder.push_op(DslIr::CircuitPoseidon2Permute(state));
        [state[0]; BN254_DIGEST_SIZE]
    }

    fn assert_digest_eq(
        builder: &mut Builder<C>,
        a: Self::DigestVariable,
        b: Self::DigestVariable,
    ) {
        zip(a, b).for_each(|(e1, e2)| builder.assert_var_eq(e1, e2));
    }

    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: <C as CircuitConfig>::Bit,
        input: [Self::DigestVariable; 2],
    ) -> [Self::DigestVariable; 2] {
        let result0: [Var<_>; BN254_DIGEST_SIZE] = core::array::from_fn(|j| {
            let result = builder.uninit();
            builder.push_op(DslIr::CircuitSelectV(should_swap, input[1][j], input[0][j], result));
            result
        });
        let result1: [Var<_>; BN254_DIGEST_SIZE] = core::array::from_fn(|j| {
            let result = builder.uninit();
            builder.push_op(DslIr::CircuitSelectV(should_swap, input[0][j], input[1][j], result));
            result
        });

        [result0, result1]
    }

    fn print_digest(builder: &mut Builder<C>, digest: Self::DigestVariable) {
        for d in digest.iter() {
            builder.print_v(*d);
        }
    }
}
