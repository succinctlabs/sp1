use std::iter::zip;

use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, Field};

use p3_bn254_fr::Bn254Fr;
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, DslIr, Felt, Var},
};
use sp1_recursion_core_v2::{stark::config::BabyBearPoseidon2Outer, DIGEST_SIZE};
use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;

use crate::{
    challenger::{reduce_32, RATE, SPONGE_SIZE},
    select_chain, CircuitConfig,
};

pub trait FieldHasherVariable<C: CircuitConfig> {
    type Digest: Clone + Copy;

    fn hash(builder: &mut Builder<C>, input: &[Felt<C::F>]) -> Self::Digest;

    fn compress(builder: &mut Builder<C>, input: [Self::Digest; 2]) -> Self::Digest;

    fn assert_digest_eq(builder: &mut Builder<C>, a: Self::Digest, b: Self::Digest);

    // Encountered many issues trying to make the following two parametrically polymorphic.
    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: C::Bit,
        input: [Self::Digest; 2],
    ) -> [Self::Digest; 2];
}

impl<C: CircuitConfig<F = BabyBear, Bit = Felt<BabyBear>>> FieldHasherVariable<C>
    for BabyBearPoseidon2
{
    type Digest = [Felt<BabyBear>; DIGEST_SIZE];

    fn hash(builder: &mut Builder<C>, input: &[Felt<<C as Config>::F>]) -> Self::Digest {
        builder.poseidon2_hash_v2(input)
    }

    fn compress(builder: &mut Builder<C>, input: [Self::Digest; 2]) -> Self::Digest {
        builder.poseidon2_compress_v2(input.into_iter().flatten())
    }

    fn assert_digest_eq(builder: &mut Builder<C>, a: Self::Digest, b: Self::Digest) {
        zip(a, b).for_each(|(e1, e2)| builder.assert_felt_eq(e1, e2));
    }

    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: <C as CircuitConfig>::Bit,
        input: [Self::Digest; 2],
    ) -> [Self::Digest; 2] {
        let err_msg = "select_chain's return value should have length the sum of its inputs";
        let mut selected = select_chain(builder, should_swap, input[0], input[1]);
        let ret = [
            core::array::from_fn(|_| selected.next().expect(err_msg)),
            core::array::from_fn(|_| selected.next().expect(err_msg)),
        ];
        assert_eq!(selected.next(), None, "{}", err_msg);
        ret
    }
}

pub const BN254_DIGEST_SIZE: usize = 1;
impl<C: CircuitConfig<F = BabyBear, N = Bn254Fr, Bit = Var<Bn254Fr>>> FieldHasherVariable<C>
    for BabyBearPoseidon2Outer
{
    type Digest = [Var<Bn254Fr>; BN254_DIGEST_SIZE];

    fn hash(builder: &mut Builder<C>, input: &[Felt<<C as Config>::F>]) -> Self::Digest {
        assert!(C::N::bits() == p3_bn254_fr::Bn254Fr::bits());
        assert!(C::F::bits() == p3_baby_bear::BabyBear::bits());
        let num_f_elms = C::N::bits() / C::F::bits();
        let mut state: [Var<C::N>; SPONGE_SIZE] =
            [builder.eval(C::N::zero()), builder.eval(C::N::zero()), builder.eval(C::N::zero())];
        for block_chunk in &input.iter().chunks(RATE) {
            for (chunk_id, chunk) in (&block_chunk.chunks(num_f_elms)).into_iter().enumerate() {
                let chunk = chunk.collect_vec().into_iter().copied().collect::<Vec<_>>();
                state[chunk_id] = reduce_32(builder, chunk.as_slice());
            }
            builder.push(DslIr::CircuitPoseidon2Permute(state))
        }

        [state[0]; BN254_DIGEST_SIZE]
    }

    fn compress(builder: &mut Builder<C>, input: [Self::Digest; 2]) -> Self::Digest {
        let state: [Var<C::N>; SPONGE_SIZE] =
            [builder.eval(input[0][0]), builder.eval(input[1][0]), builder.eval(C::N::zero())];
        builder.push(DslIr::CircuitPoseidon2Permute(state));
        [state[0]; BN254_DIGEST_SIZE]
    }

    fn assert_digest_eq(builder: &mut Builder<C>, a: Self::Digest, b: Self::Digest) {
        zip(a, b).for_each(|(e1, e2)| builder.assert_var_eq(e1, e2));
    }

    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: <C as CircuitConfig>::Bit,
        input: [Self::Digest; 2],
    ) -> [Self::Digest; 2] {
        let result0: [Var<_>; 1] = core::array::from_fn(|j| {
            let result = builder.uninit();
            builder.push(DslIr::CircuitSelectV(should_swap, input[1][j], input[0][j], result));
            result
        });
        let result1: [Var<_>; 1] = core::array::from_fn(|j| {
            let result = builder.uninit();
            builder.push(DslIr::CircuitSelectV(should_swap, input[0][j], input[1][j], result));
            result
        });

        [result0, result1]
    }
}

// impl<C: Config<F = BabyBear>> FieldHasherVariable<C> for OuterHash {

// }
