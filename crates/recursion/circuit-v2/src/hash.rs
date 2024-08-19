use std::iter::zip;

use p3_baby_bear::BabyBear;

use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, Felt},
};
use sp1_recursion_core_v2::DIGEST_SIZE;
use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;

use crate::{select_chain, CircuitConfig};

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

// impl<C: Config<F = BabyBear>> FieldHasherVariable<C> for OuterHash {

// }
