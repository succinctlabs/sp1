//! Copied from [`sp1_recursion_program`].

use std::{
    iter::{repeat, zip},
    ops::{Add, Mul},
};

use challenger::{
    CanObserveVariable, DuplexChallengerVariable, FeltChallenger, FieldChallengerVariable,
};
use p3_field::AbstractField;
use p3_matrix::dense::RowMajorMatrix;
use sp1_recursion_compiler::{
    config::InnerConfig,
    ir::{Builder, Config, Ext, Felt, Variable},
};
use sp1_recursion_core_v2::{D, DIGEST_SIZE};

mod types;

pub mod build_wrap_v2;
pub mod challenger;
pub mod constraints;
pub mod domain;
pub mod fri;
pub mod machine;
pub mod stark;
pub(crate) mod utils;
pub mod witness;

pub use types::*;

use p3_challenger::{CanObserve, CanSample, FieldChallenger, GrindingChallenger};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::Radix2DitParallel;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use sp1_recursion_core_v2::stark::config::{BabyBearPoseidon2Outer, OuterValMmcs};

use p3_baby_bear::BabyBear;
use sp1_core::{stark::StarkGenericConfig, utils::BabyBearPoseidon2};

type EF = <BabyBearPoseidon2 as StarkGenericConfig>::Challenge;

pub type PcsConfig<C> = FriConfig<
    ExtensionMmcs<
        <C as StarkGenericConfig>::Val,
        <C as StarkGenericConfig>::Challenge,
        <C as BabyBearFriConfig>::ValMmcs,
    >,
>;

pub type FriMmcs<C> = ExtensionMmcs<BabyBear, EF, <C as BabyBearFriConfig>::ValMmcs>;

pub trait BabyBearFriConfig:
    StarkGenericConfig<
    Val = BabyBear,
    Challenge = EF,
    Challenger = Self::FriChallenger,
    Pcs = TwoAdicFriPcs<
        BabyBear,
        Radix2DitParallel,
        Self::ValMmcs,
        ExtensionMmcs<BabyBear, EF, Self::ValMmcs>,
    >,
>
{
    type ValMmcs: Mmcs<BabyBear, ProverData<RowMajorMatrix<BabyBear>> = Self::RowMajorProverData>;
    type RowMajorProverData: Clone;
    type FriChallenger: CanObserve<<Self::ValMmcs as Mmcs<BabyBear>>::Commitment>
        + CanSample<EF>
        + GrindingChallenger<Witness = BabyBear>
        + FieldChallenger<BabyBear>;

    fn fri_config(&self) -> &FriConfig<FriMmcs<Self>>;
}

pub trait CircuitConfig: Config {
    type Bit: Clone;
    type Digest: IntoIterator + Clone;
    type FriChallengerVariable: FieldChallengerVariable<Self, Self::Bit>;

    // Move these to their own traits later, perhaps.
    // TODO change these to be more generic (e.g. for Vars)
    fn poseidon2_hash(
        builder: &mut Builder<Self>,
        input: &[Felt<<Self as Config>::F>],
    ) -> Self::Digest;

    fn poseidon2_compress(builder: &mut Builder<Self>, input: [Self::Digest; 2]) -> Self::Digest;

    fn ext2felt(
        builder: &mut Builder<Self>,
        ext: Ext<<Self as Config>::F, <Self as Config>::EF>,
    ) -> [Felt<<Self as Config>::F>; D];

    fn exp_reverse_bits(
        builder: &mut Builder<Self>,
        input: Felt<<Self as Config>::F>,
        power_bits: Vec<Self::Bit>,
    ) -> Felt<<Self as Config>::F>;

    fn num2bits(
        builder: &mut Builder<Self>,
        num: Felt<<Self as Config>::F>,
        num_bits: usize,
    ) -> Vec<Self::Bit>;

    fn bits2num(
        builder: &mut Builder<Self>,
        bits: impl IntoIterator<Item = Self::Bit>,
    ) -> Felt<<Self as Config>::F>;

    // Encountered many issues trying to make the following two parametrically polymorphic.
    fn select_chain_hv(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        input: [Self::Digest; 2],
    ) -> [Self::Digest; 2];

    #[allow(clippy::type_complexity)]
    fn select_chain_ef(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Ext<<Self as Config>::F, <Self as Config>::EF>> + Clone,
        second: impl IntoIterator<Item = Ext<<Self as Config>::F, <Self as Config>::EF>> + Clone,
    ) -> Vec<Ext<<Self as Config>::F, <Self as Config>::EF>>;

    fn assert_digest_eq(builder: &mut Builder<Self>, a: Self::Digest, b: Self::Digest);

    fn observe_digest(
        builder: &mut Builder<Self>,
        challenger: &mut Self::FriChallengerVariable,
        digest: Self::Digest,
    );
}

impl BabyBearFriConfig for BabyBearPoseidon2 {
    type ValMmcs = sp1_core::utils::baby_bear_poseidon2::ValMmcs;
    type FriChallenger = <Self as StarkGenericConfig>::Challenger;
    type RowMajorProverData =
        <sp1_core::utils::baby_bear_poseidon2::ValMmcs as Mmcs<BabyBear>>::ProverData<
            RowMajorMatrix<BabyBear>,
        >;

    fn fri_config(&self) -> &FriConfig<FriMmcs<Self>> {
        self.pcs().fri_config()
    }
}

impl CircuitConfig for InnerConfig {
    type Bit = Felt<<Self as Config>::F>;
    type Digest = [Felt<<Self as Config>::F>; 8];
    type FriChallengerVariable = DuplexChallengerVariable<Self>;

    fn poseidon2_hash(
        builder: &mut Builder<Self>,
        input: &[Felt<<Self as Config>::F>],
    ) -> Self::Digest {
        builder.poseidon2_hash_v2(input)
    }

    fn poseidon2_compress(builder: &mut Builder<Self>, input: [Self::Digest; 2]) -> Self::Digest {
        builder.poseidon2_compress_v2(input.into_iter().flatten())
    }

    fn ext2felt(
        builder: &mut Builder<Self>,
        ext: Ext<<Self as Config>::F, <Self as Config>::EF>,
    ) -> [Felt<<Self as Config>::F>; D] {
        builder.ext2felt_v2(ext)
    }

    fn exp_reverse_bits(
        builder: &mut Builder<Self>,
        input: Felt<<Self as Config>::F>,
        power_bits: Vec<Felt<<Self as Config>::F>>,
    ) -> Felt<<Self as Config>::F> {
        builder.exp_reverse_bits_v2(input, power_bits)
    }

    fn num2bits(
        builder: &mut Builder<Self>,
        num: Felt<<Self as Config>::F>,
        num_bits: usize,
    ) -> Vec<Felt<<Self as Config>::F>> {
        builder.num2bits_v2_f(num, num_bits)
    }

    fn bits2num(
        builder: &mut Builder<Self>,
        bits: impl IntoIterator<Item = Felt<<Self as Config>::F>>,
    ) -> Felt<<Self as Config>::F> {
        builder.bits2num_v2_f(bits)
    }

    fn select_chain_hv(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
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

    fn select_chain_ef(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Ext<<Self as Config>::F, <Self as Config>::EF>> + Clone,
        second: impl IntoIterator<Item = Ext<<Self as Config>::F, <Self as Config>::EF>> + Clone,
    ) -> Vec<Ext<<Self as Config>::F, <Self as Config>::EF>> {
        select_chain(builder, should_swap, first, second).collect::<Vec<_>>()
    }

    fn assert_digest_eq(builder: &mut Builder<Self>, a: Self::Digest, b: Self::Digest) {
        zip(a, b).for_each(|(e1, e2)| builder.assert_felt_eq(e1, e2));
    }

    fn observe_digest(
        builder: &mut Builder<Self>,
        challenger: &mut Self::FriChallengerVariable,
        digest: Self::Digest,
    ) {
        challenger.observe_slice(builder, digest);
    }
}

impl BabyBearFriConfig for BabyBearPoseidon2Outer {
    type ValMmcs = OuterValMmcs;
    type FriChallenger = <Self as StarkGenericConfig>::Challenger;

    type RowMajorProverData =
        <OuterValMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>;

    fn fri_config(&self) -> &FriConfig<FriMmcs<Self>> {
        self.pcs().fri_config()
    }
}

pub fn select_chain<'a, C, R, S>(
    builder: &'a mut Builder<C>,
    should_swap: R,
    first: impl IntoIterator<Item = S> + Clone + 'a,
    second: impl IntoIterator<Item = S> + Clone + 'a,
) -> impl Iterator<Item = S> + 'a
where
    C: Config,
    R: Variable<C> + 'a,
    S: Variable<C> + 'a,
    <R as Variable<C>>::Expression: AbstractField,
    <S as Variable<C>>::Expression: Add<Output = <S as Variable<C>>::Expression>
        + Mul<<R as Variable<C>>::Expression, Output = <S as Variable<C>>::Expression>,
{
    let should_swap: <R as Variable<C>>::Expression = should_swap.into();
    let one = <R as Variable<C>>::Expression::one();
    let shouldnt_swap = one - should_swap.clone();

    let id_branch = first
        .clone()
        .into_iter()
        .chain(second.clone())
        .map(<S as Variable<C>>::Expression::from);
    let swap_branch = second
        .into_iter()
        .chain(first)
        .map(<S as Variable<C>>::Expression::from);
    zip(
        zip(id_branch, swap_branch),
        zip(repeat(shouldnt_swap), repeat(should_swap)),
    )
    .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_v * id_c + sw_v * sw_c))
}
