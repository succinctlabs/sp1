//! Copied from [`sp1_recursion_program`].

use std::{
    iter::{repeat, zip},
    ops::{Add, Mul},
};

use challenger::{CanObserveVariable, DuplexChallengerVariable, FieldChallengerVariable};
use hash::FieldHasherVariable;
use p3_field::AbstractField;
use p3_matrix::dense::RowMajorMatrix;
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    config::InnerConfig,
    ir::{Builder, Config, Ext, Felt, SymbolicFelt, Variable},
};

mod types;

pub mod build_wrap_v2;
pub mod challenger;
pub mod constraints;
pub mod domain;
pub mod fri;
pub mod hash;
pub mod machine;
pub mod stark;
pub(crate) mod utils;
pub mod witness;

use sp1_stark::{
    baby_bear_poseidon2::{BabyBearPoseidon2, ValMmcs},
    StarkGenericConfig,
};
pub use types::*;

use p3_challenger::{CanObserve, CanSample, FieldChallenger, GrindingChallenger};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::Radix2DitParallel;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use sp1_recursion_core_v2::{
    stark::config::{BabyBearPoseidon2Outer, OuterValMmcs},
    D,
};

use p3_baby_bear::BabyBear;

type EF = <BabyBearPoseidon2 as StarkGenericConfig>::Challenge;

pub type PcsConfig<C> = FriConfig<
    ExtensionMmcs<
        <C as StarkGenericConfig>::Val,
        <C as StarkGenericConfig>::Challenge,
        <C as BabyBearFriConfig>::ValMmcs,
    >,
>;

pub type Digest<C, SC> = <SC as FieldHasherVariable<C>>::Digest;

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

pub trait BabyBearFriConfigVariable<C: CircuitConfig<F = BabyBear>>:
    BabyBearFriConfig + FieldHasherVariable<C>
{
    type FriChallengerVariable: FieldChallengerVariable<C, <C as CircuitConfig>::Bit>
        + CanObserveVariable<C, <Self as FieldHasherVariable<C>>::Digest>;

    /// Get a new challenger corresponding to the given config.
    fn challenger_variable(&self, builder: &mut Builder<C>) -> Self::FriChallengerVariable;
}

pub trait CircuitConfig: Config {
    type Bit: Clone + Variable<Self, Expression = Self::BitExpression>;
    type BitExpression: AbstractField
        + Mul<
            <Felt<Self::F> as Variable<Self>>::Expression,
            Output = <Felt<Self::F> as Variable<Self>>::Expression,
        > + Mul<
            <Ext<Self::F, Self::EF> as Variable<Self>>::Expression,
            Output = <Ext<Self::F, Self::EF> as Variable<Self>>::Expression,
        >;

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

    #[allow(clippy::type_complexity)]
    fn select_chain_ef(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Ext<<Self as Config>::F, <Self as Config>::EF>> + Clone,
        second: impl IntoIterator<Item = Ext<<Self as Config>::F, <Self as Config>::EF>> + Clone,
    ) -> Vec<Ext<<Self as Config>::F, <Self as Config>::EF>> {
        select_chain(builder, should_swap, first, second).collect::<Vec<_>>()
    }
}

impl CircuitConfig for InnerConfig {
    type Bit = Felt<<Self as Config>::F>;
    type BitExpression = SymbolicFelt<<Self as Config>::F>;

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

impl BabyBearFriConfig for BabyBearPoseidon2 {
    type ValMmcs = ValMmcs;
    type FriChallenger = <Self as StarkGenericConfig>::Challenger;
    type RowMajorProverData = <ValMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>;

    fn fri_config(&self) -> &FriConfig<FriMmcs<Self>> {
        self.pcs().fri_config()
    }
}

impl<C: CircuitConfig<F = BabyBear, Bit = Felt<BabyBear>>> BabyBearFriConfigVariable<C>
    for BabyBearPoseidon2
{
    type FriChallengerVariable = DuplexChallengerVariable<C>;

    fn challenger_variable(&self, builder: &mut Builder<C>) -> Self::FriChallengerVariable {
        DuplexChallengerVariable::new(builder)
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
    <R as Variable<C>>::Expression: AbstractField
        + Mul<<S as Variable<C>>::Expression, Output = <S as Variable<C>>::Expression>,
    <S as Variable<C>>::Expression: Add<Output = <S as Variable<C>>::Expression>,
{
    let should_swap: <R as Variable<C>>::Expression = should_swap.into();
    let one = <R as Variable<C>>::Expression::one();
    let shouldnt_swap = one - should_swap.clone();

    let id_branch =
        first.clone().into_iter().chain(second.clone()).map(<S as Variable<C>>::Expression::from);
    let swap_branch = second.into_iter().chain(first).map(<S as Variable<C>>::Expression::from);
    zip(zip(id_branch, swap_branch), zip(repeat(shouldnt_swap), repeat(should_swap)))
        .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_c * id_v + sw_c * sw_v))
}
