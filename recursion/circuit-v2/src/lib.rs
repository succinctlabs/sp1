//! Copied from [`sp1_recursion_program`].

use std::{
    iter::{repeat, zip},
    ops::{Add, Mul},
};

use challenger::{CanObserveVariable, DuplexChallengerVariable, FieldChallengerVariable};
use itertools::WhileSome;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::AbstractField;

use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    config::InnerConfig,
    ir::{Builder, Config, Ext, Felt, Variable},
};
use sp1_recursion_core_v2::{D, DIGEST_SIZE};

mod types;

pub mod build_wrap_v2;
pub mod challenger;
pub mod challenger_gnark;
pub mod constraints;
pub mod domain;
pub mod fri;
pub mod stark;
pub mod witness;

pub use types::*;

pub type DigestVariable<C> = [Felt<<C as Config>::F>; DIGEST_SIZE];

#[derive(Clone)]
pub struct FriProofVariable<C: Config> {
    pub commit_phase_commits: Vec<DigestVariable<C>>,
    pub query_proofs: Vec<FriQueryProofVariable<C>>,
    pub final_poly: Ext<C::F, C::EF>,
    pub pow_witness: Felt<C::F>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
#[derive(Clone)]
pub struct FriCommitPhaseProofStepVariable<C: Config> {
    pub sibling_value: Ext<C::F, C::EF>,
    pub opening_proof: Vec<DigestVariable<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L23
#[derive(Clone)]
pub struct FriQueryProofVariable<C: Config> {
    pub commit_phase_openings: Vec<FriCommitPhaseProofStepVariable<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L22
#[derive(Clone)]
pub struct FriChallenges<C: Config, Bit> {
    pub query_indices: Vec<Vec<Bit>>,
    pub betas: Vec<Ext<C::F, C::EF>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsProofVariable<C: Config> {
    pub fri_proof: FriProofVariable<C>,
    pub query_openings: Vec<Vec<BatchOpeningVariable<C>>>,
}

#[derive(Clone)]
pub struct BatchOpeningVariable<C: Config> {
    pub opened_values: Vec<Vec<Vec<Felt<C::F>>>>,
    pub opening_proof: Vec<DigestVariable<C>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsRoundVariable<C: Config> {
    pub batch_commit: DigestVariable<C>,
    pub domains_points_and_opens: Vec<TwoAdicPcsMatsVariable<C>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsMatsVariable<C: Config> {
    pub domain: TwoAdicMultiplicativeCoset<C::F>,
    pub points: Vec<Ext<C::F, C::EF>>,
    pub values: Vec<Vec<Ext<C::F, C::EF>>>,
}

use p3_challenger::{CanObserve, CanSample, FieldChallenger, GrindingChallenger};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::Radix2DitParallel;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use sp1_recursion_core::stark::config::{BabyBearPoseidon2Outer, OuterValMmcs};

use p3_baby_bear::BabyBear;
use sp1_core::{stark::StarkGenericConfig, utils::BabyBearPoseidon2};

type EF = <BabyBearPoseidon2 as StarkGenericConfig>::Challenge;

pub type PcsConfig<SC> = FriConfig<
    ExtensionMmcs<
        <SC as StarkGenericConfig>::Val,
        <SC as StarkGenericConfig>::Challenge,
        <SC as BabyBearFriConfig>::ValMmcs,
    >,
>;

pub type FriMmcs<SC> = ExtensionMmcs<BabyBear, EF, <SC as BabyBearFriConfig>::ValMmcs>;

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
    type ValMmcs: Mmcs<BabyBear>;
    // type RowMajorProverData: Clone;
    type FriChallenger: CanObserve<<Self::ValMmcs as Mmcs<BabyBear>>::Commitment>
        + CanSample<EF>
        + GrindingChallenger<Witness = BabyBear>
        + FieldChallenger<BabyBear>;

    fn fri_config(&self) -> &FriConfig<FriMmcs<Self>>;
}

pub trait BabyBearFriConfigVariable: BabyBearFriConfig {
    // Is this is the best place to put this?
    type C: Config<F = Self::Val, EF = Self::Challenge>;
    type Bit: Variable<Self::C, Expression = Self::BitExpression> + Clone + 'static;
    // If you try to simplify by removing this, rustc will complain about some static lifetime
    // bound not being satisfied at the call site of `select_chain`. Where? Nobody knows.
    type BitExpression: AbstractField;
    // where
    //     <Self::Bit as Variable<Self::C>>::Expression: AbstractField;
    type FriChallengerVariable: FieldChallengerVariable<Self::C, Self::Bit>;

    // Move these to their own traits later, perhaps.
    // TODO change these to be more generic (e.g. for Vars)
    fn poseidon2_hash(
        builder: &mut Builder<Self::C>,
        input: &[Felt<<Self::C as Config>::F>],
    ) -> [Felt<<Self::C as Config>::F>; DIGEST_SIZE];

    fn poseidon2_compress(
        builder: &mut Builder<Self::C>,
        input: impl IntoIterator<Item = Felt<<Self::C as Config>::F>>,
    ) -> [Felt<<Self::C as Config>::F>; DIGEST_SIZE];

    fn ext2felt(
        builder: &mut Builder<Self::C>,
        ext: Ext<<Self::C as Config>::F, <Self::C as Config>::EF>,
    ) -> [Felt<<Self::C as Config>::F>; D];

    fn exp_reverse_bits(
        builder: &mut Builder<Self::C>,
        input: Felt<<Self::C as Config>::F>,
        power_bits: Vec<Self::Bit>,
    ) -> Felt<<Self::C as Config>::F>;

    fn num2bits(
        builder: &mut Builder<Self::C>,
        num: Felt<<Self::C as Config>::F>,
        num_bits: usize,
    ) -> Vec<Self::Bit>;

    fn bits2num(
        builder: &mut Builder<Self::C>,
        bits: impl IntoIterator<Item = Self::Bit>,
    ) -> Felt<<Self::C as Config>::F>;

    fn complement(builder: &mut Builder<Self::C>, bit: Self::Bit) -> Self::Bit;

    // fn select_chain<S>(
    //     builder: &mut Builder<Self::C>,
    //     should_swap: Self::Bit,
    //     first: Vec<S>,
    //     second: Vec<S>,
    // ) -> Vec<S>
    // where
    //     S: Variable<Self::C> + AbstractField + Mul<Self::Bit, Output = S>;
    // S: Variable<Self::C>,
    // <S as Variable<Self::C>>::Expression: Add<Output = <S as Variable<Self::C>>::Expression>
    //     + Mul<
    //         <Self::Bit as Variable<Self::C>>::Expression,
    //         Output = <S as Variable<Self::C>>::Expression,
    //     >;
    // where
    //     S: Variable<Self::C> + Into<<S as Variable<Self::C>>::Expression>,
    //     <S as Variable<Self::C>>::Expression: Add<Output = <S as Variable<Self::C>>::Expression>
    //         + Mul<
    //             <Self::Bit as Variable<Self::C>>::Expression,
    //             Output = <S as Variable<Self::C>>::Expression,
    //         >
    // fn select_chain<'a, S>(
    //     builder: &'a mut Builder<Self::C>,
    //     should_swap: Self::Bit,
    //     first: impl IntoIterator<Item = S>,
    //     second: impl IntoIterator<Item = S>,
    // ) -> Vec<S>
    // where
    //     S: Variable<Self::C>,
    //     <S as Variable<Self::C>>::Expression: Add<Output = <S as Variable<Self::C>>::Expression>
    //         + Mul<Self::BitExpression, Output = <S as Variable<Self::C>>::Expression>,
    // {
    //     // let should_swap: <Self::Bit as Variable<Self::C>>::Expression = should_swap.into();
    //     // let one = <Self::Bit as Variable<Self::C>>::Expression::one();
    //     // let shouldnt_swap = one - should_swap.clone();

    //     // let id_branch = first
    //     //     .clone()
    //     //     .into_iter()
    //     //     .chain(second.clone())
    //     //     .map(<S as Variable<Self::C>>::Expression::from);
    //     // let swap_branch = second
    //     //     .into_iter()
    //     //     .chain(first)
    //     //     .map(<S as Variable<Self::C>>::Expression::from);
    //     // zip(
    //     //     zip(id_branch, swap_branch),
    //     //     zip(repeat(shouldnt_swap), repeat(should_swap)),
    //     // )
    //     // .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_v * id_c + sw_v * sw_c))
    //     // .collect()
    //     vec![]
    // }
}

impl BabyBearFriConfig for BabyBearPoseidon2 {
    type ValMmcs = sp1_core::utils::baby_bear_poseidon2::ValMmcs;
    type FriChallenger = <Self as StarkGenericConfig>::Challenger;

    fn fri_config(&self) -> &FriConfig<FriMmcs<Self>> {
        self.pcs().fri_config()
    }
}

impl BabyBearFriConfigVariable for BabyBearPoseidon2 {
    type C = InnerConfig;
    type Bit = Felt<<Self::C as Config>::F>;
    type BitExpression = <Self::Bit as Variable<Self::C>>::Expression;
    type FriChallengerVariable = DuplexChallengerVariable<Self::C>;

    fn poseidon2_hash(
        builder: &mut Builder<Self::C>,
        input: &[Felt<<Self::C as Config>::F>],
    ) -> [Felt<<Self::C as Config>::F>; DIGEST_SIZE] {
        builder.poseidon2_hash_v2(input)
    }

    fn poseidon2_compress(
        builder: &mut Builder<Self::C>,
        input: impl IntoIterator<Item = Felt<<Self::C as Config>::F>>,
    ) -> [Felt<<Self::C as Config>::F>; DIGEST_SIZE] {
        builder.poseidon2_compress_v2(input)
    }

    fn ext2felt(
        builder: &mut Builder<Self::C>,
        ext: Ext<<Self::C as Config>::F, <Self::C as Config>::EF>,
    ) -> [Felt<<Self::C as Config>::F>; D] {
        builder.ext2felt_v2(ext)
    }

    fn exp_reverse_bits(
        builder: &mut Builder<Self::C>,
        input: Felt<<Self::C as Config>::F>,
        power_bits: Vec<Felt<<Self::C as Config>::F>>,
    ) -> Felt<<Self::C as Config>::F> {
        builder.exp_reverse_bits_v2(input, power_bits)
    }

    fn num2bits(
        builder: &mut Builder<Self::C>,
        num: Felt<<Self::C as Config>::F>,
        num_bits: usize,
    ) -> Vec<Felt<<Self::C as Config>::F>> {
        builder.num2bits_v2_f(num, num_bits)
    }

    fn bits2num(
        builder: &mut Builder<Self::C>,
        bits: impl IntoIterator<Item = Felt<<Self::C as Config>::F>>,
    ) -> Felt<<Self::C as Config>::F> {
        builder.bits2num_v2_f(bits)
    }

    /// TODO Try to remove this and instead tighten the bounds on `Bit` in the trait.
    fn complement(builder: &mut Builder<Self::C>, bit: Self::Bit) -> Self::Bit {
        let one: Self::Bit = builder.constant(AbstractField::one());
        builder.eval(one - bit)
    }

    // fn select_chain<S>(
    //     builder: &mut Builder<Self::C>,
    //     should_swap: Self::Bit,
    //     first: impl IntoIterator<Item = S> + Clone,
    //     second: impl IntoIterator<Item = S> + Clone,
    // ) -> Vec<S>
    // where
    //     S: Variable<Self::C>,
    //     <S as Variable<Self::C>>::Expression: Add<Output = <S as Variable<Self::C>>::Expression>
    //         + Mul<
    //             <Self::Bit as Variable<Self::C>>::Expression,
    //             Output = <S as Variable<Self::C>>::Expression,
    //         >, // where
    //            //     S: Variable<Self::C>,
    //            //     <S as Variable<Self::C>>::Expression: Add<Output = <S as Variable<Self::C>>::Expression>
    //            //         + Mul<
    //            //             <Self::Bit as Variable<Self::C>>::Expression,
    //            //             Output = <S as Variable<Self::C>>::Expression,
    //            //         >,
    // {
    //     let should_swap: <Self::Bit as Variable<Self::C>>::Expression = should_swap.into();
    //     let one = <Self::Bit as Variable<Self::C>>::Expression::one();
    //     let shouldnt_swap = one - should_swap.clone();

    //     let id_branch = first
    //         .clone()
    //         .into_iter()
    //         .chain(second.clone())
    //         .map(<S as Variable<Self::C>>::Expression::from);
    //     let swap_branch = second
    //         .into_iter()
    //         .chain(first)
    //         .map(<S as Variable<Self::C>>::Expression::from);
    //     zip(
    //         zip(id_branch, swap_branch),
    //         zip(repeat(shouldnt_swap), repeat(should_swap)),
    //     )
    //     .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_v * id_c + sw_v * sw_c))
    //     .collect()
    // }

    // fn select_chain<S>(
    //     builder: &mut Builder<Self::C>,
    //     should_swap: Self::Bit,
    //     first: Vec<S>,
    //     second: Vec<S>,
    // ) -> Vec<S>
    // where
    //     S: Variable<Self::C> + AbstractField + Mul<Self::Bit, Output = S>,
    // {
    //     let shouldnt_swap = Self::complement(builder, should_swap);
    //     let id_branch = first.clone().into_iter().chain(second.clone());
    //     let swap_branch = second.into_iter().chain(first);
    //     zip(
    //         zip(id_branch, swap_branch),
    //         zip(repeat(shouldnt_swap), repeat(should_swap)),
    //     )
    //     .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_v * id_c + sw_v * sw_c))
    //     .collect()
    // }
}

impl BabyBearFriConfig for BabyBearPoseidon2Outer {
    type ValMmcs = OuterValMmcs;
    type FriChallenger = <Self as StarkGenericConfig>::Challenger;

    fn fri_config(&self) -> &FriConfig<FriMmcs<Self>> {
        self.pcs().fri_config()
    }
}

pub fn select_chain<C, R, S>(
    builder: &mut Builder<C>,
    should_swap: R,
    first: impl IntoIterator<Item = S> + Clone,
    second: impl IntoIterator<Item = S> + Clone,
) -> Vec<S>
where
    C: Config,
    R: Variable<C>,
    S: Variable<C>,
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
    .collect()
}
