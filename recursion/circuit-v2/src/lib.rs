//! Copied from [`sp1_recursion_program`].

use challenger::{CanObserveVariable, DuplexChallengerVariable, FeltChallenger};
use sp1_recursion_compiler::{
    config::InnerConfig,
    ir::{Config, Ext},
};

mod types;

pub mod build_wrap_v2;
pub mod challenger;
pub mod constraints;
pub mod domain;
pub mod fri;
pub mod stark;
pub mod witness;

pub use types::*;

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
    type FriChallengerVariable: FeltChallenger<Self::C>;
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

    type FriChallengerVariable = DuplexChallengerVariable<Self::C>;
}

impl BabyBearFriConfig for BabyBearPoseidon2Outer {
    type ValMmcs = OuterValMmcs;
    type FriChallenger = <Self as StarkGenericConfig>::Challenger;

    fn fri_config(&self) -> &FriConfig<FriMmcs<Self>> {
        self.pcs().fri_config()
    }
}
