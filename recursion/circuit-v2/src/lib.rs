//! Copied from [`sp1_recursion_program`].

use challenger::{CanObserveVariable, DuplexChallengerVariable, FeltChallenger};
use p3_commit::TwoAdicMultiplicativeCoset;
use sp1_recursion_compiler::{
    config::InnerConfig,
    ir::{Config, Ext, Felt},
};
use sp1_recursion_core_v2::DIGEST_SIZE;

pub mod build_wrap_v2;
pub mod challenger;
pub mod domain;
pub mod fri;
pub mod stark;
pub mod utils;
pub mod witness;

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
pub struct FriChallenges<C: Config> {
    pub query_indices: Vec<Vec<Felt<C::F>>>,
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
    pub mats: Vec<TwoAdicPcsMatsVariable<C>>,
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
use p3_matrix::dense::RowMajorMatrix;
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

// TODO write subtrait that enables use of the Variable variants
// consider merging this into the above trait
pub trait BabyBearFriConfigVariable: BabyBearFriConfig {
    // Is this is the best place to put this?
    type C: Config<F = Self::Val, EF = Self::Challenge>;
    type FriChallengerVariable: FeltChallenger<Self::C>;
}

impl BabyBearFriConfig for BabyBearPoseidon2 {
    type ValMmcs = sp1_core::utils::baby_bear_poseidon2::ValMmcs;
    // type RowMajorProverData = PcsProverData<Self>;
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
    // type RowMajorProverData = PcsProverData<Self>;
    type FriChallenger = <Self as StarkGenericConfig>::Challenger;

    fn fri_config(&self) -> &FriConfig<FriMmcs<Self>> {
        self.pcs().fri_config()
    }
}
