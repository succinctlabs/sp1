use p3_baby_bear::{BabyBear, DiffusionMatrixBabybear};
use p3_bn254_fr::{Bn254Fr, DiffusionMatrixBN254};
use p3_challenger::{DuplexChallenger, MultiField32Challenger};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, Field};
use p3_fri::BatchOpening;
use p3_fri::CommitPhaseProofStep;
use p3_fri::QueryProof;
use p3_fri::{FriConfig, FriProof, TwoAdicFriPcs, TwoAdicFriPcsProof};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::Poseidon2;
use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
use p3_symmetric::Hash;
use p3_symmetric::{MultiField32PaddingFreeSponge, PaddingFreeSponge, TruncatedPermutation};
use serde::Deserialize;
use serde::Serialize;
use sp1_core::{stark::StarkGenericConfig, utils::poseidon2_instance::RC_16_30};

use crate::runtime::DIGEST_SIZE;

use super::poseidon2::bn254_poseidon2_rc3;

/// A configuration for outer recursion.
pub type OuterVal = BabyBear;
pub type OuterChallenge = BinomialExtensionField<OuterVal, 4>;
pub type OuterPerm = Poseidon2<Bn254Fr, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBN254, 3, 5>;
pub type OuterHash = MultiField32PaddingFreeSponge<OuterVal, Bn254Fr, OuterPerm, 3, 8, 1>;
pub type OuterDigestHash = Hash<Bn254Fr, Bn254Fr, 1>;
pub type OuterDigest = [Bn254Fr; 1];
pub type OuterCompress = TruncatedPermutation<OuterPerm, 2, 1, 3>;
pub type OuterValMmcs = FieldMerkleTreeMmcs<BabyBear, Bn254Fr, OuterHash, OuterCompress, 1>;
pub type OuterChallengeMmcs = ExtensionMmcs<OuterVal, OuterChallenge, OuterValMmcs>;
pub type OuterDft = Radix2DitParallel;
pub type OuterChallenger = MultiField32Challenger<OuterVal, Bn254Fr, OuterPerm, 3>;
pub type OuterPcs = TwoAdicFriPcs<OuterVal, OuterDft, OuterValMmcs, OuterChallengeMmcs>;

pub type OuterQueryProof = QueryProof<OuterChallenge, OuterChallengeMmcs>;
pub type OuterCommitPhaseStep = CommitPhaseProofStep<OuterChallenge, OuterChallengeMmcs>;
pub type OuterFriProof = FriProof<OuterChallenge, OuterChallengeMmcs, OuterVal>;
pub type OuterBatchOpening = BatchOpening<OuterVal, OuterValMmcs>;
pub type OuterPcsProof =
    TwoAdicFriPcsProof<OuterVal, OuterChallenge, OuterValMmcs, OuterChallengeMmcs>;

/// The permutation for outer recursion.
pub fn outer_perm() -> OuterPerm {
    const ROUNDS_F: usize = 8;
    const ROUNDS_P: usize = 56;
    let mut round_constants = bn254_poseidon2_rc3();
    let internal_start = ROUNDS_F / 2;
    let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
    let internal_round_constants = round_constants
        .drain(internal_start..internal_end)
        .map(|vec| vec[0])
        .collect::<Vec<_>>();
    let external_round_constants = round_constants;
    OuterPerm::new(
        ROUNDS_F,
        external_round_constants,
        Poseidon2ExternalMatrixGeneral,
        ROUNDS_P,
        internal_round_constants,
        DiffusionMatrixBN254,
    )
}

/// The FRI config for outer recursion.
pub fn outer_fri_config() -> FriConfig<OuterChallengeMmcs> {
    let perm = outer_perm();
    let hash = OuterHash::new(perm.clone()).unwrap();
    let compress = OuterCompress::new(perm.clone());
    let challenge_mmcs = OuterChallengeMmcs::new(OuterValMmcs::new(hash, compress));
    FriConfig {
        log_blowup: 3,
        num_queries: 1,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    }
}

/// A configuration for inner recursion.
pub type InnerVal = BabyBear;
pub type InnerChallenge = BinomialExtensionField<InnerVal, 4>;
pub type InnerPerm =
    Poseidon2<InnerVal, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabybear, 16, 7>;
pub type InnerHash = PaddingFreeSponge<InnerPerm, 16, 8, 8>;
pub type InnerDigestHash = Hash<InnerVal, InnerVal, DIGEST_SIZE>;
pub type InnerDigest = [InnerVal; DIGEST_SIZE];
pub type InnerCompress = TruncatedPermutation<InnerPerm, 2, 8, 16>;
pub type InnerValMmcs = FieldMerkleTreeMmcs<
    <InnerVal as Field>::Packing,
    <InnerVal as Field>::Packing,
    InnerHash,
    InnerCompress,
    8,
>;
pub type InnerChallengeMmcs = ExtensionMmcs<InnerVal, InnerChallenge, InnerValMmcs>;
pub type InnerChallenger = DuplexChallenger<InnerVal, InnerPerm, 16>;
pub type InnerDft = Radix2DitParallel;
pub type InnerPcs = TwoAdicFriPcs<InnerVal, InnerDft, InnerValMmcs, InnerChallengeMmcs>;
pub type InnerQueryProof = QueryProof<InnerChallenge, InnerChallengeMmcs>;
pub type InnerCommitPhaseStep = CommitPhaseProofStep<InnerChallenge, InnerChallengeMmcs>;
pub type InnerFriProof = FriProof<InnerChallenge, InnerChallengeMmcs, InnerVal>;
pub type InnerBatchOpening = BatchOpening<InnerVal, InnerValMmcs>;
pub type InnerPcsProof =
    TwoAdicFriPcsProof<InnerVal, InnerChallenge, InnerValMmcs, InnerChallengeMmcs>;

/// The permutation for inner recursion.
pub fn inner_perm() -> InnerPerm {
    const ROUNDS_F: usize = 8;
    const ROUNDS_P: usize = 22;
    let mut round_constants = RC_16_30.to_vec();
    let internal_start = ROUNDS_F / 2;
    let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
    let internal_round_constants = round_constants
        .drain(internal_start..internal_end)
        .map(|vec| vec[0])
        .collect::<Vec<_>>();
    let external_round_constants = round_constants;
    InnerPerm::new(
        ROUNDS_F,
        external_round_constants,
        Poseidon2ExternalMatrixGeneral,
        ROUNDS_P,
        internal_round_constants,
        DiffusionMatrixBabybear,
    )
}

/// The FRI config for inner recursion.
pub fn sp1_fri_config() -> FriConfig<InnerChallengeMmcs> {
    let perm = inner_perm();
    let hash = InnerHash::new(perm.clone());
    let compress = InnerCompress::new(perm.clone());
    let challenge_mmcs = InnerChallengeMmcs::new(InnerValMmcs::new(hash, compress));
    FriConfig {
        log_blowup: 1,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    }
}

/// The FRI config for inner recursion.
pub fn inner_fri_config() -> FriConfig<InnerChallengeMmcs> {
    let perm = inner_perm();
    let hash = InnerHash::new(perm.clone());
    let compress = InnerCompress::new(perm.clone());
    let challenge_mmcs = InnerChallengeMmcs::new(InnerValMmcs::new(hash, compress));
    FriConfig {
        log_blowup: 1,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    }
}

#[derive(Deserialize)]
#[serde(from = "std::marker::PhantomData<BabyBearPoseidon2Outer>")]
pub struct BabyBearPoseidon2Outer {
    pub perm: OuterPerm,
    pub pcs: OuterPcs,
}

impl Clone for BabyBearPoseidon2Outer {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Serialize for BabyBearPoseidon2Outer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        std::marker::PhantomData::<BabyBearPoseidon2Outer>.serialize(serializer)
    }
}

impl From<std::marker::PhantomData<BabyBearPoseidon2Outer>> for BabyBearPoseidon2Outer {
    fn from(_: std::marker::PhantomData<BabyBearPoseidon2Outer>) -> Self {
        Self::new()
    }
}

impl BabyBearPoseidon2Outer {
    pub fn new() -> Self {
        let perm = outer_perm();
        let hash = OuterHash::new(perm.clone()).unwrap();
        let compress = OuterCompress::new(perm.clone());
        let val_mmcs = OuterValMmcs::new(hash, compress);
        let dft = OuterDft {};
        let fri_config = outer_fri_config();
        let pcs = OuterPcs::new(27, dft, val_mmcs, fri_config);
        Self { pcs, perm }
    }
}

impl Default for BabyBearPoseidon2Outer {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkGenericConfig for BabyBearPoseidon2Outer {
    type Val = OuterVal;
    type Domain = <OuterPcs as p3_commit::Pcs<OuterChallenge, OuterChallenger>>::Domain;
    type Pcs = OuterPcs;
    type Challenge = OuterChallenge;
    type Challenger = OuterChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn challenger(&self) -> Self::Challenger {
        OuterChallenger::new(self.perm.clone()).unwrap()
    }
}

#[derive(Deserialize)]
#[serde(from = "std::marker::PhantomData<BabyBearPoseidon2Inner>")]
pub struct BabyBearPoseidon2Inner {
    pub perm: InnerPerm,
    pub pcs: InnerPcs,
}

impl Clone for BabyBearPoseidon2Inner {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Serialize for BabyBearPoseidon2Inner {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        std::marker::PhantomData::<BabyBearPoseidon2Inner>.serialize(serializer)
    }
}

impl From<std::marker::PhantomData<BabyBearPoseidon2Inner>> for BabyBearPoseidon2Inner {
    fn from(_: std::marker::PhantomData<BabyBearPoseidon2Inner>) -> Self {
        Self::new()
    }
}

impl BabyBearPoseidon2Inner {
    pub fn new() -> Self {
        let perm = inner_perm();
        let hash = InnerHash::new(perm.clone());
        let compress = InnerCompress::new(perm.clone());
        let val_mmcs = InnerValMmcs::new(hash, compress);
        let dft = InnerDft {};
        let fri_config = inner_fri_config();
        let pcs = InnerPcs::new(27, dft, val_mmcs, fri_config);
        Self { pcs, perm }
    }
}

impl Default for BabyBearPoseidon2Inner {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkGenericConfig for BabyBearPoseidon2Inner {
    type Val = InnerVal;
    type Domain = <InnerPcs as p3_commit::Pcs<InnerChallenge, InnerChallenger>>::Domain;
    type Pcs = InnerPcs;
    type Challenge = InnerChallenge;
    type Challenger = InnerChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn challenger(&self) -> Self::Challenger {
        InnerChallenger::new(self.perm.clone())
    }
}
