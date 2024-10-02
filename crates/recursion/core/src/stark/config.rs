use p3_baby_bear::BabyBear;
use p3_bn254_fr::{Bn254Fr, DiffusionMatrixBN254};
use p3_challenger::MultiField32Challenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, AbstractField};
use p3_fri::{
    BatchOpening, CommitPhaseProofStep, FriConfig, FriProof, QueryProof, TwoAdicFriPcs,
    TwoAdicFriPcsProof,
};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{Hash, MultiField32PaddingFreeSponge, TruncatedPermutation};
use serde::{Deserialize, Serialize};
use sp1_stark::{Com, StarkGenericConfig, ZeroCommitment};

use super::{poseidon2::bn254_poseidon2_rc3, sp1_dev_mode};

pub const DIGEST_SIZE: usize = 1;

pub const OUTER_MULTI_FIELD_CHALLENGER_WIDTH: usize = 3;
pub const OUTER_MULTI_FIELD_CHALLENGER_RATE: usize = 2;
pub const OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE: usize = 1;

/// A configuration for outer recursion.
pub type OuterVal = BabyBear;
pub type OuterChallenge = BinomialExtensionField<OuterVal, 4>;
pub type OuterPerm = Poseidon2<Bn254Fr, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBN254, 3, 5>;
pub type OuterHash =
    MultiField32PaddingFreeSponge<OuterVal, Bn254Fr, OuterPerm, 3, 16, DIGEST_SIZE>;
pub type OuterDigestHash = Hash<OuterVal, Bn254Fr, DIGEST_SIZE>;
pub type OuterDigest = [Bn254Fr; DIGEST_SIZE];
pub type OuterCompress = TruncatedPermutation<OuterPerm, 2, 1, 3>;
pub type OuterValMmcs = FieldMerkleTreeMmcs<BabyBear, Bn254Fr, OuterHash, OuterCompress, 1>;
pub type OuterChallengeMmcs = ExtensionMmcs<OuterVal, OuterChallenge, OuterValMmcs>;
pub type OuterDft = Radix2DitParallel;
pub type OuterChallenger = MultiField32Challenger<
    OuterVal,
    Bn254Fr,
    OuterPerm,
    OUTER_MULTI_FIELD_CHALLENGER_WIDTH,
    OUTER_MULTI_FIELD_CHALLENGER_RATE,
>;
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
    let internal_round_constants =
        round_constants.drain(internal_start..internal_end).map(|vec| vec[0]).collect::<Vec<_>>();
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
    let num_queries = if sp1_dev_mode() {
        1
    } else {
        match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => 25,
        }
    };
    FriConfig { log_blowup: 4, num_queries, proof_of_work_bits: 16, mmcs: challenge_mmcs }
}

/// The FRI config for outer recursion.
pub fn outer_fri_config_with_blowup(log_blowup: usize) -> FriConfig<OuterChallengeMmcs> {
    let perm = outer_perm();
    let hash = OuterHash::new(perm.clone()).unwrap();
    let compress = OuterCompress::new(perm.clone());
    let challenge_mmcs = OuterChallengeMmcs::new(OuterValMmcs::new(hash, compress));
    let num_queries = if sp1_dev_mode() {
        1
    } else {
        match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => 100 / log_blowup,
        }
    };
    FriConfig { log_blowup, num_queries, proof_of_work_bits: 16, mmcs: challenge_mmcs }
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
    pub fn new_with_log_blowup(log_blowup: usize) -> Self {
        let perm = outer_perm();
        let hash = OuterHash::new(perm.clone()).unwrap();
        let compress = OuterCompress::new(perm.clone());
        let val_mmcs = OuterValMmcs::new(hash, compress);
        let dft = OuterDft {};
        let fri_config = outer_fri_config_with_blowup(log_blowup);
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

impl ZeroCommitment<BabyBearPoseidon2Outer> for OuterPcs {
    fn zero_commitment(&self) -> Com<BabyBearPoseidon2Outer> {
        OuterDigestHash::from([Bn254Fr::zero(); DIGEST_SIZE])
    }
}

/// The FRI config for testing recursion.
pub fn test_fri_config() -> FriConfig<OuterChallengeMmcs> {
    let perm = outer_perm();
    let hash = OuterHash::new(perm.clone()).unwrap();
    let compress = OuterCompress::new(perm.clone());
    let challenge_mmcs = OuterChallengeMmcs::new(OuterValMmcs::new(hash, compress));
    FriConfig { log_blowup: 1, num_queries: 1, proof_of_work_bits: 1, mmcs: challenge_mmcs }
}
