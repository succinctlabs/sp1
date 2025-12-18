use p3_baby_bear::BabyBear;
use p3_bls12_377_fr::{Bls12377Fr, DiffusionMatrixBls12377};
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

use super::{poseidon2::bls12377_poseidon2_rc3, sp1_dev_mode};

pub const DIGEST_SIZE: usize = 1;

pub const OUTER_MULTI_FIELD_CHALLENGER_WIDTH: usize = 3;
pub const OUTER_MULTI_FIELD_CHALLENGER_RATE: usize = 2;
pub const OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE: usize = 1;

/// A configuration for outer recursion.
pub type OuterVal = BabyBear;
pub type OuterChallenge = BinomialExtensionField<OuterVal, 4>;
pub type OuterPerm =
    Poseidon2<Bls12377Fr, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBls12377, 3, 11>;
pub type OuterHash =
    MultiField32PaddingFreeSponge<OuterVal, Bls12377Fr, OuterPerm, 3, 16, DIGEST_SIZE>;
pub type OuterDigestHash = Hash<OuterVal, Bls12377Fr, DIGEST_SIZE>;
pub type OuterDigest = [Bls12377Fr; DIGEST_SIZE];
pub type OuterCompress = TruncatedPermutation<OuterPerm, 2, 1, 3>;
pub type OuterValMmcs =
    FieldMerkleTreeMmcs<BabyBear, Bls12377Fr, OuterHash, OuterCompress, 1>;
pub type OuterChallengeMmcs = ExtensionMmcs<OuterVal, OuterChallenge, OuterValMmcs>;
pub type OuterDft = Radix2DitParallel;
pub type OuterChallenger = MultiField32Challenger<
    OuterVal,
    Bls12377Fr,
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
    let mut round_constants = bls12377_poseidon2_rc3().clone();
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
        DiffusionMatrixBls12377,
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

#[cfg(test)]
mod bls12377_poseidon2_kat_tests {
    use super::*;
    use ff::PrimeField;
    use p3_symmetric::Permutation;

    fn fr_from_hex_be(hex: &str) -> Bls12377Fr {
        // hex is "0x..." big-endian, 32 bytes.
        let h = hex.strip_prefix("0x").expect("0x-prefixed hex");
        assert_eq!(h.len(), 64, "expected 32-byte hex");
        let mut be = [0u8; 32];
        for i in 0..32 {
            let byte = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).expect("hex byte");
            be[i] = byte;
        }
        let mut le = be;
        le.reverse();

        let mut repr = <p3_bls12_377_fr::FFBls12377Fr as ff::PrimeField>::Repr::default();
        for (i, digit) in repr.0.as_mut().iter_mut().enumerate() {
            *digit = le[i];
        }
        let value = p3_bls12_377_fr::FFBls12377Fr::from_repr(repr);
        if value.is_some().into() {
            Bls12377Fr { value: value.unwrap() }
        } else {
            panic!("Invalid field element")
        }
    }

    #[test]
    fn test_outer_perm_kat_zero_state() {
        // KAT computed from the generated rc3Vals for BLS12-377 (t=3, alpha=11, RF=8, RP=56),
        // matching gnark's `poseidon2` implementation in this repo.
        let mut state = [Bls12377Fr::zero(), Bls12377Fr::zero(), Bls12377Fr::zero()];
        outer_perm().permute_mut(&mut state);

        let expected = [
            fr_from_hex_be("0x073A16E09D72EB3CE2BE32D26298E581FE6D6F5C50DF62B35C7ED36BED69B06A"),
            fr_from_hex_be("0x0646CF2FA3846E5B849972B65A44D33CBC30112153515071103EB6D8B162A187"),
            fr_from_hex_be("0x11781011359B52E0D8AE583C071D5F487A1B06D5F64E755A7BD893C27A827C25"),
        ];

        assert_eq!(state, expected);
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
        OuterDigestHash::from([Bls12377Fr::zero(); DIGEST_SIZE])
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
