use p3_baby_bear::{BabyBear, DiffusionMatrixBabybear};
use p3_bn254_fr::{Bn254Fr, DiffusionMatrixBN254};
use p3_challenger::{DuplexChallenger, MultiFieldChallenger};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, Field};
use p3_fri::{FriConfig, FriProof, TwoAdicFriPcs, TwoAdicFriPcsProof};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::Poseidon2;
use p3_symmetric::{PaddingFreeSponge, PaddingFreeSpongeMultiField, TruncatedPermutation};
use sp1_core::utils::poseidon2_instance::RC_16_30;

use super::poseidon2::bn254_poseidon2_rc3;

/// A configuration for outter recursion.
pub type OuterVal = BabyBear;
pub type OuterChallenge = BinomialExtensionField<OuterVal, 4>;
pub type OuterPerm = Poseidon2<Bn254Fr, DiffusionMatrixBN254, 3, 5>;
pub type OuterHash = PaddingFreeSpongeMultiField<OuterVal, Bn254Fr, OuterPerm, 3, 8, 1>;
pub type OuterCompress = TruncatedPermutation<OuterPerm, 2, 1, 3>;
pub type OuterValMmcs = FieldMerkleTreeMmcs<BabyBear, Bn254Fr, OuterHash, OuterCompress, 1>;
pub type OuterChallengeMmcs = ExtensionMmcs<OuterVal, OuterChallenge, OuterValMmcs>;
pub type OuterDft = Radix2DitParallel;
pub type OuterChallenger = MultiFieldChallenger<OuterVal, Bn254Fr, OuterPerm, 3>;
pub type OuterPcs = TwoAdicFriPcs<OuterVal, OuterDft, OuterValMmcs, OuterChallengeMmcs>;
pub type OuterFriProof = FriProof<OuterChallenge, OuterChallengeMmcs, OuterVal>;
pub type OuterPcsProof = TwoAdicFriPcsProof<OuterVal, OuterDft, OuterValMmcs, OuterChallengeMmcs>;

/// The permutation for outter recursion.
pub fn outer_perm() -> OuterPerm {
    OuterPerm::new(8, 56, bn254_poseidon2_rc3(), DiffusionMatrixBN254)
}

/// The FRI config for outter recursion.
pub fn outer_fri_config() -> FriConfig<OuterChallengeMmcs> {
    let perm = outer_perm();
    let hash = OuterHash::new(perm.clone()).unwrap();
    let compress = OuterCompress::new(perm.clone());
    let challenge_mmcs = OuterChallengeMmcs::new(OuterValMmcs::new(hash, compress));
    FriConfig {
        log_blowup: 1,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    }
}

/// A configuration for inner recursion.
pub type InnerVal = BabyBear;
pub type InnerChallenge = BinomialExtensionField<InnerVal, 4>;
pub type InnerPerm = Poseidon2<InnerVal, DiffusionMatrixBabybear, 16, 7>;
pub type InnerHash = PaddingFreeSponge<InnerPerm, 16, 8, 8>;
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
pub type InnerFriProof = FriProof<InnerChallenge, InnerChallengeMmcs, InnerVal>;
pub type InnerPcsProof = TwoAdicFriPcsProof<InnerVal, InnerDft, InnerValMmcs, InnerChallengeMmcs>;

/// The permutation for inner recursion.
pub fn inner_perm() -> InnerPerm {
    InnerPerm::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear)
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
