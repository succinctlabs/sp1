use p3_baby_bear::BabyBear;
use p3_bn254_fr::{Bn254Fr, DiffusionMatrixBN254};
use p3_challenger::MultiFieldChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::Poseidon2;
use p3_symmetric::{PaddingFreeSpongeMultiField, TruncatedPermutation};

pub type Val = BabyBear;
pub type Challenge = BinomialExtensionField<Val, 4>;
pub type Perm = Poseidon2<Bn254Fr, DiffusionMatrixBN254, 3, 5>;
pub type MyHash = PaddingFreeSpongeMultiField<Val, Bn254Fr, Perm, 3, 8, 1>;
pub type MyCompress = TruncatedPermutation<Perm, 2, 1, 3>;
pub type ValMmcs = FieldMerkleTreeMmcs<BabyBear, Bn254Fr, MyHash, MyCompress, 1>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Dft = Radix2DitParallel;
pub type Challenger = MultiFieldChallenger<Val, Bn254Fr, Perm, 3>;
