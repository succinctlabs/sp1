use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriConfig, TwoAdicFriPcs, TwoAdicFriPcsConfig};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, PseudoCompressionFunction,
    SerializingHasher32,
};
use serde::{Deserialize, Serialize};

use crate::stark::StarkGenericConfig;

use super::StarkUtils;

pub type Val = BabyBear;
pub type Challenge = BinomialExtensionField<Val, 4>;
type ByteHash = Blake3U32Zkvm;
type FieldHash = SerializingHasher32<ByteHash>;
type Compress = Blake3SingleBlockCompression;
pub type ValMmcs = FieldMerkleTreeMmcs<Val, u32, FieldHash, Compress, 8>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

pub type Dft = Radix2DitParallel;

type Challenger = SerializingChallenger32<Val, u32, HashChallenger<u32, ByteHash, 8>>;

type Pcs = RecursiveTwoAdicFriPCS;

// Fri parameters
const LOG_BLOWUP: usize = 1;
const NUM_QUERIES: usize = 100;
const PROOF_OF_WORK_BITS: usize = 16;

#[derive(Deserialize)]
#[serde(from = "std::marker::PhantomData<BabyBearBlake3Recursion>")]
#[allow(dead_code)]
pub struct BabyBearBlake3Recursion {
    pcs: Pcs,
}

// Implement serialization manually instead of using serde(into) to avoid cloing the config
impl Serialize for BabyBearBlake3Recursion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        std::marker::PhantomData::<Self>.serialize(serializer)
    }
}

impl From<std::marker::PhantomData<BabyBearBlake3Recursion>> for BabyBearBlake3Recursion {
    fn from(_: std::marker::PhantomData<BabyBearBlake3Recursion>) -> Self {
        Self::new()
    }
}

impl Clone for BabyBearBlake3Recursion {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl BabyBearBlake3Recursion {
    pub const fn new() -> Self {
        // Create the recursive verifier PCS instance
        let byte_hash = ByteHash {};
        let field_hash: SerializingHasher32<Blake3U32Zkvm> = FieldHash::new(byte_hash);

        let compress = Compress::new();

        let val_mmcs = ValMmcs::new(field_hash, compress);

        let challenge_mmcs = ChallengeMmcs::new(val_mmcs_clone);

        let fri_config = FriConfig {
            log_blowup: LOG_BLOWUP,
            num_queries: NUM_QUERIES,
            proof_of_work_bits: PROOF_OF_WORK_BITS,
            mmcs: challenge_mmcs,
        };
        let pcs = Pcs::new(fri_config, dft, val_mmcs);

        Self { pcs }
    }
}

impl StarkUtils for BabyBearBlake3 {
    type UniConfig = Self;

    fn challenger(&self) -> Self::Challenger {
        cfg_if::cfg_if! {
            if #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))] {
                RecursiveVerifierChallenger::from_hasher(vec![], RecursiveVerifierByteHash {})
            } else {
                Challenger::from_hasher(vec![], ByteHash {})
            }
        }
    }

    fn uni_stark_config(&self) -> &Self::UniConfig {
        self
    }
}

impl StarkGenericConfig for BabyBearBlake3 {
    type Val = Val;
    type Challenge = Challenge;

    cfg_if::cfg_if! {
        if #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))] {
            type Pcs = RecursiveVerifierPcs;
            type Challenger = RecursiveVerifierChallenger;
        } else {
            type Pcs = Pcs;
            type Challenger = Challenger;
        }
    }

    fn pcs(&self) -> &Self::Pcs {
        cfg_if::cfg_if! {
            if #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))] {
                &self.recursive_verifier_pcs
            } else {
                &self.pcs
            }
        }
    }
}

impl p3_uni_stark::StarkGenericConfig for BabyBearBlake3 {
    type Val = Val;
    type Challenge = Challenge;

    cfg_if::cfg_if! {
        if #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))] {
            type Pcs = RecursiveVerifierPcs;
            type Challenger = RecursiveVerifierChallenger;
        } else {
            type Pcs = Pcs;
            type Challenger = Challenger;
        }
    }

    fn pcs(&self) -> &Self::Pcs {
        cfg_if::cfg_if! {
            if #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))] {
                &self.recursive_verifier_pcs
            } else {
                &self.pcs
            }
        }
    }
}
