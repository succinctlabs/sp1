use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_challenger::DuplexChallenger;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::Hash;
use sp1_core::{air::PublicValues, runtime::ExecutionRecord};
use std::fs::File;

pub type PublicValueStreamType = Vec<u8>;
pub type PublicValuesType = PublicValues<u32, u32>;
pub type CheckpointType = File;

pub type ChallengerType = DuplexChallenger<
    BabyBear,
    Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
    16,
    8,
>;

pub type CommitmentType = Hash<BabyBear, BabyBear, 8>;
pub type RecordType = ExecutionRecord;
