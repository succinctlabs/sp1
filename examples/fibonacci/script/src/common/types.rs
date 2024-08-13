use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_challenger::DuplexChallenger;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::Hash;
use sp1_core::{
    air::PublicValues, runtime::ExecutionRecord, stark::RiscvAir, utils::BabyBearPoseidon2,
};
use sp1_prover::{SP1DeferredMemoryLayout, SP1RecursionMemoryLayout, SP1ReduceMemoryLayout};
use sp1_recursion_core::stark::RecursionAir;
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

pub type RecursionLayout<'a> = SP1RecursionMemoryLayout<'a, BabyBearPoseidon2, RiscvAir<BabyBear>>;
pub type DeferredLayout<'a> =
    SP1DeferredMemoryLayout<'a, BabyBearPoseidon2, RecursionAir<BabyBear, 3>>;
pub type ReduceLayout<'a> = SP1ReduceMemoryLayout<'a, BabyBearPoseidon2, RecursionAir<BabyBear, 3>>;

pub enum LayoutType {
    Recursion,
    Deferred,
    Reduce,
}

impl LayoutType {
    pub fn from_usize(num: usize) -> Self {
        match num {
            0 => LayoutType::Recursion,
            1 => LayoutType::Deferred,
            2 => LayoutType::Reduce,
            _ => panic!("Invalid layout type"),
        }
    }

    pub fn to_usize(&self) -> usize {
        match self {
            LayoutType::Recursion => 0,
            LayoutType::Deferred => 1,
            LayoutType::Reduce => 2,
        }
    }
}
