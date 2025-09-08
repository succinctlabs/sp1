use p3_baby_bear::BabyBear;
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, *};

/// Errors that can occur during machine verification.
pub enum MachineVerificationError<SC: StarkGenericConfig> {
    /// An error occurred during the verification of a shard proof.
    InvalidShardProof(VerificationError<SC>),
    /// An error occurred during the verification of a global proof.
    InvalidGlobalProof(VerificationError<SC>),
    // /// The cumulative sum is non-zero.
    // NonZeroCumulativeSum(InteractionScope, usize),
    /// The public values digest is invalid.
    InvalidPublicValuesDigest,
    /// The debug interactions failed.
    DebugInteractionsFailed,
    /// The proof is empty.
    EmptyProof,
    /// The public values are invalid.
    InvalidPublicValues(&'static str),
    /// The number of shards is too large.
    TooManyShards,
    /// The chip occurrence is invalid.
    InvalidChipOccurrence(String),
    /// The CPU is missing in the first shard.
    MissingCpuInFirstShard,
    /// The CPU log degree is too large.
    CpuLogDegreeTooLarge(usize),
    /// The verification key is not allowed.
    InvalidVerificationKey,
}

/// The configuration for the core prover.
pub type CoreSC = BabyBearPoseidon2;

/// TODO(tqn) determine if we want to keep some state/cached data between calls.
/// Verify a compressed proof.
pub fn verify_compressed(
    proof: &SP1ReduceProof<BabyBearPoseidon2>,
    vkey_hash: &[BabyBear; 8],
) -> Result<(), MachineVerificationError<CoreSC>> {
    let SP1ReduceProof { vk: compress_vk, proof } = proof;
    // let mut challenger = self.compress_prover.config().challenger();
    // let machine_proof = MachineProof { shard_proofs: vec![proof.clone()] };
    // self.compress_prover.machine().verify(compress_vk, &machine_proof, &mut challenger)?;

    // // Validate public values
    // let public_values: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();

    // if !is_recursion_public_values_valid(self.compress_prover.machine().config(), public_values) {
    //     return Err(MachineVerificationError::InvalidPublicValues(
    //         "recursion public values are invalid",
    //     ));
    // }

    // if public_values.vk_root != self.recursion_vk_root {
    //     return Err(MachineVerificationError::InvalidPublicValues("vk_root mismatch"));
    // }

    // if self.vk_verification && !self.recursion_vk_map.contains_key(&compress_vk.hash_babybear()) {
    //     return Err(MachineVerificationError::InvalidVerificationKey);
    // }

    // // `is_complete` should be 1. In the reduce program, this ensures that the proof is fully
    // // reduced.
    // if public_values.is_complete != BabyBear::one() {
    //     return Err(MachineVerificationError::InvalidPublicValues("is_complete is not 1"));
    // }

    // // Verify that the proof is for the sp1 vkey we are expecting.
    // let vkey_hash = vk.hash_babybear();
    // if public_values.sp1_vk_digest != vkey_hash {
    //     return Err(MachineVerificationError::InvalidPublicValues("sp1 vk hash mismatch"));
    // }

    Ok(())
}

pub fn square(x: u32) -> u32 {
    use p3_baby_bear::BabyBear;
    use p3_field::{AbstractField, PrimeField32};

    BabyBear::from_wrapped_u32(x).square().as_canonical_u32()
}
