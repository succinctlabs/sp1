use alloc::{boxed::Box, vec};
use core::borrow::Borrow;

use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use p3_symmetric::CryptographicHasher;
use sp1_recursion_core::{
    air::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH},
    machine::RecursionAir,
};
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, *};

/// The configuration for the core prover.
type F = BabyBear;
type SC = BabyBearPoseidon2;

const COMPRESS_DEGREE: usize = 3;

// TODO(tqn) static/const assertions for all these constants?

const RECURSION_VK_ROOT_U32: [u32; 8] =
    [779620665, 657361014, 1275916220, 1016544356, 761269804, 102002516, 650304731, 1117171342];

/// TODO(tqn) determine if we want to keep some state/cached data between calls.
/// Verify a compressed proof.
pub fn verify_compressed(
    proof: &SP1ReduceProof<SC>,
    vkey_hash: &[BabyBear; 8],
) -> Result<(), MachineVerificationError<SC>> {
    let SP1ReduceProof { vk: compress_vk, proof } = proof;

    let compress_machine: StarkMachine<SC, _> =
        RecursionAir::<F, COMPRESS_DEGREE>::compress_machine(SC::default());

    let mut challenger = compress_machine.config().challenger();
    let machine_proof = MachineProof { shard_proofs: vec![proof.clone()] };
    compress_machine.verify(compress_vk, &machine_proof, &mut challenger)?;

    // Validate public values
    let public_values: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();

    if !is_recursion_public_values_valid(compress_machine.config(), public_values) {
        return Err(MachineVerificationError::InvalidPublicValues(
            "recursion public values are invalid",
        ));
    }

    if public_values.vk_root != RECURSION_VK_ROOT_U32.map(BabyBear::from_canonical_u32) {
        return Err(MachineVerificationError::InvalidPublicValues("vk_root mismatch"));
    }

    // if self.vk_verification && !self.recursion_vk_map.contains_key(&compress_vk.hash_babybear()) {
    //     return Err(MachineVerificationError::InvalidVerificationKey);
    // }

    // `is_complete` should be 1. In the reduce program, this ensures that the proof is fully
    // reduced.
    if public_values.is_complete != BabyBear::one() {
        return Err(MachineVerificationError::InvalidPublicValues("is_complete is not 1"));
    }

    // Verify that the proof is for the sp1 vkey we are expecting.
    // let vkey_hash = vk.hash_babybear();
    if public_values.sp1_vk_digest != *vkey_hash {
        return Err(MachineVerificationError::InvalidPublicValues("sp1 vk hash mismatch"));
    }

    Ok(())
}

/// Compute the digest of the public values.
fn recursion_public_values_digest(
    config: &SC,
    public_values: &RecursionPublicValues<BabyBear>,
) -> [BabyBear; 8] {
    let hash = InnerHash::new(config.perm.clone());
    let pv_array = public_values.as_array();
    hash.hash_slice(&pv_array[0..NUM_PV_ELMS_TO_HASH])
}

/// Check if the digest of the public values is correct.
fn is_recursion_public_values_valid(
    config: &SC,
    public_values: &RecursionPublicValues<BabyBear>,
) -> bool {
    let expected_digest = recursion_public_values_digest(config, public_values);
    public_values.digest.iter().copied().eq(expected_digest)
}

/// A verifier for Groth16 zero-knowledge proofs.
#[derive(Debug)]
pub struct CompressedVerifier;
impl CompressedVerifier {
    pub fn verify(
        proof: &[u8],
        sp1_public_inputs: &[u8],
        sp1_vkey_hash: &[u8],
    ) -> Result<(), CompressedError> {
        let reduce_proof: SP1ReduceProof<SC> =
            bincode::deserialize(proof).map_err(CompressedError::Deserialization)?;

        let vkey_hash: [F; 8] =
            bincode::deserialize(sp1_vkey_hash).map_err(CompressedError::Deserialization)?;

        verify_compressed(&reduce_proof, &vkey_hash).map_err(CompressedError::Verification)?;

        Ok(())
    }
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CompressedError {
    // TODO(tqn) better errosr
    // #[error("Proof verification failed")]
    // ProofVerificationFailed,
    // #[error("Process verifying key failed")]
    // ProcessVerifyingKeyFailed,
    // #[error("Prepare inputs failed")]
    // PrepareInputsFailed,
    #[error("General error")]
    GeneralError(#[from] crate::error::Error),
    #[error("Deserialization error")]
    Deserialization(#[from] Box<bincode::ErrorKind>),
    #[error("Verification error")]
    Verification(#[from] MachineVerificationError<SC>),
}

pub fn square(x: u32) -> u32 {
    use p3_baby_bear::BabyBear;
    use p3_field::{AbstractField, PrimeField32};

    BabyBear::from_wrapped_u32(x).square().as_canonical_u32()
}
