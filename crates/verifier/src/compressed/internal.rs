//! Internal constants and types that determine the verifier configuration.

use alloc::vec::Vec;
use core::borrow::Borrow;

use slop_algebra::{AbstractField, PrimeField32};
use slop_symmetric::CryptographicHasher;
use sp1_hypercube::{
    verify_merkle_proof, HashableKey, InnerSC, MachineVerifier, MachineVerifierError,
    SP1RecursionProof, ShardVerifier, DIGEST_SIZE,
};
use sp1_primitives::{fri_params::recursion_fri_config, poseidon2_hasher, SP1Field};
use sp1_recursion_executor::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH};

use super::CompressedError;
use crate::{
    blake3_hash,
    compressed::{RECURSION_LOG_STACKING_HEIGHT, RECURSION_MAX_LOG_ROW_COUNT},
};

/// The finite field used for compress proofs.
type GC = sp1_primitives::SP1GlobalContext;
/// The stark configuration used for compress proofs.
type C = sp1_hypercube::SP1PcsProofInner;

/// Degree of Poseidon2 etc. in the compress machine.
pub const COMPRESS_DEGREE: usize = 3;

pub type CompressAir<SP1Field> = sp1_recursion_machine::RecursionAir<SP1Field, COMPRESS_DEGREE, 2>;

// // The rest of the functions in this file have been copied from elsewhere with slight
// modifications.

/// A verifier for SP1 "compressed" proofs.
pub struct SP1CompressedVerifier {
    verifier: MachineVerifier<GC, InnerSC<CompressAir<SP1Field>>>,
    vk_merkle_root: [SP1Field; DIGEST_SIZE],
}

impl Default for SP1CompressedVerifier {
    fn default() -> Self {
        let compress_log_stacking_height = RECURSION_LOG_STACKING_HEIGHT;
        let compress_max_log_row_count = RECURSION_MAX_LOG_ROW_COUNT;

        let machine = CompressAir::<SP1Field>::compress_machine();
        let recursion_shard_verifier = ShardVerifier::from_basefold_parameters(
            recursion_fri_config(),
            compress_log_stacking_height,
            compress_max_log_row_count,
            machine.clone(),
        );

        let verifier = MachineVerifier::new(recursion_shard_verifier);
        let vk_merkle_root = crate::VerifierRecursionVks::default().root();
        Self { verifier, vk_merkle_root }
    }
}

impl SP1CompressedVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute the digest of the public values.
    pub fn recursion_public_values_digest(
        &self,
        public_values: &RecursionPublicValues<SP1Field>,
    ) -> [SP1Field; 8] {
        let hasher = poseidon2_hasher();
        hasher.hash_slice(&public_values.as_array()[0..NUM_PV_ELMS_TO_HASH])
    }

    /// Assert that the digest of the public values is correct.
    pub fn is_recursion_public_values_valid(
        &self,
        public_values: &RecursionPublicValues<SP1Field>,
    ) -> bool {
        let expected_digest = self.recursion_public_values_digest(public_values);
        public_values.digest.iter().copied().eq(expected_digest)
    }

    /// Verify a compressed proof.
    pub fn verify_compressed(
        &self,
        proof: &SP1RecursionProof<GC, C>,
        vkey_hash: &[SP1Field; 8],
    ) -> Result<(), CompressedError> {
        let SP1RecursionProof { vk: compress_vk, proof, vk_merkle_proof } = proof;

        let mut challenger = self.verifier.challenger();
        compress_vk.observe_into(&mut challenger);

        // Verify the shard proof.
        self.verifier
            .verify_shard(compress_vk, proof, &mut challenger)
            .map_err(MachineVerifierError::InvalidShardProof)?;

        // Validate the public values.
        let public_values: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();

        // The `digest` is the correct hash of the recursion public values.
        if !self.is_recursion_public_values_valid(public_values) {
            return Err(MachineVerifierError::InvalidPublicValues(
                "recursion public values are invalid",
            )
            .into());
        }
        // TODO: add compress vkey verification when circuits are released.
        verify_merkle_proof(vk_merkle_proof, compress_vk.hash_koalabear(), self.vk_merkle_root)
            .map_err(CompressedError::InvalidVkey)?;

        // `is_complete` should be 1. This ensures that the proof is fully reduced.
        if public_values.is_complete != SP1Field::one() {
            return Err(MachineVerifierError::InvalidPublicValues("is_complete is not 1").into());
        }

        // Verify that the proof is for the sp1 vkey we are expecting.
        if public_values.sp1_vk_digest != *vkey_hash {
            return Err(MachineVerifierError::InvalidPublicValues("sp1 vk hash mismatch").into());
        }

        Ok(())
    }

    /// Verify a compressed proof.
    pub fn verify_compressed_with_public_values(
        &self,
        proof: &SP1RecursionProof<GC, C>,
        sp1_public_inputs: &[u8],
        vkey_hash: &[SP1Field; 8],
    ) -> Result<(), CompressedError> {
        // Verify the proof
        self.verify_compressed(proof, vkey_hash)?;

        // Verify the public values are corresponding to the digest of the public inputs in the
        // proof

        let SP1RecursionProof { proof, .. } = proof;

        // Validate the public values.
        let public_values: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();

        // Validate the SP1 public values against the committed digest.
        let committed_value_digest_bytes = public_values
            .committed_value_digest
            .iter()
            .flat_map(|w| w.iter().map(|x| x.as_canonical_u32() as u8))
            .collect::<Vec<_>>();

        // For compressed proofs, the committed digest uses the full hash (no bit masking).
        // hash_public_inputs zeroes the top 3 bits for Plonk/Groth16 field compatibility,
        // but that doesn't apply here.
        let sha256_digest = crate::sha256_hash(sp1_public_inputs);
        let blake3_digest = blake3_hash(sp1_public_inputs);
        if committed_value_digest_bytes.as_slice() != sha256_digest.as_slice()
            && committed_value_digest_bytes.as_slice() != blake3_digest.as_slice()
        {
            return Err(CompressedError::PublicValuesMismatch);
        }
        Ok(())
    }
}
