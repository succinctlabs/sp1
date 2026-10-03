//! # TEE Integrity Proofs.
//!
//! An "integrity proof" is a signature over the outputs of the execution of a program computed
//! in a trusted execution environment (TEE).
//!
//! This acts a "2-factor authentication" for the SP1 proving system.

use sp1_prover::{HashableKey, SP1VerifyingKey};

use crate::SP1VerificationError;

const RECOVERY_ID_OFFSET: usize = 4;
const SIGNATURE_OFFSET: usize = 5;
const SIGNATURE_END: usize = 69;

/// The API for the TEE server.
pub mod api;

/// The client for the TEE server.
pub mod client;

/// The SP1 TEE backend version to use.
///
/// Since this doesn't necessarily correspond to new versions of SP1,
/// we opt to keep track of it manually here.
pub const SP1_TEE_VERSION: u32 = 2;

/// This method will get the list of signers for the TEE server, trusting the server to honestly
/// report the list of signers.
///
/// This is a convenience method, if you want to actually verify attestions from the TEE server,
/// you need to build the enclave image yourself, and use the provided functionality from the
/// `sp1-tee` crate to verify the signers you care about.
///
/// Signers may be cross checked from the on-chain state with attestaions stored in s3.
///
/// See <https://github.com/succinctlabs/sp1-tee/blob/main/host/bin/validate_signers.rs>
///
/// # Errors
/// - [`client::ClientError::Http`] - If the request fails to send.
pub async fn get_tee_signers() -> Result<Vec<alloy_primitives::Address>, client::ClientError> {
    let client = client::Client::default();

    client.get_signers().await
}

/// Verify a TEE integrity proof.
///
/// This function will reconstruct the expected signature from the TEE executor, and recover the
/// signer. If the signer is in the list of provided signers, the proof is valid.
///
/// # Errors
/// - [`SP1VerificationError::Other`] - If the proof is invalid.
pub fn verify_tee_proof(
    signers: &[alloy_primitives::Address],
    tee_proof: &[u8],
    vkey: &SP1VerifyingKey,
    public_values: &[u8],
) -> Result<(), SP1VerificationError> {
    if signers.is_empty() {
        return Err(crate::SP1VerificationError::Other(anyhow::anyhow!(
            "TEE integrity proof verification is enabled, but no TEE signers are provided"
        )));
    }

    if tee_proof.len() < SIGNATURE_END {
        return Err(crate::SP1VerificationError::Other(anyhow::anyhow!(
            "Invalid TEE proof length: expected at least {SIGNATURE_END} bytes, got {}",
            tee_proof.len()
        )));
    }

    let mut bytes = Vec::new();

    // Push the version hash.
    let version_hash =
        alloy_primitives::keccak256(crate::network::tee::SP1_TEE_VERSION.to_le_bytes());
    bytes.extend_from_slice(version_hash.as_ref());

    // Push the vkey.
    bytes.extend_from_slice(&vkey.bytes32_raw());

    // Push the public values hash.
    let public_values_hash = alloy_primitives::keccak256(public_values);
    bytes.extend_from_slice(public_values_hash.as_ref());

    // Compute the message digest.
    let message_digest = alloy_primitives::keccak256(&bytes);

    // Parse the signature.
    let signature =
        k256::ecdsa::Signature::from_bytes(tee_proof[SIGNATURE_OFFSET..SIGNATURE_END].into())
            .map_err(|err| {
                crate::SP1VerificationError::Other(anyhow::anyhow!("Invalid TEE signature: {err}"))
            })?;
    // The recovery id is the last byte of the signature minus 27.
    let recovery_id = tee_proof[RECOVERY_ID_OFFSET]
        .checked_sub(27)
        .and_then(k256::ecdsa::RecoveryId::from_byte)
        .ok_or_else(|| {
            crate::SP1VerificationError::Other(anyhow::anyhow!("Invalid TEE recovery id"))
        })?;

    // Recover the signer.
    let signer = k256::ecdsa::VerifyingKey::recover_from_prehash(
        message_digest.as_ref(),
        &signature,
        recovery_id,
    )
    .map_err(|err| {
        crate::SP1VerificationError::Other(anyhow::anyhow!("Failed to recover TEE signer: {err}"))
    })?;
    let address = alloy_primitives::Address::from_public_key(&signer);

    // Verify the proof.
    if signers.contains(&address) {
        Ok(())
    } else {
        Err(crate::SP1VerificationError::Other(anyhow::anyhow!(
            "Invalid TEE proof, signed by unknown address {address}",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_hypercube::{septic_digest::SepticDigest, MachineVerifyingKey, UntrustedConfig};
    use sp1_primitives::SP1Field;

    fn dummy_vkey() -> SP1VerifyingKey {
        SP1VerifyingKey {
            vk: MachineVerifyingKey {
                pc_start: [SP1Field::default(); 3],
                initial_global_cumulative_sum: SepticDigest::zero(),
                preprocessed_commit: [SP1Field::default(); 8],
                untrusted_config: UntrustedConfig::zero(),
            },
        }
    }

    #[test]
    fn test_verify_tee_proof_rejects_short_proof() {
        let vkey = dummy_vkey();
        let signers = [alloy_primitives::Address::ZERO];
        let err = verify_tee_proof(&signers, &[0u8; SIGNATURE_END - 1], &vkey, &[]).unwrap_err();

        assert!(err.to_string().contains("Invalid TEE proof length"));
    }

    #[test]
    fn test_verify_tee_proof_rejects_invalid_recovery_id() {
        let vkey = dummy_vkey();
        let signers = [alloy_primitives::Address::ZERO];
        let err = verify_tee_proof(&signers, &[0u8; SIGNATURE_END], &vkey, &[]).unwrap_err();

        assert!(err.to_string().contains("Invalid TEE recovery id"));
    }
}
