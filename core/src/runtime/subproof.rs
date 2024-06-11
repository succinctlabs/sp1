use std::sync::atomic::AtomicBool;

use crate::{
    stark::{MachineVerificationError, ShardProof, StarkVerifyingKey},
    utils::BabyBearPoseidon2,
};

/// Function to verify proofs during runtime when the verify_sp1_proof precompile is used. This
/// is only done as a sanity check to ensure that users are passing in valid proofs. The actual
/// constraints are verified in the recursion layer.
///
/// This function is passed into the runtime because its actual implementation relies on crates
/// in recursion that depend on sp1-core.
pub trait SubproofVerifier: Send {
    fn verify_deferred_proof(
        &self,
        proof: &ShardProof<BabyBearPoseidon2>,
        vk: &StarkVerifyingKey<BabyBearPoseidon2>,
        vk_hash: [u32; 8],
        committed_value_digest: [u32; 8],
    ) -> Result<(), MachineVerificationError<BabyBearPoseidon2>>;
}

#[derive(Default)]
pub struct DefaultSubproofVerifier {
    printed: AtomicBool,
}

pub struct NoOpSubproofVerifier;

impl SubproofVerifier for NoOpSubproofVerifier {
    fn verify_deferred_proof(
        &self,
        _proof: &ShardProof<BabyBearPoseidon2>,
        _vk: &StarkVerifyingKey<BabyBearPoseidon2>,
        _vk_hash: [u32; 8],
        _committed_value_digest: [u32; 8],
    ) -> Result<(), MachineVerificationError<BabyBearPoseidon2>> {
        Ok(())
    }
}

impl DefaultSubproofVerifier {
    pub fn new() -> Self {
        Self {
            printed: AtomicBool::new(false),
        }
    }
}

impl SubproofVerifier for DefaultSubproofVerifier {
    fn verify_deferred_proof(
        &self,
        _proof: &ShardProof<BabyBearPoseidon2>,
        _vk: &StarkVerifyingKey<BabyBearPoseidon2>,
        _vk_hash: [u32; 8],
        _committed_value_digest: [u32; 8],
    ) -> Result<(), MachineVerificationError<BabyBearPoseidon2>> {
        if !self.printed.load(std::sync::atomic::Ordering::SeqCst) {
            tracing::info!("Not verifying sub proof during runtime");
            self.printed
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }
}
