//! Types and methods for subproof verification inside the [`crate::Executor`].

use sp1_stark::{
    baby_bear_poseidon2::BabyBearPoseidon2, MachineVerificationError, StarkVerifyingKey,
};
use std::sync::atomic::AtomicBool;

use crate::SP1ReduceProof;

/// Verifier used in runtime when `sp1_zkvm::precompiles::verify::verify_sp1_proof` is called. This
/// is then used to sanity check that the user passed in the correct proof; the actual constraints
/// happen in the recursion layer.
///
/// This needs to be passed in rather than written directly since the actual implementation relies
/// on crates in recursion that depend on sp1-core.
pub trait SubproofVerifier: Sync + Send {
    /// Verify a deferred proof.
    fn verify_deferred_proof(
        &self,
        proof: &SP1ReduceProof<BabyBearPoseidon2>,
        vk: &StarkVerifyingKey<BabyBearPoseidon2>,
        vk_hash: [u32; 8],
        committed_value_digest: [u32; 8],
    ) -> Result<(), MachineVerificationError<BabyBearPoseidon2>>;
}

/// A dummy verifier which prints a warning on the first proof and does nothing else.
#[derive(Default)]
pub struct DefaultSubproofVerifier {
    printed: AtomicBool,
}

impl DefaultSubproofVerifier {
    /// Creates a new [`DefaultSubproofVerifier`].
    #[must_use]
    pub fn new() -> Self {
        Self { printed: AtomicBool::new(false) }
    }
}

impl SubproofVerifier for DefaultSubproofVerifier {
    fn verify_deferred_proof(
        &self,
        _proof: &SP1ReduceProof<BabyBearPoseidon2>,
        _vk: &StarkVerifyingKey<BabyBearPoseidon2>,
        _vk_hash: [u32; 8],
        _committed_value_digest: [u32; 8],
    ) -> Result<(), MachineVerificationError<BabyBearPoseidon2>> {
        if !self.printed.load(std::sync::atomic::Ordering::SeqCst) {
            tracing::info!("Not verifying sub proof during runtime");
            self.printed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }
}

/// A dummy verifier which does nothing.
pub struct NoOpSubproofVerifier;

impl SubproofVerifier for NoOpSubproofVerifier {
    fn verify_deferred_proof(
        &self,
        _proof: &SP1ReduceProof<BabyBearPoseidon2>,
        _vk: &StarkVerifyingKey<BabyBearPoseidon2>,
        _vk_hash: [u32; 8],
        _committed_value_digest: [u32; 8],
    ) -> Result<(), MachineVerificationError<BabyBearPoseidon2>> {
        Ok(())
    }
}
