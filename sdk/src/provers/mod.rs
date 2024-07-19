mod local;
mod mock;

use anyhow::Result;
pub use local::LocalProver;
pub use mock::MockProver;
use sp1_core::runtime::SP1Context;
use sp1_core::stark::MachineVerificationError;
use sp1_core::utils::SP1ProverOpts;
use sp1_core::SP1_CIRCUIT_VERSION;
use sp1_prover::components::SP1ProverComponents;
use sp1_prover::CoreSC;
use sp1_prover::InnerSC;
use sp1_prover::SP1CoreProofData;
use sp1_prover::SP1Prover;
use sp1_prover::SP1ReduceProof;
use sp1_prover::{SP1ProvingKey, SP1Stdin, SP1VerifyingKey};
use strum_macros::EnumString;
use thiserror::Error;

use crate::install::try_install_plonk_bn254_artifacts;
use crate::SP1Proof;
use crate::SP1ProofKind;
use crate::SP1ProofWithPublicValues;

/// The type of prover.
#[derive(Debug, PartialEq, EnumString)]
pub enum ProverType {
    Local,
    Mock,
    Network,
}

#[derive(Error, Debug)]
pub enum SP1VerificationError {
    #[error("Version mismatch")]
    VersionMismatch(String),
    #[error("Core machine verification error: {0}")]
    Core(MachineVerificationError<CoreSC>),
    #[error("Recursion verification error: {0}")]
    Recursion(MachineVerificationError<InnerSC>),
    #[error("Plonk verification error: {0}")]
    Plonk(anyhow::Error),
}

/// An implementation of [crate::ProverClient].
pub trait Prover<C: SP1ProverComponents>: Send + Sync {
    fn id(&self) -> ProverType;

    fn sp1_prover(&self) -> &SP1Prover<C>;

    fn version(&self) -> &str {
        SP1_CIRCUIT_VERSION
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey);

    /// Prove the execution of a RISCV ELF with the given inputs, according to the given proof mode.
    fn prove<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        opts: SP1ProverOpts,
        context: SP1Context<'a>,
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues>;

    /// Verify that an SP1 proof is valid given its vkey and metadata.
    /// For Plonk proofs, verifies that the public inputs of the PlonkBn254 proof match
    /// the hash of the VK and the committed public values of the SP1ProofWithPublicValues.
    fn verify(
        &self,
        bundle: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        if bundle.sp1_version != self.version() {
            return Err(SP1VerificationError::VersionMismatch(
                bundle.sp1_version.clone(),
            ));
        }
        match bundle.proof.clone() {
            SP1Proof::Core(proof) => self
                .sp1_prover()
                .verify(&SP1CoreProofData(proof), vkey)
                .map_err(SP1VerificationError::Core),
            SP1Proof::Compressed(proof) => self
                .sp1_prover()
                .verify_compressed(&SP1ReduceProof { proof }, vkey)
                .map_err(SP1VerificationError::Recursion),
            SP1Proof::Plonk(proof) => self
                .sp1_prover()
                .verify_plonk_bn254(
                    &proof,
                    vkey,
                    &bundle.public_values,
                    &if sp1_prover::build::sp1_dev_mode() {
                        sp1_prover::build::plonk_bn254_artifacts_dev_dir()
                    } else {
                        try_install_plonk_bn254_artifacts()
                    },
                )
                .map_err(SP1VerificationError::Plonk),
        }
    }
}
