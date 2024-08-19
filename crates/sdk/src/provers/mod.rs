mod cpu;
#[cfg(feature = "cuda")]
mod cuda;
mod mock;

pub use cpu::CpuProver;
#[cfg(feature = "cuda")]
pub use cuda::CudaProver;
pub use mock::MockProver;

use anyhow::Result;
use sp1_core_executor::SP1Context;
use sp1_core_machine::{io::SP1Stdin, SP1_CIRCUIT_VERSION};
use sp1_prover::{
    components::SP1ProverComponents, CoreSC, InnerSC, SP1CoreProofData, SP1Prover, SP1ProvingKey,
    SP1ReduceProof, SP1VerifyingKey,
};
use sp1_stark::{MachineVerificationError, SP1ProverOpts};
use std::time::Duration;
use strum_macros::EnumString;
use thiserror::Error;

use crate::{
    install::try_install_circuit_artifacts, SP1Proof, SP1ProofKind, SP1ProofWithPublicValues,
};

/// The type of prover.
#[derive(Debug, PartialEq, EnumString)]
pub enum ProverType {
    Cpu,
    Cuda,
    Mock,
    Network,
}

/// Options to configure proof generation.
#[derive(Clone, Default)]
pub struct ProofOpts {
    /// Options to configure the SP1 prover.
    pub sp1_prover_opts: SP1ProverOpts,
    /// Optional timeout duration for proof generation.
    pub timeout: Option<Duration>,
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
    #[error("Groth16 verification error: {0}")]
    Groth16(anyhow::Error),
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
        opts: ProofOpts,
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
            return Err(SP1VerificationError::VersionMismatch(bundle.sp1_version.clone()));
        }
        match &bundle.proof {
            SP1Proof::Core(proof) => self
                .sp1_prover()
                .verify(&SP1CoreProofData(proof.clone()), vkey)
                .map_err(SP1VerificationError::Core),
            SP1Proof::Compressed(proof) => self
                .sp1_prover()
                .verify_compressed(&SP1ReduceProof { proof: proof.clone() }, vkey)
                .map_err(SP1VerificationError::Recursion),
            SP1Proof::Plonk(proof) => self
                .sp1_prover()
                .verify_plonk_bn254(
                    proof,
                    vkey,
                    &bundle.public_values,
                    &if sp1_prover::build::sp1_dev_mode() {
                        sp1_prover::build::plonk_bn254_artifacts_dev_dir()
                    } else {
                        try_install_circuit_artifacts()
                    },
                )
                .map_err(SP1VerificationError::Plonk),
            SP1Proof::Groth16(proof) => self
                .sp1_prover()
                .verify_groth16_bn254(
                    proof,
                    vkey,
                    &bundle.public_values,
                    &if sp1_prover::build::sp1_dev_mode() {
                        sp1_prover::build::groth16_bn254_artifacts_dev_dir()
                    } else {
                        try_install_circuit_artifacts()
                    },
                )
                .map_err(SP1VerificationError::Groth16),
        }
    }
}
