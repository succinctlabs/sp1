//! # SP1 Prover Trait  
//!
//! A trait that each prover variant must implement.

use std::borrow::Borrow;

use anyhow::Result;
use itertools::Itertools;
use p3_field::PrimeField32;
use sp1_core_executor::{ExecutionReport, SP1Context};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{
    components::SP1ProverComponents, CoreSC, InnerSC, SP1CoreProofData, SP1Prover, SP1ProvingKey,
    SP1VerifyingKey, SP1_CIRCUIT_VERSION,
};
use sp1_stark::{air::PublicValues, MachineVerificationError, Word};
use thiserror::Error;

use crate::install::try_install_circuit_artifacts;
use crate::{SP1Proof, SP1ProofMode, SP1ProofWithPublicValues};

/// Enum representing different prover implementations
pub enum SP1ProverImpl<C: SP1ProverComponents> {
    #[cfg(feature = "docker")]
    Docker(DockerProver<C>),
    #[cfg(feature = "in_memory")]
    InMemory(InMemoryProver<C>),
}

/// In-memory prover implementation
#[cfg(feature = "in_memory")]
pub struct InMemoryProver<C: SP1ProverComponents> {
    core_prover: SP1Prover<C>,
}

#[cfg(feature = "in_memory")]
impl<C: SP1ProverComponents> Prover<C> for InMemoryProver<C> {
    fn inner(&self) -> &SP1Prover<C> {
        &self.core_prover
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        SP1Prover::core_setup(elf)
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
    ) -> Result<SP1ProofWithPublicValues> {
        match mode {
            SP1ProofMode::Compressed => {
                let proof = self.core_prover.prove_compressed(pk, stdin)?;
                Ok(SP1ProofWithPublicValues {
                    proof: SP1Proof::Compressed(proof),
                    public_values: self.core_prover.get_public_values(),
                    sp1_version: self.version().to_string(),
                })
            }
            _ => anyhow::bail!("In-memory prover only supports compressed proofs"),
        }
    }
}

/// Docker-based prover implementation
#[cfg(feature = "docker")]
pub struct DockerProver<C: SP1ProverComponents> {
    docker_prover: SP1Prover<C>,
}

#[cfg(feature = "docker")]
impl<C: SP1ProverComponents> Prover<C> for DockerProver<C> {
    fn inner(&self) -> &SP1Prover<C> {
        &self.docker_prover
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        SP1Prover::docker_setup(elf)
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
    ) -> Result<SP1ProofWithPublicValues> {
        // Existing Docker-based implementation
        self.docker_prover.prove(pk, stdin, mode)
    }
}

// Rest of the original file remains unchanged...
