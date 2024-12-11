use anyhow::Result;
use async_trait::async_trait;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{SP1ProvingKey, SP1VerifyingKey};

use crate::CpuProver;
use crate::SP1ProofWithPublicValues;
use crate::SP1VerificationError;

#[async_trait]
pub trait Prover: Send + Sync {
    fn cpu_prover(&self) -> &CpuProver;

    async fn setup(&self, elf: &[u8]) -> Result<(SP1ProvingKey, SP1VerifyingKey)> {
        &self.cpu_prover().setup(elf)
    }

    async fn execute(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1Report> {
        self.cpu_prover().sp1_prover().execute(elf, stdin, Default::default())
    }

    async fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1ProofWithPublicValues>;

    async fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        self.cpu_prover().verify(proof, vk)
    }
}
