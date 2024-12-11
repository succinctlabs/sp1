use anyhow::Result;
use async_trait::async_trait;
use sp1_core_executor::ExecutionReport;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{SP1ProvingKey, SP1VerifyingKey};

use crate::{opts::ProofOpts, proof::SP1ProofWithPublicValues, provers::SP1VerificationError};

#[async_trait]
pub trait Prover: Send + Sync {
    async fn setup(&self, elf: &[u8]) -> Result<(SP1ProvingKey, SP1VerifyingKey)>;

    async fn execute(&self, elf: &[u8], stdin: SP1Stdin) -> Result<ExecutionReport>;

    async fn prove_with_options(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        opts: &ProofOpts,
    ) -> Result<SP1ProofWithPublicValues>;

    #[cfg(feature = "blocking")]
    fn prove_with_options_sync(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        opts: &ProofOpts,
    ) -> Result<SP1ProofWithPublicValues>;

    async fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError>;
}
