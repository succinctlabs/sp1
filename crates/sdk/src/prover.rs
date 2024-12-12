use anyhow::Result;
use async_trait::async_trait;
use sp1_core_executor::{ExecutionError, ExecutionReport};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use crate::types::{SP1ProvingKey, SP1VerifyingKey, Elf};

use crate::{SP1ProofWithPublicValues, ProofOpts, SP1VerificationError};

#[async_trait]
pub trait Prover: Sync {
    async fn setup(&self, elf: &Elf) -> SP1ProvingKey;

    #[cfg(feature = "blocking")]
    fn setup_sync(&self, elf: &Elf) -> SP1ProvingKey;

    async fn execute(
        &self,
        elf: &Elf,
        stdin: SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError>;

    #[cfg(feature = "blocking")]
    fn execute_sync(
        &self,
        elf: &Elf,
        stdin: SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError>;

    async fn prove_with_options(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        opts: ProofOpts,
    ) -> Result<SP1ProofWithPublicValues>;

    #[cfg(feature = "blocking")]
    fn prove_with_options_sync(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        opts: ProofOpts,
    ) -> Result<SP1ProofWithPublicValues>;

    async fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError>;

    #[cfg(feature = "blocking")]
    fn verify_sync(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError>;
}
