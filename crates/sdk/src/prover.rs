use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use sp1_core_executor::{ExecutionError, ExecutionReport};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{SP1ProvingKey, SP1VerifyingKey};

use crate::{ProofOpts, proof::SP1ProofWithPublicValues, SP1VerificationError};

#[async_trait]
pub trait Prover: Sync {
    async fn setup(&self, elf: Arc<[u8]>) -> Arc<SP1ProvingKey>;

    #[cfg(feature = "blocking")]
    fn setup_sync(&self, elf: &[u8]) -> Arc<SP1ProvingKey>;

    async fn execute(
        &self,
        elf: Arc<[u8]>,
        stdin: SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError>;

    #[cfg(feature = "blocking")]
    fn execute_sync(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError>;

    async fn prove_with_options(
        &self,
        pk: &Arc<SP1ProvingKey>,
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
        proof: Arc<SP1ProofWithPublicValues>,
        vk: Arc<SP1VerifyingKey>,
    ) -> Result<(), SP1VerificationError>;

    #[cfg(feature = "blocking")]
    fn verify_sync(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError>;
}
