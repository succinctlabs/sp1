use anyhow::Result;
use sp1_core::{runtime::SP1Context, utils::SP1ProverOpts};
use sp1_prover::{SP1Prover, SP1Stdin};

use crate::{
    Prover, SP1CompressedProof, SP1PlonkBn254Proof, SP1Proof, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1VerifyingKey,
};

use super::ProverType;

/// An implementation of [crate::ProverClient] that can generate end-to-end proofs locally.
pub struct LocalProver {
    prover: SP1Prover,
}

impl LocalProver {
    /// Creates a new [LocalProver].
    pub fn new() -> Self {
        let prover = SP1Prover::new();
        Self { prover }
    }
}

impl Prover for LocalProver {
    fn id(&self) -> ProverType {
        ProverType::Local
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn sp1_prover(&self) -> &SP1Prover {
        &self.prover
    }

    fn prove<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        opts: SP1ProverOpts,
        context: SP1Context<'a>,
    ) -> Result<SP1Proof> {
        let proof = self.prover.prove_core_with(pk, &stdin, opts, context)?;
        Ok(SP1ProofWithPublicValues {
            proof: proof.proof.0,
            stdin: proof.stdin,
            public_values: proof.public_values,
            sp1_version: self.version().to_string(),
        })
    }

    fn prove_compressed<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        opts: SP1ProverOpts,
        context: SP1Context<'a>,
    ) -> Result<SP1CompressedProof> {
        let proof = self.prover.prove_core_with(pk, &stdin, opts, context)?;
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self
            .prover
            .compress_with(&pk.vk, proof, deferred_proofs, opts)?;
        Ok(SP1CompressedProof {
            proof: reduce_proof.proof,
            stdin,
            public_values,
            sp1_version: self.version().to_string(),
        })
    }

    fn prove_plonk<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        opts: SP1ProverOpts,
        context: SP1Context<'a>,
    ) -> Result<SP1PlonkBn254Proof> {
        let proof = self.prover.prove_core_with(pk, &stdin, opts, context)?;
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self
            .prover
            .compress_with(&pk.vk, proof, deferred_proofs, opts)?;
        let compress_proof = self.prover.shrink_with(reduce_proof, opts)?;
        let outer_proof = self.prover.wrap_bn254(compress_proof)?;

        let plonk_bn254_aritfacts = if sp1_prover::build::sp1_dev_mode() {
            sp1_prover::build::try_build_plonk_bn254_artifacts_dev(
                &self.prover.wrap_vk,
                &outer_proof.proof,
            )
        } else {
            sp1_prover::build::try_install_plonk_bn254_artifacts()
        };
        let proof = self
            .prover
            .wrap_plonk_bn254(outer_proof, &plonk_bn254_aritfacts);
        Ok(SP1ProofWithPublicValues {
            proof,
            stdin,
            public_values,
            sp1_version: self.version().to_string(),
        })
    }
}

impl Default for LocalProver {
    fn default() -> Self {
        Self::new()
    }
}
