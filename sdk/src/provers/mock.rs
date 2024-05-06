#![allow(unused_variables)]
use crate::{
    Prover, SP1Groth16ProofData, SP1PlonkProofData, SP1ProofWithMetadata, SP1ProvingKey,
    SP1VerifyingKey,
};
use anyhow::Result;
use sp1_prover::{
    Groth16Proof, PlonkBn254Proof, SP1CoreProof, SP1CoreProofData, SP1Groth16Proof, SP1PlonkProof,
    SP1Prover, SP1ReducedProof, SP1Stdin,
};

use crate::{
    Prover, SP1CompressedProof, SP1Groth16Proof, SP1PlonkProof, SP1Proof, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1VerifyingKey,
};

/// An implementation of [crate::ProverClient] that can generate mock proofs.
pub struct MockProver {
    pub(crate) prover: SP1Prover,
}

impl MockProver {
    /// Creates a new [MockProver].
    pub fn new() -> Self {
        let prover = SP1Prover::new();
        Self { prover }
    }
}

impl Prover for MockProver {
    fn id(&self) -> String {
        "mock".to_string()
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn sp1_prover(&self) -> &SP1Prover {
        unimplemented!("MockProver does not support SP1Prover")
    }

    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Proof> {
        let public_values = SP1Prover::execute(&pk.elf, &stdin);
        Ok(SP1ProofWithPublicValues {
            proof: vec![],
            stdin,
            public_values,
        })
    }

    fn prove_compressed(
        &self,
        _pk: &SP1ProvingKey,
        _stdin: SP1Stdin,
    ) -> Result<SP1CompressedProof> {
        unimplemented!()
    }

    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof> {
        let public_values = SP1Prover::execute(&pk.elf, &stdin);
        Ok(SP1ProofWithPublicValues {
            proof: PlonkBn254Proof::default(),
            stdin,
            public_values,
        })
    }

    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof> {
        let public_values = SP1Prover::execute(&pk.elf, &stdin);
        Ok(SP1ProofWithPublicValues {
            proof: Groth16Proof::default(),
            stdin,
            public_values,
        })
    }

    fn verify(&self, _proof: &SP1Proof, _vkey: &SP1VerifyingKey) -> Result<()> {
        Ok(())
    }

    fn verify_compressed(
        &self,
        _proof: &SP1CompressedProof,
        _vkey: &SP1VerifyingKey,
    ) -> Result<()> {
        Ok(())
    }

    fn verify_groth16(&self, _proof: &SP1Groth16Proof, _vkey: &SP1VerifyingKey) -> Result<()> {
        Ok(())
    }

    fn verify_plonk(&self, _proof: &SP1PlonkProof, _vkey: &SP1VerifyingKey) -> Result<()> {
        Ok(())
    }
}

impl Default for MockProver {
    fn default() -> Self {
        Self::new()
    }
}
