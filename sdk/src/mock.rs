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

pub struct MockProver {
    pub(crate) prover: SP1Prover,
}

impl Default for MockProver {
    fn default() -> Self {
        Self::new()
    }
}

impl MockProver {
    pub fn new() -> Self {
        let prover = SP1Prover::new();
        Self { prover }
    }
}

impl Prover for MockProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CoreProof> {
        let public_values = SP1Prover::execute(&pk.elf, &stdin);
        Ok(SP1ProofWithMetadata {
            proof: SP1CoreProofData(vec![]),
            stdin,
            public_values,
        })
    }

    fn prove_reduced(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1ReducedProof> {
        unimplemented!()
    }

    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof> {
        let public_values = SP1Prover::execute(&pk.elf, &stdin);
        Ok(SP1ProofWithMetadata {
            proof: SP1PlonkProofData(PlonkBn254Proof::default()),
            stdin,
            public_values,
        })
    }

    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof> {
        let public_values = SP1Prover::execute(&pk.elf, &stdin);
        Ok(SP1ProofWithMetadata {
            proof: SP1Groth16ProofData(Groth16Proof::default()),
            stdin,
            public_values,
        })
    }

    fn verify(&self, proof: &SP1CoreProof, vkey: &SP1VerifyingKey) -> Result<()> {
        Ok(())
    }

    fn verify_reduced(&self, proof: &SP1ReducedProof, vkey: &SP1VerifyingKey) -> Result<()> {
        Ok(())
    }

    fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()> {
        Ok(())
    }

    fn verify_plonk(&self, proof: &SP1PlonkProof, vkey: &SP1VerifyingKey) -> Result<()> {
        Ok(())
    }
}
