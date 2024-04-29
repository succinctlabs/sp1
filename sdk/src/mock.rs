use crate::{
    Prover, SP1CompressedProof, SP1DefaultProof, SP1Groth16Proof, SP1PlonkProof,
    SP1ProofWithMetadata, SP1ProvingKey, SP1VerifyingKey,
};
use anyhow::Result;
use sp1_prover::{Groth16Proof, PlonkBn254Proof, SP1Prover, SP1Stdin};

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

    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1DefaultProof> {
        let public_values = SP1Prover::execute(&pk.elf, &stdin);
        Ok(SP1ProofWithMetadata {
            proof: vec![],
            stdin,
            public_values,
        })
    }

    fn prove_compressed(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CompressedProof> {
        unimplemented!()
    }

    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof> {
        let public_values = SP1Prover::execute(&pk.elf, &stdin);
        Ok(SP1ProofWithMetadata {
            proof: PlonkBn254Proof::default(),
            stdin,
            public_values,
        })
    }

    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof> {
        let public_values = SP1Prover::execute(&pk.elf, &stdin);
        Ok(SP1ProofWithMetadata {
            proof: Groth16Proof::default(),
            stdin,
            public_values,
        })
    }

    fn verify(&self, proof: &SP1DefaultProof, vkey: &SP1VerifyingKey) -> Result<()> {
        Ok(())
    }

    fn verify_compressed(&self, proof: &SP1CompressedProof, vkey: &SP1VerifyingKey) -> Result<()> {
        unimplemented!()
    }

    fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()> {
        Ok(())
    }

    fn verify_plonk(&self, proof: &SP1PlonkProof, vkey: &SP1VerifyingKey) -> Result<()> {
        Ok(())
    }
}
