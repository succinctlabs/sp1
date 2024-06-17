#![allow(unused_variables)]
use crate::{
    Prover, SP1CompressedProof, SP1PlonkBn254Proof, SP1Proof, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1VerificationError, SP1VerifyingKey,
};
use anyhow::Result;
use p3_field::PrimeField;
use sp1_prover::{
    verify::verify_plonk_bn254_public_inputs, HashableKey, PlonkBn254Proof, SP1Prover, SP1Stdin,
};

use super::ProverType;

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
    fn id(&self) -> ProverType {
        ProverType::Mock
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn sp1_prover(&self) -> &SP1Prover {
        unimplemented!("MockProver does not support SP1Prover")
    }

    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Proof> {
        let (public_values, _) = SP1Prover::execute(&pk.elf, &stdin)?;
        Ok(SP1ProofWithPublicValues {
            proof: vec![],
            stdin,
            public_values,
            sp1_version: self.version().to_string(),
        })
    }

    fn prove_compressed(
        &self,
        _pk: &SP1ProvingKey,
        _stdin: SP1Stdin,
    ) -> Result<SP1CompressedProof> {
        unimplemented!()
    }

    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkBn254Proof> {
        let (public_values, _) = SP1Prover::execute(&pk.elf, &stdin)?;
        Ok(SP1PlonkBn254Proof {
            proof: PlonkBn254Proof {
                public_inputs: [
                    pk.vk.hash_bn254().as_canonical_biguint().to_string(),
                    public_values.hash().to_string(),
                ],
                encoded_proof: "".to_string(),
                raw_proof: "".to_string(),
                plonk_vkey_hash: [0; 32],
            },
            stdin,
            public_values,
            sp1_version: self.version().to_string(),
        })
    }

    fn verify(
        &self,
        _proof: &SP1Proof,
        _vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        Ok(())
    }

    fn verify_compressed(
        &self,
        _proof: &SP1CompressedProof,
        _vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        Ok(())
    }

    fn verify_plonk(
        &self,
        proof: &SP1PlonkBn254Proof,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        verify_plonk_bn254_public_inputs(vkey, &proof.public_values, &proof.proof.public_inputs)
            .map_err(SP1VerificationError::Plonk)?;
        Ok(())
    }
}

impl Default for MockProver {
    fn default() -> Self {
        Self::new()
    }
}
