#![allow(unused_variables)]
use std::str::FromStr;

use crate::{
    Prover, SP1CompressedProof, SP1Groth16Proof, SP1PlonkProof, SP1Proof,
    SP1ProofVerificationError, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey,
};
use anyhow::Result;
use num_bigint::BigUint;
use p3_field::PrimeField;
use sp1_prover::{Groth16Proof, HashableKey, SP1Prover, SP1Stdin};

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
        let public_values = SP1Prover::execute(&pk.elf, &stdin)?;
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

    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof> {
        let public_values = SP1Prover::execute(&pk.elf, &stdin)?;
        Ok(SP1Groth16Proof {
            proof: Groth16Proof {
                public_inputs: [
                    public_values.hash().to_string(),
                    pk.vk.hash_bn254().as_canonical_biguint().to_string(),
                ],
                encoded_proof: "".to_string(),
                raw_proof: "".to_string(),
            },
            stdin,
            public_values,
        })
    }

    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof> {
        todo!()
    }

    fn verify(
        &self,
        _proof: &SP1Proof,
        _vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1ProofVerificationError> {
        Ok(())
    }

    fn verify_compressed(
        &self,
        _proof: &SP1CompressedProof,
        _vkey: &SP1VerifyingKey,
    ) -> Result<()> {
        Ok(())
    }

    fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()> {
        // Verify the public values and the vkey matches.
        let public_values_hash = proof.public_values.hash();
        let vk_hash = vkey.vk.hash_bn254().as_canonical_biguint();

        // Get the public inputs from the inner Groth16Proof.
        let groth16_vkey_hash = BigUint::from_str(&proof.proof.public_inputs[0])?;
        let groth16_committed_values_digest = BigUint::from_str(&proof.proof.public_inputs[1])?;

        if groth16_vkey_hash != vk_hash {
            return Err(anyhow::anyhow!(
                "The supplied verifying key does not match the inner Groth16 proof's verifying key."
            ));
        }
        if groth16_committed_values_digest != public_values_hash {
            return Err(anyhow::anyhow!(
                "The public values in the SP1 proof do not match the public values in the inner 
                Groth16 proof."
            ));
        }

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
