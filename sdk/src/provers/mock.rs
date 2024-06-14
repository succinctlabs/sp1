#![allow(unused_variables)]
use crate::{
    Prover, SP1CompressedProof, SP1PlonkBn254Proof, SP1Proof, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1VerificationError, SP1VerifyingKey,
};
use anyhow::Result;
use p3_field::PrimeField;
use sp1_core::runtime::SP1Context;
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
        self.prove_with_context(pk, stdin, Default::default())
    }

    /// TODO find out what to actually impl here
    fn prove_with_context(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        context: SP1Context,
    ) -> Result<SP1Proof> {
        let (public_values, _) = SP1Prover::execute_with_context(&pk.elf, &stdin, context)?;
        Ok(SP1ProofWithPublicValues {
            proof: vec![],
            stdin,
            public_values,
            sp1_version: self.version().to_string(),
        })
    }

    fn prove_compressed(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CompressedProof> {
        self.prove_compressed_with_context(pk, stdin, Default::default())
    }

    fn prove_compressed_with_context(
        &self,
        _pk: &SP1ProvingKey,
        _stdin: SP1Stdin,
        _context: SP1Context,
    ) -> Result<SP1CompressedProof> {
        unimplemented!()
    }

    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkBn254Proof> {
        self.prove_plonk_with_context(pk, stdin, Default::default())
    }

    fn prove_plonk_with_context(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        context: SP1Context,
    ) -> Result<SP1PlonkBn254Proof> {
        let (public_values, _) = SP1Prover::execute_with_context(&pk.elf, &stdin, context)?;
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
