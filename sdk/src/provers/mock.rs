#![allow(unused_variables)]
use crate::{
    Prover, SP1Proof, SP1ProofBundle, SP1ProofKind, SP1ProvingKey, SP1VerificationError,
    SP1VerifyingKey,
};
use anyhow::Result;
use p3_field::PrimeField;
use sp1_core::{runtime::SP1Context, utils::SP1ProverOpts};
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

    fn prove<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        opts: SP1ProverOpts,
        context: SP1Context<'a>,
        kind: SP1ProofKind,
    ) -> Result<SP1ProofBundle> {
        match kind {
            SP1ProofKind::Core => {
                let (public_values, _) = SP1Prover::execute(&pk.elf, &stdin, context)?;
                Ok(SP1ProofBundle {
                    proof: SP1Proof::Core(vec![]),
                    stdin,
                    public_values,
                    sp1_version: self.version().to_string(),
                })
            }
            SP1ProofKind::Compress => unimplemented!(),
            SP1ProofKind::PlonkBn254 => {
                let (public_values, _) = SP1Prover::execute(&pk.elf, &stdin, context)?;
                Ok(SP1ProofBundle {
                    proof: SP1Proof::PlonkBn254(PlonkBn254Proof {
                        public_inputs: [
                            pk.vk.hash_bn254().as_canonical_biguint().to_string(),
                            public_values.hash().to_string(),
                        ],
                        encoded_proof: "".to_string(),
                        raw_proof: "".to_string(),
                        plonk_vkey_hash: [0; 32],
                    }),
                    stdin,
                    public_values,
                    sp1_version: self.version().to_string(),
                })
            }
        }
    }

    fn verify(
        &self,
        bundle: &SP1ProofBundle,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        match &bundle.proof {
            SP1Proof::PlonkBn254(PlonkBn254Proof { public_inputs, .. }) => {
                verify_plonk_bn254_public_inputs(vkey, &bundle.public_values, public_inputs)
                    .map_err(SP1VerificationError::Plonk)
            }
            _ => Ok(()),
        }
    }
}

impl Default for MockProver {
    fn default() -> Self {
        Self::new()
    }
}
