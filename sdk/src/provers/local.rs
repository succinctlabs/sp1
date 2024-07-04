use anyhow::Result;
use sp1_core::{runtime::SP1Context, utils::SP1ProverOpts};
use sp1_prover::{SP1Prover, SP1Stdin};

use crate::{
    Prover, SP1Proof, SP1ProofKind, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey,
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
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
        let proof = self.prover.prove_core(pk, &stdin, opts, context)?;
        if kind == SP1ProofKind::Core {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Core(proof.proof.0),
                stdin: proof.stdin,
                public_values: proof.public_values,
                sp1_version: self.version().to_string(),
            });
        }
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs, opts)?;
        if kind == SP1ProofKind::Compressed {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Compressed(reduce_proof.proof),
                stdin,
                public_values,
                sp1_version: self.version().to_string(),
            });
        }
        let compress_proof = self.prover.shrink(reduce_proof, opts)?;
        let outer_proof = self.prover.wrap_bn254(compress_proof, opts)?;

        let plonk_bn254_aritfacts = if sp1_prover::build::sp1_dev_mode() {
            sp1_prover::build::try_build_plonk_bn254_artifacts_dev(
                &self.prover.wrap_vk,
                &outer_proof.proof,
            )
        } else {
            cfg_if::cfg_if! {
                if #[cfg(feature = "network")] {
                    sp1_prover::install::try_install_plonk_bn254_artifacts()
                } else {
                    return Err(anyhow::anyhow!("cannot install plonk artifacts without network feature"));
                }
            }
        };
        let proof = self
            .prover
            .wrap_plonk_bn254(outer_proof, &plonk_bn254_aritfacts);
        if kind == SP1ProofKind::Plonk {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Plonk(proof),
                stdin,
                public_values,
                sp1_version: self.version().to_string(),
            });
        }
        unreachable!()
    }
}

impl Default for LocalProver {
    fn default() -> Self {
        Self::new()
    }
}
