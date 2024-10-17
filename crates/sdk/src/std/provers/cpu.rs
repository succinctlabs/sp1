use anyhow::Result;
use sp1_core_executor::SP1Context;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{components::DefaultProverComponents, SP1Prover};

use crate::install::try_install_circuit_artifacts;
use crate::{
    provers::ProofOpts, Prover, SP1Proof, SP1ProofKind, SP1ProofWithPublicValues, SP1ProvingKey,
    SP1VerifyingKey,
};

use super::ProverType;

/// An implementation of [crate::ProverClient] that can generate end-to-end proofs locally.
pub struct CpuProver {
    prover: SP1Prover<DefaultProverComponents>,
}

impl CpuProver {
    /// Creates a new [LocalProver].
    pub fn new() -> Self {
        let prover = SP1Prover::new();
        Self { prover }
    }

    /// Creates a new [LocalProver] from an existing [SP1Prover].
    pub fn from_prover(prover: SP1Prover<DefaultProverComponents>) -> Self {
        Self { prover }
    }
}

impl Prover<DefaultProverComponents> for CpuProver {
    fn id(&self) -> ProverType {
        ProverType::Cpu
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn sp1_prover(&self) -> &SP1Prover<DefaultProverComponents> {
        &self.prover
    }

    fn prove<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        opts: ProofOpts,
        context: SP1Context<'a>,
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
        // Generate the core proof.
        let proof: sp1_prover::SP1ProofWithMetadata<sp1_prover::SP1CoreProofData> =
            self.prover.prove_core(pk, &stdin, opts.sp1_prover_opts, context)?;
        if kind == SP1ProofKind::Core {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Core(proof.proof.0),
                stdin: proof.stdin,
                public_values: proof.public_values,
                sp1_version: self.version().to_string(),
            });
        }

        let deferred_proofs =
            stdin.proofs.iter().map(|(reduce_proof, _)| reduce_proof.clone()).collect();
        let public_values = proof.public_values.clone();

        // Generate the compressed proof.
        let reduce_proof =
            self.prover.compress(&pk.vk, proof, deferred_proofs, opts.sp1_prover_opts)?;
        if kind == SP1ProofKind::Compressed {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Compressed(Box::new(reduce_proof)),
                stdin,
                public_values,
                sp1_version: self.version().to_string(),
            });
        }

        // Generate the shrink proof.
        let compress_proof = self.prover.shrink(reduce_proof, opts.sp1_prover_opts)?;

        // Genenerate the wrap proof.
        let outer_proof = self.prover.wrap_bn254(compress_proof, opts.sp1_prover_opts)?;

        if kind == SP1ProofKind::Plonk {
            let plonk_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
                sp1_prover::build::try_build_plonk_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts("plonk")
            };
            let proof = self.prover.wrap_plonk_bn254(outer_proof, &plonk_bn254_artifacts);

            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Plonk(proof),
                stdin,
                public_values,
                sp1_version: self.version().to_string(),
            });
        } else if kind == SP1ProofKind::Groth16 {
            let groth16_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
                sp1_prover::build::try_build_groth16_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts("groth16")
            };

            let proof = self.prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Groth16(proof),
                stdin,
                public_values,
                sp1_version: self.version().to_string(),
            });
        }

        unreachable!()
    }
}

impl Default for CpuProver {
    fn default() -> Self {
        Self::new()
    }
}
