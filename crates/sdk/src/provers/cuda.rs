use anyhow::Result;
use sp1_core_machine::io::SP1Stdin;
use sp1_cuda::SP1CudaProver;
use sp1_prover::{components::DefaultProverComponents, SP1Prover};

use super::ProverType;
use crate::install::try_install_circuit_artifacts;
use crate::{
    provers::ProofOpts, Prover, SP1Context, SP1Proof, SP1ProofKind, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1VerifyingKey,
};

/// An implementation of [crate::ProverClient] that can generate proofs locally using CUDA.
pub struct CudaProver {
    prover: SP1Prover<DefaultProverComponents>,
    cuda_prover: SP1CudaProver,
}

impl CudaProver {
    /// Creates a new [CudaProver].
    pub fn new(prover: SP1Prover) -> Self {
        let cuda_prover = SP1CudaProver::new();
        Self { prover, cuda_prover: cuda_prover.expect("Failed to initialize CUDA prover") }
    }
}

impl Prover<DefaultProverComponents> for CudaProver {
    fn id(&self) -> ProverType {
        ProverType::Cuda
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
        _opts: ProofOpts,
        _context: SP1Context<'a>,
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
        tracing::warn!("opts and context are ignored for the cuda prover");

        // Generate the core proof.
        let proof = self.cuda_prover.prove_core(pk, &stdin)?;
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
        let reduce_proof = self.cuda_prover.compress(&pk.vk, proof, deferred_proofs)?;
        if kind == SP1ProofKind::Compressed {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Compressed(Box::new(reduce_proof)),
                stdin,
                public_values,
                sp1_version: self.version().to_string(),
            });
        }

        // Generate the shrink proof.
        let compress_proof = self.cuda_prover.shrink(reduce_proof)?;

        // Genenerate the wrap proof.
        let outer_proof = self.cuda_prover.wrap_bn254(compress_proof)?;

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

impl Default for CudaProver {
    fn default() -> Self {
        Self::new(SP1Prover::new())
    }
}
