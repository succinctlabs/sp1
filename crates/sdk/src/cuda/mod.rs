//! # SP1 CUDA Prover
//!
//! A prover that uses the CUDA to execute and prove programs.

pub mod builder;
pub mod prove;

use anyhow::Result;
use prove::CudaProveBuilder;
use sp1_core_executor::SP1ContextBuilder;
use sp1_core_machine::io::SP1Stdin;
use sp1_cuda::SP1CudaProver;
use sp1_prover::{components::CpuProverComponents, SP1Prover};

use crate::cpu::execute::CpuExecuteBuilder;
use crate::install::try_install_circuit_artifacts;
use crate::{
    Prover, SP1Proof, SP1ProofMode, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey,
};

/// A prover that uses the CPU for execution and the CUDA for proving.
pub struct CudaProver {
    pub(crate) cpu_prover: SP1Prover<CpuProverComponents>,
    pub(crate) cuda_prover: SP1CudaProver,
}

impl CudaProver {
    /// Creates a new [`CudaProver`].
    pub fn new(prover: SP1Prover) -> Self {
        let cuda_prover = SP1CudaProver::new();
        Self {
            cpu_prover: prover,
            cuda_prover: cuda_prover.expect("Failed to initialize CUDA prover"),
        }
    }

    /// Creates a new [`CpuExecuteBuilder`] for simulating the execution of a program on the CPU.
    ///
    /// # Details
    /// The builder is used for both the [`crate::cpu::CpuProver`] and [`crate::CudaProver`] client
    /// types.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, include_elf, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().cuda().build();
    /// let (public_values, execution_report) = client.execute(elf, &stdin)
    ///     .run()
    ///     .unwrap();
    /// ```
    pub fn execute<'a>(&'a self, elf: &'a [u8], stdin: &SP1Stdin) -> CpuExecuteBuilder<'a> {
        CpuExecuteBuilder {
            prover: &self.cpu_prover,
            elf,
            stdin: stdin.clone(),
            context_builder: SP1ContextBuilder::default(),
        }
    }

    /// Creates a new [`CudaProveBuilder`] for proving a program on the CUDA.
    ///
    /// # Details
    /// The builder is used for only the [`crate::CudaProver`] client type.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, include_elf, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().cuda().build();
    /// let (pk, vk) = client.setup(elf);
    /// let proof = client.prove(&pk, &stdin)
    ///     .run()
    ///     .unwrap();
    /// ```
    pub fn prove<'a>(&'a self, pk: &'a SP1ProvingKey, stdin: &'a SP1Stdin) -> CudaProveBuilder<'a> {
        CudaProveBuilder { prover: self, mode: SP1ProofMode::Core, pk, stdin: stdin.clone() }
    }
}

impl Prover<CpuProverComponents> for CudaProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.cpu_prover.setup(elf)
    }

    fn inner(&self) -> &SP1Prover<CpuProverComponents> {
        &self.cpu_prover
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        kind: SP1ProofMode,
    ) -> Result<SP1ProofWithPublicValues> {
        // Generate the core proof.
        let proof = self.cuda_prover.prove_core(pk, stdin)?;
        if kind == SP1ProofMode::Core {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Core(proof.proof.0),
                public_values: proof.public_values,
                sp1_version: self.version().to_string(),
            });
        }

        // Generate the compressed proof.
        let deferred_proofs =
            stdin.proofs.iter().map(|(reduce_proof, _)| reduce_proof.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.cuda_prover.compress(&pk.vk, proof, deferred_proofs)?;
        if kind == SP1ProofMode::Compressed {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Compressed(Box::new(reduce_proof)),
                public_values,
                sp1_version: self.version().to_string(),
            });
        }

        // Generate the shrink proof.
        let compress_proof = self.cuda_prover.shrink(reduce_proof)?;

        // Genenerate the wrap proof.
        let outer_proof = self.cuda_prover.wrap_bn254(compress_proof)?;

        if kind == SP1ProofMode::Plonk {
            let plonk_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
                sp1_prover::build::try_build_plonk_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts("plonk")
            };
            let proof = self.cpu_prover.wrap_plonk_bn254(outer_proof, &plonk_bn254_artifacts);
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Plonk(proof),
                public_values,
                sp1_version: self.version().to_string(),
            });
        } else if kind == SP1ProofMode::Groth16 {
            let groth16_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
                sp1_prover::build::try_build_groth16_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts("groth16")
            };

            let proof = self.cpu_prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Groth16(proof),
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
