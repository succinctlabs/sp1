use super::ProverType;
use crate::install::try_install_circuit_artifacts;
use crate::util::dump_proof_input;
use crate::{
    Prover, SP1Proof, SP1ProofKind, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey,
};
use anyhow::Result;
use sp1_core_machine::io::SP1Stdin;
use sp1_cuda::SP1CudaProver;
use sp1_prover::{components::DefaultProverComponents, SP1Prover};

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

    /// Prepare to prove the execution of the given program with the given input in the default
    /// mode. The returned [CudaProve] may be configured via its methods before running.
    /// For example, calling [CudaProve::compressed] sets the mode to compressed mode.
    pub fn prove<'a>(&'a self, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> CudaProve<'a> {
        CudaProve::new(self, pk, stdin)
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

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
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

/// Builder to prepare and configure proving execution of a program on an input.
/// May be run with [Self::run].
pub struct CudaProve<'a> {
    prover: &'a CudaProver,
    kind: SP1ProofKind,
    pk: &'a SP1ProvingKey,
    stdin: SP1Stdin,
}

impl<'a> CudaProve<'a> {
    fn new(prover: &'a CudaProver, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> Self {
        Self { prover, kind: Default::default(), pk, stdin }
    }

    /// Prove the execution of the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<SP1ProofWithPublicValues> {
        let Self { prover, kind, pk, stdin } = self;

        // Dump the program and stdin to files for debugging if `SP1_DUMP` is set.
        dump_proof_input(&pk.elf, &stdin);

        Prover::<DefaultProverComponents>::prove(prover, pk, stdin, kind)
    }

    /// Set the proof kind to the core mode. This is the default.
    pub fn core(mut self) -> Self {
        self.kind = SP1ProofKind::Core;
        self
    }

    /// Set the proof kind to the compressed mode.
    pub fn compressed(mut self) -> Self {
        self.kind = SP1ProofKind::Compressed;
        self
    }

    /// Set the proof mode to the plonk bn254 mode.
    pub fn plonk(mut self) -> Self {
        self.kind = SP1ProofKind::Plonk;
        self
    }

    /// Set the proof mode to the groth16 bn254 mode.
    pub fn groth16(mut self) -> Self {
        self.kind = SP1ProofKind::Groth16;
        self
    }

    /// Set the proof mode to the given mode.
    pub fn mode(mut self, mode: SP1ProofKind) -> Self {
        self.kind = mode;
        self
    }
}
