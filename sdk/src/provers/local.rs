use anyhow::Result;
use sp1_core::runtime::SP1Context;
use sp1_prover::{components::SP1ProverComponents, SP1Prover, SP1Stdin};
use sysinfo::System;

#[cfg(feature = "cuda")]
use sp1_cuda::SP1CudaProver;

use crate::{
    install::try_install_plonk_bn254_artifacts, provers::ProofOpts, Prover, SP1Proof, SP1ProofKind,
    SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey,
};

use super::ProverType;

/// An implementation of [crate::ProverClient] that can generate end-to-end proofs locally.
pub struct LocalProver<C: SP1ProverComponents> {
    prover: SP1Prover<C>,
    #[cfg(feature = "cuda")]
    cuda_prover: SP1CudaProver,
}

impl<C: SP1ProverComponents> LocalProver<C> {
    /// Creates a new [LocalProver].
    pub fn new() -> Self {
        let prover = SP1Prover::new();

        #[cfg(not(feature = "cuda"))]
        {
            Self { prover }
        }

        #[cfg(feature = "cuda")]
        {
            let cuda_prover = SP1CudaProver::new();
            Self {
                prover,
                cuda_prover,
            }
        }
    }

    /// Creates a new [LocalProver] from an existing [SP1Prover].
    pub fn from_prover(prover: SP1Prover<C>) -> Self {
        #[cfg(not(feature = "cuda"))]
        {
            Self { prover }
        }

        #[cfg(feature = "cuda")]
        {
            let cuda_prover = SP1CudaProver::new();
            Self {
                prover,
                cuda_prover,
            }
        }
    }
}

impl<C: SP1ProverComponents> Prover<C> for LocalProver<C> {
    fn id(&self) -> ProverType {
        ProverType::Local
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn sp1_prover(&self) -> &SP1Prover<C> {
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
        let total_ram_gb = System::new_all().total_memory() / 1_000_000_000;
        if kind == SP1ProofKind::Plonk && total_ram_gb <= 60 {
            return Err(anyhow::anyhow!(
                "not enough memory to generate plonk proof. at least 64GB is required."
            ));
        }

        // Generate the core proof.
        #[cfg(not(feature = "cuda"))]
        let proof = self
            .prover
            .prove_core(pk, &stdin, opts.sp1_prover_opts, context)?;
        #[cfg(feature = "cuda")]
        let proof = self.cuda_prover.prove_core(pk, &stdin)?;

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

        // Generate the compressed proof.
        #[cfg(not(feature = "cuda"))]
        let reduce_proof =
            self.prover
                .compress(&pk.vk, proof, deferred_proofs, opts.sp1_prover_opts)?;
        #[cfg(feature = "cuda")]
        let reduce_proof = self.cuda_prover.compress(&pk.vk, proof, deferred_proofs)?;

        if kind == SP1ProofKind::Compressed {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Compressed(reduce_proof.proof),
                stdin,
                public_values,
                sp1_version: self.version().to_string(),
            });
        }

        // Generate the shrink proof.
        #[cfg(not(feature = "cuda"))]
        let compress_proof = self.prover.shrink(reduce_proof, opts.sp1_prover_opts)?;
        #[cfg(feature = "cuda")]
        let compress_proof = self.cuda_prover.shrink(reduce_proof)?;

        // Genenerate the wrap proof.
        #[cfg(not(feature = "cuda"))]
        let outer_proof = self
            .prover
            .wrap_bn254(compress_proof, opts.sp1_prover_opts)?;
        #[cfg(feature = "cuda")]
        let outer_proof = self.cuda_prover.wrap_bn254(compress_proof)?;

        let plonk_bn254_aritfacts = if sp1_prover::build::sp1_dev_mode() {
            sp1_prover::build::try_build_plonk_bn254_artifacts_dev(
                self.prover.wrap_vk(),
                &outer_proof.proof,
            )
        } else {
            try_install_plonk_bn254_artifacts()
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

impl<C: SP1ProverComponents> Default for LocalProver<C> {
    fn default() -> Self {
        Self::new()
    }
}
