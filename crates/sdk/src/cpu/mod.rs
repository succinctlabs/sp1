//! # SP1 CPU Prover
//!
//! A prover that uses the CPU to execute and prove programs.

pub mod builder;
pub mod execute;
pub mod prove;

use anyhow::Result;
use execute::CpuExecuteBuilder;
use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_field::{extension::BinomialExtensionField, AbstractField, PrimeField};
use p3_fri::{FriProof, TwoAdicFriPcsProof};
use prove::CpuProveBuilder;
use sp1_core_executor::{SP1Context, SP1ContextBuilder, SP1ReduceProof};
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{
    components::CpuProverComponents,
    verify::{verify_groth16_bn254_public_inputs, verify_plonk_bn254_public_inputs},
    Groth16Bn254Proof, HashableKey, PlonkBn254Proof, SP1CoreProofData, SP1ProofWithMetadata,
    SP1Prover,
};
use sp1_stark::{
    SP1CoreOpts, SP1ProverOpts, ShardCommitment, ShardOpenedValues, ShardProof, StarkVerifyingKey,
};

use crate::install::try_install_circuit_artifacts;
use crate::prover::verify_proof;
use crate::SP1VerificationError;
use crate::{
    Prover, SP1Proof, SP1ProofMode, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey,
};

/// A prover that uses the CPU to execute and prove programs.
pub struct CpuProver {
    pub(crate) prover: SP1Prover<CpuProverComponents>,
    pub(crate) mock: bool,
}

impl CpuProver {
    /// Creates a new [`CpuProver`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new [`CpuProver`] in mock mode.
    #[must_use]
    pub fn mock() -> Self {
        Self { prover: SP1Prover::new(), mock: true }
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
    /// let client = ProverClient::builder().cpu().build();
    /// let (public_values, execution_report) = client.execute(elf, &stdin)
    ///     .run()
    ///     .unwrap();
    /// ```
    pub fn execute<'a>(&'a self, elf: &'a [u8], stdin: &SP1Stdin) -> CpuExecuteBuilder<'a> {
        CpuExecuteBuilder {
            prover: &self.prover,
            elf,
            stdin: stdin.clone(),
            context_builder: SP1ContextBuilder::default(),
        }
    }

    /// Creates a new [`CpuProveBuilder`] for proving a program on the CPU.
    ///
    /// # Details
    /// The builder is used for only the [`crate::cpu::CpuProver`] client type.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin, include_elf, Prover};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = SP1Stdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin)
    ///     .core()
    ///     .run();
    /// ```
    pub fn prove<'a>(&'a self, pk: &'a SP1ProvingKey, stdin: &SP1Stdin) -> CpuProveBuilder<'a> {
        CpuProveBuilder {
            prover: self,
            mode: SP1ProofMode::Core,
            pk,
            stdin: stdin.clone(),
            context_builder: SP1ContextBuilder::default(),
            core_opts: SP1CoreOpts::default(),
            recursion_opts: SP1CoreOpts::recursion(),
            mock: self.mock,
        }
    }

    pub(crate) fn prove_impl<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        opts: SP1ProverOpts,
        context: SP1Context<'a>,
        mode: SP1ProofMode,
    ) -> Result<SP1ProofWithPublicValues> {
        // If we're in mock mode, return a mock proof.
        if self.mock {
            return self.mock_prove_impl(pk, stdin.clone(), mode);
        }

        // Generate the core proof.
        let proof: SP1ProofWithMetadata<SP1CoreProofData> =
            self.prover.prove_core(pk, stdin, opts, context)?;
        if mode == SP1ProofMode::Core {
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
        let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs, opts)?;
        if mode == SP1ProofMode::Compressed {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Compressed(Box::new(reduce_proof)),
                public_values,
                sp1_version: self.version().to_string(),
            });
        }

        // Generate the shrink proof.
        let compress_proof = self.prover.shrink(reduce_proof, opts)?;

        // Generate the wrap proof.
        let outer_proof = self.prover.wrap_bn254(compress_proof, opts)?;

        // Generate the gnark proof.
        match mode {
            SP1ProofMode::Groth16 => {
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
                    public_values,
                    sp1_version: self.version().to_string(),
                });
            }
            SP1ProofMode::Plonk => {
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
                    public_values,
                    sp1_version: self.version().to_string(),
                });
            }
            _ => unreachable!(),
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn mock_prove_impl(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        mode: SP1ProofMode,
    ) -> Result<SP1ProofWithPublicValues> {
        let context = SP1Context::default();
        match mode {
            SP1ProofMode::Core => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;
                Ok(SP1ProofWithPublicValues {
                    proof: SP1Proof::Core(vec![]),
                    public_values,
                    sp1_version: self.version().to_string(),
                })
            }
            SP1ProofMode::Compressed => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;

                let shard_proof = ShardProof {
                    commitment: ShardCommitment {
                        global_main_commit: [BabyBear::zero(); 8].into(),
                        local_main_commit: [BabyBear::zero(); 8].into(),
                        permutation_commit: [BabyBear::zero(); 8].into(),
                        quotient_commit: [BabyBear::zero(); 8].into(),
                    },
                    opened_values: ShardOpenedValues { chips: vec![] },
                    opening_proof: TwoAdicFriPcsProof {
                        fri_proof: FriProof {
                            commit_phase_commits: vec![],
                            query_proofs: vec![],
                            final_poly: BinomialExtensionField::default(),
                            pow_witness: BabyBear::zero(),
                        },
                        query_openings: vec![],
                    },
                    chip_ordering: HashMap::new(),
                    public_values: vec![],
                };

                let reduce_vk = StarkVerifyingKey {
                    commit: [BabyBear::zero(); 8].into(),
                    pc_start: BabyBear::zero(),
                    chip_information: vec![],
                    chip_ordering: HashMap::new(),
                };

                let proof = SP1Proof::Compressed(Box::new(SP1ReduceProof {
                    vk: reduce_vk,
                    proof: shard_proof,
                }));

                Ok(SP1ProofWithPublicValues {
                    proof,
                    public_values,
                    sp1_version: self.version().to_string(),
                })
            }
            SP1ProofMode::Plonk => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;
                Ok(SP1ProofWithPublicValues {
                    proof: SP1Proof::Plonk(PlonkBn254Proof {
                        public_inputs: [
                            pk.vk.hash_bn254().as_canonical_biguint().to_string(),
                            public_values.hash_bn254().to_string(),
                        ],
                        encoded_proof: String::new(),
                        raw_proof: String::new(),
                        plonk_vkey_hash: [0; 32],
                    }),
                    public_values,
                    sp1_version: self.version().to_string(),
                })
            }
            SP1ProofMode::Groth16 => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;
                Ok(SP1ProofWithPublicValues {
                    proof: SP1Proof::Groth16(Groth16Bn254Proof {
                        public_inputs: [
                            pk.vk.hash_bn254().as_canonical_biguint().to_string(),
                            public_values.hash_bn254().to_string(),
                        ],
                        encoded_proof: String::new(),
                        raw_proof: String::new(),
                        groth16_vkey_hash: [0; 32],
                    }),
                    public_values,
                    sp1_version: self.version().to_string(),
                })
            }
        }
    }

    fn mock_verify(
        bundle: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        match &bundle.proof {
            SP1Proof::Plonk(PlonkBn254Proof { public_inputs, .. }) => {
                verify_plonk_bn254_public_inputs(vkey, &bundle.public_values, public_inputs)
                    .map_err(SP1VerificationError::Plonk)
            }
            SP1Proof::Groth16(Groth16Bn254Proof { public_inputs, .. }) => {
                verify_groth16_bn254_public_inputs(vkey, &bundle.public_values, public_inputs)
                    .map_err(SP1VerificationError::Groth16)
            }
            _ => Ok(()),
        }
    }
}

impl Prover<CpuProverComponents> for CpuProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn inner(&self) -> &SP1Prover<CpuProverComponents> {
        &self.prover
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
    ) -> Result<SP1ProofWithPublicValues> {
        self.prove_impl(pk, stdin, SP1ProverOpts::default(), SP1Context::default(), mode)
    }

    fn verify(
        &self,
        bundle: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        if self.mock {
            tracing::warn!("using mock verifier");
            return Self::mock_verify(bundle, vkey);
        }
        verify_proof(self.inner(), self.version(), bundle, vkey)
    }
}

impl Default for CpuProver {
    fn default() -> Self {
        let prover = SP1Prover::new();
        Self { prover, mock: false }
    }
}
