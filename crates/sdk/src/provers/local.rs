use anyhow::Result;
use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use p3_field::PrimeField;
use p3_fri::{FriProof, TwoAdicFriPcsProof};
use sp1_core_executor::{HookEnv, SP1Context, SP1ContextBuilder, SP1ReduceProof};
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::verify::{verify_groth16_bn254_public_inputs, verify_plonk_bn254_public_inputs};
use sp1_prover::{components::DefaultProverComponents, SP1Prover};
use sp1_prover::{Groth16Bn254Proof, HashableKey, PlonkBn254Proof};
use sp1_stark::{
    SP1CoreOpts, SP1ProverOpts, ShardCommitment, ShardOpenedValues, ShardProof, StarkVerifyingKey,
};

use crate::install::try_install_circuit_artifacts;
use crate::{
    Prover, SP1Proof, SP1ProofKind, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey,
};

use super::verify_proof;
use super::{ProverType, SP1VerificationError};

/// An implementation of [crate::Prover] that can generate end-to-end proofs locally.
pub struct LocalProver {
    prover: SP1Prover<DefaultProverComponents>,
    mock: bool,
}

impl LocalProver {
    /// Creates a new [LocalProver].
    pub fn new(mock: bool) -> Self {
        let prover = SP1Prover::new();
        Self { prover, mock }
    }

    /// Creates a new [LocalProver] from an existing [SP1Prover].
    pub fn from_prover(prover: SP1Prover<DefaultProverComponents>) -> Self {
        Self { prover, mock: false }
    }

    pub(crate) fn prove_impl<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        opts: SP1ProverOpts,
        context: SP1Context<'a>,
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
        if self.mock {
            tracing::info!("Using mock prover");
            return self.mock_proof(&pk, stdin, kind);
        }

        // Generate the core proof.
        let proof: sp1_prover::SP1ProofWithMetadata<sp1_prover::SP1CoreProofData> =
            self.prover.prove_core(pk, &stdin, opts, context)?;
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
        let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs, opts)?;
        if kind == SP1ProofKind::Compressed {
            return Ok(SP1ProofWithPublicValues {
                proof: SP1Proof::Compressed(Box::new(reduce_proof)),
                stdin,
                public_values,
                sp1_version: self.version().to_string(),
            });
        }

        // Generate the shrink proof.
        let compress_proof = self.prover.shrink(reduce_proof, opts)?;

        // Genenerate the wrap proof.

        let outer_proof = self.prover.wrap_bn254(compress_proof, opts)?;
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

    pub fn prove<'a>(
        &'a self,
        pk: &'a SP1ProvingKey,
        stdin: SP1Stdin,
        kind: SP1ProofKind,
    ) -> CpuProve<'a> {
        CpuProve {
            prover: self,
            kind,
            pk,
            stdin,
            context_builder: Default::default(),
            core_opts: SP1CoreOpts::default(),
            recursion_opts: SP1CoreOpts::recursion(),
        }
    }

    fn mock_proof(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
        let context = SP1Context::default();
        match kind {
            SP1ProofKind::Core => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;
                Ok(SP1ProofWithPublicValues {
                    proof: SP1Proof::Core(vec![]),
                    stdin,
                    public_values,
                    sp1_version: self.version().to_string(),
                })
            }
            SP1ProofKind::Compressed => {
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
                            final_poly: Default::default(),
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
                    stdin,
                    public_values,
                    sp1_version: self.version().to_string(),
                })
            }
            SP1ProofKind::Plonk => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;
                Ok(SP1ProofWithPublicValues {
                    proof: SP1Proof::Plonk(PlonkBn254Proof {
                        public_inputs: [
                            pk.vk.hash_bn254().as_canonical_biguint().to_string(),
                            public_values.hash_bn254().to_string(),
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
            SP1ProofKind::Groth16 => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;
                Ok(SP1ProofWithPublicValues {
                    proof: SP1Proof::Groth16(Groth16Bn254Proof {
                        public_inputs: [
                            pk.vk.hash_bn254().as_canonical_biguint().to_string(),
                            public_values.hash_bn254().to_string(),
                        ],
                        encoded_proof: "".to_string(),
                        raw_proof: "".to_string(),
                        groth16_vkey_hash: [0; 32],
                    }),
                    stdin,
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

impl Prover<DefaultProverComponents> for LocalProver {
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
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
        self.prove_impl(pk, stdin, Default::default(), SP1Context::default(), kind)
    }

    fn verify(
        &self,
        bundle: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        if self.mock {
            tracing::warn!("Using mock verifier");
            return Self::mock_verify(bundle, vkey);
        }
        verify_proof(self.sp1_prover(), self.version(), bundle, vkey)
    }
}

impl Default for LocalProver {
    fn default() -> Self {
        Self::new(false)
    }
}

/// Builder to prepare and configure proving execution of a program on an input.
/// May be run with [Self::run].
pub struct CpuProve<'a> {
    prover: &'a LocalProver,
    kind: SP1ProofKind,
    context_builder: SP1ContextBuilder<'a>,
    pk: &'a SP1ProvingKey,
    stdin: SP1Stdin,
    core_opts: SP1CoreOpts,
    recursion_opts: SP1CoreOpts,
}

impl<'a> CpuProve<'a> {
    /// Prove the execution of the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<SP1ProofWithPublicValues> {
        let Self { prover, kind, pk, stdin, mut context_builder, core_opts, recursion_opts } = self;
        let opts = SP1ProverOpts { core_opts, recursion_opts };
        let context = context_builder.build();

        // Dump the program and stdin to files for debugging if `SP1_DUMP` is set.
        if std::env::var("SP1_DUMP")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            let program = pk.elf.clone();
            std::fs::write("program.bin", program).unwrap();
            let stdin = bincode::serialize(&stdin).unwrap();
            std::fs::write("stdin.bin", stdin.clone()).unwrap();
        }

        prover.prove_impl(pk, stdin, opts, context, kind)
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

    /// Add a runtime [Hook](super::Hook) into the context.
    ///
    /// Hooks may be invoked from within SP1 by writing to the specified file descriptor `fd`
    /// with [`sp1_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`sp1_zkvm::io::read`].
    pub fn with_hook(
        mut self,
        fd: u32,
        f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> Self {
        self.context_builder.hook(fd, f);
        self
    }

    /// Avoid registering the default hooks in the runtime.
    ///
    /// It is not necessary to call this to override hooks --- instead, simply
    /// register a hook with the same value of `fd` by calling [`Self::with_hook`].
    pub fn without_default_hooks(mut self) -> Self {
        self.context_builder.without_default_hooks();
        self
    }

    /// Set the shard size for proving.
    pub fn shard_size(mut self, value: usize) -> Self {
        self.core_opts.shard_size = value;
        self
    }

    /// Set the shard batch size for proving.
    pub fn shard_batch_size(mut self, value: usize) -> Self {
        self.core_opts.shard_batch_size = value;
        self
    }

    /// Set whether we should reconstruct commitments while proving.
    pub fn reconstruct_commitments(mut self, value: bool) -> Self {
        self.core_opts.reconstruct_commitments = value;
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    ///
    /// If the cycle limit is exceeded, execution will return
    /// [`sp1_core_executor::ExecutionError::ExceededCycleLimit`].
    pub fn cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.context_builder.max_cycles(cycle_limit);
        self
    }

    /// Set the skip deferred proof verification flag.
    pub fn set_skip_deferred_proof_verification(mut self, value: bool) -> Self {
        self.context_builder.set_skip_deferred_proof_verification(value);
        self
    }
}
