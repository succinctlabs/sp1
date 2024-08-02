#![allow(unused_variables)]
use hashbrown::HashMap;

use crate::{
    Prover, SP1Proof, SP1ProofKind, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerificationError,
    SP1VerifyingKey,
};
use anyhow::Result;
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, PrimeField};
use p3_fri::{FriProof, TwoAdicFriPcsProof};
use sp1_core::{
    runtime::SP1Context,
    stark::{ShardCommitment, ShardOpenedValues, ShardProof},
};
use sp1_prover::{
    components::DefaultProverComponents, verify::verify_plonk_bn254_public_inputs, HashableKey,
    PlonkBn254Proof, SP1Prover, SP1Stdin,
};

use super::{ProofOpts, ProverType};

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

impl Prover<DefaultProverComponents> for MockProver {
    fn id(&self) -> ProverType {
        ProverType::Mock
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
        opts: ProofOpts,
        context: SP1Context<'a>,
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
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
                Ok(SP1ProofWithPublicValues {
                    proof: SP1Proof::Compressed(ShardProof {
                        commitment: ShardCommitment {
                            main_commit: [BabyBear::zero(); 8].into(),
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
                    }),
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
        bundle: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        match &bundle.proof {
            SP1Proof::Plonk(PlonkBn254Proof { public_inputs, .. }) => {
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
