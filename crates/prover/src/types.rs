use std::{fs::File, path::Path};

use anyhow::Result;
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
use p3_field::{AbstractField, PrimeField, PrimeField32, TwoAdicField};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sp1_core_machine::{io::SP1Stdin, reduce::SP1ReduceProof};
use sp1_primitives::{io::SP1PublicValues, poseidon2_hash};

use sp1_recursion_circuit::machine::{
    SP1CompressWitnessValues, SP1DeferredWitnessValues, SP1RecursionWitnessValues,
};

use sp1_recursion_gnark_ffi::proof::{Groth16Bn254Proof, PlonkBn254Proof};

use sp1_stark::{ShardProof, StarkGenericConfig, StarkProvingKey, StarkVerifyingKey, DIGEST_SIZE};
use thiserror::Error;

use crate::{
    utils::{babybears_to_bn254, words_to_bytes_be},
    CoreSC, InnerSC,
};

/// The information necessary to generate a proof for a given RISC-V program.
#[derive(Clone, Serialize, Deserialize)]
pub struct SP1ProvingKey {
    pub pk: StarkProvingKey<CoreSC>,
    pub elf: Vec<u8>,
    /// Verifying key is also included as we need it for recursion
    pub vk: SP1VerifyingKey,
}

/// The information necessary to verify a proof for a given RISC-V program.
#[derive(Clone, Serialize, Deserialize)]
pub struct SP1VerifyingKey {
    pub vk: StarkVerifyingKey<CoreSC>,
}

/// A trait for keys that can be hashed into a digest.
pub trait HashableKey {
    /// Hash the key into a digest of BabyBear elements.
    fn hash_babybear(&self) -> [BabyBear; DIGEST_SIZE];

    /// Hash the key into a digest of  u32 elements.
    fn hash_u32(&self) -> [u32; DIGEST_SIZE];

    fn hash_bn254(&self) -> Bn254Fr {
        babybears_to_bn254(&self.hash_babybear())
    }

    fn bytes32(&self) -> String {
        let vkey_digest_bn254 = self.hash_bn254();
        format!("0x{:0>64}", vkey_digest_bn254.as_canonical_biguint().to_str_radix(16))
    }

    /// Hash the key into a digest of bytes elements.
    fn hash_bytes(&self) -> [u8; DIGEST_SIZE * 4] {
        words_to_bytes_be(&self.hash_u32())
    }
}

impl HashableKey for SP1VerifyingKey {
    fn hash_babybear(&self) -> [BabyBear; DIGEST_SIZE] {
        self.vk.hash_babybear()
    }

    fn hash_u32(&self) -> [u32; DIGEST_SIZE] {
        self.vk.hash_u32()
    }
}

impl<SC: StarkGenericConfig<Val = BabyBear, Domain = TwoAdicMultiplicativeCoset<BabyBear>>>
    HashableKey for StarkVerifyingKey<SC>
where
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: AsRef<[BabyBear; DIGEST_SIZE]>,
{
    fn hash_babybear(&self) -> [BabyBear; DIGEST_SIZE] {
        let prep_domains = self.chip_information.iter().map(|(_, domain, _)| domain);
        let num_inputs = DIGEST_SIZE + 1 + (4 * prep_domains.len());
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.commit.as_ref());
        inputs.push(self.pc_start);
        for domain in prep_domains {
            inputs.push(BabyBear::from_canonical_usize(domain.log_n));
            let size = 1 << domain.log_n;
            inputs.push(BabyBear::from_canonical_usize(size));
            let g = BabyBear::two_adic_generator(domain.log_n);
            inputs.push(domain.shift);
            inputs.push(g);
        }

        poseidon2_hash(inputs)
    }

    fn hash_u32(&self) -> [u32; 8] {
        self.hash_babybear()
            .into_iter()
            .map(|n| n.as_canonical_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

/// A proof of a RISCV ELF execution with given inputs and outputs.
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound(serialize = "P: Serialize"))]
#[serde(bound(deserialize = "P: DeserializeOwned"))]
pub struct SP1ProofWithMetadata<P: Clone> {
    pub proof: P,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
    pub cycles: u64,
}

impl<P: Serialize + DeserializeOwned + Clone> SP1ProofWithMetadata<P> {
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        bincode::serialize_into(File::create(path).expect("failed to open file"), self)
            .map_err(Into::into)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        bincode::deserialize_from(File::open(path).expect("failed to open file"))
            .map_err(Into::into)
    }
}

impl<P: std::fmt::Debug + Clone> std::fmt::Debug for SP1ProofWithMetadata<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SP1ProofWithMetadata").field("proof", &self.proof).finish()
    }
}

/// A proof of an SP1 program without any wrapping.
pub type SP1CoreProof = SP1ProofWithMetadata<SP1CoreProofData>;

/// An SP1 proof that has been recursively reduced into a single proof. This proof can be verified
/// within SP1 programs.
pub type SP1ReducedProof = SP1ProofWithMetadata<SP1ReducedProofData>;

/// An SP1 proof that has been wrapped into a single PLONK proof and can be verified onchain.
pub type SP1PlonkBn254Proof = SP1ProofWithMetadata<SP1PlonkBn254ProofData>;

/// An SP1 proof that has been wrapped into a single Groth16 proof and can be verified onchain.
pub type SP1Groth16Bn254Proof = SP1ProofWithMetadata<SP1Groth16Bn254ProofData>;

/// An SP1 proof that has been wrapped into a single proof and can be verified onchain.
pub type SP1Proof = SP1ProofWithMetadata<SP1Bn254ProofData>;

#[derive(Serialize, Deserialize, Clone)]
pub struct SP1CoreProofData(pub Vec<ShardProof<CoreSC>>);

#[derive(Serialize, Deserialize, Clone)]
pub struct SP1ReducedProofData(pub ShardProof<InnerSC>);

#[derive(Serialize, Deserialize, Clone)]
pub struct SP1PlonkBn254ProofData(pub PlonkBn254Proof);

#[derive(Serialize, Deserialize, Clone)]
pub struct SP1Groth16Bn254ProofData(pub Groth16Bn254Proof);

#[derive(Serialize, Deserialize, Clone)]
pub enum SP1Bn254ProofData {
    Plonk(PlonkBn254Proof),
    Groth16(Groth16Bn254Proof),
}

impl SP1Bn254ProofData {
    pub fn get_proof_system(&self) -> ProofSystem {
        match self {
            SP1Bn254ProofData::Plonk(_) => ProofSystem::Plonk,
            SP1Bn254ProofData::Groth16(_) => ProofSystem::Groth16,
        }
    }

    pub fn get_raw_proof(&self) -> &str {
        match self {
            SP1Bn254ProofData::Plonk(proof) => &proof.raw_proof,
            SP1Bn254ProofData::Groth16(proof) => &proof.raw_proof,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSystem {
    Plonk,
    Groth16,
}

impl ProofSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProofSystem::Plonk => "Plonk",
            ProofSystem::Groth16 => "Groth16",
        }
    }
}

/// A proof that can be reduced along with other proofs into one proof.
#[derive(Serialize, Deserialize, Clone)]
pub enum SP1ReduceProofWrapper {
    Core(SP1ReduceProof<CoreSC>),
    Recursive(SP1ReduceProof<InnerSC>),
}

#[derive(Error, Debug)]
pub enum SP1RecursionProverError {
    #[error("Runtime error: {0}")]
    RuntimeError(String),
}

#[allow(clippy::large_enum_variant)]
pub enum SP1CircuitWitness {
    Core(SP1RecursionWitnessValues<CoreSC>),
    Deferred(SP1DeferredWitnessValues<InnerSC>),
    Compress(SP1CompressWitnessValues<InnerSC>),
}
