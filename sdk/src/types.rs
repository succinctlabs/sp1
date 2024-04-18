use std::marker::PhantomData;

use anyhow::Result;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sp1_core::{stark::Proof, utils::BabyBearPoseidon2};
use sp1_prover::{
    ReduceProof, ReduceProofType, SP1CompressedProof, SP1DefaultProof, SP1Groth16Proof,
    SP1ProverImpl,
};

use crate::{proof_serde, SP1PublicValues, SP1Stdin};

#[derive(Serialize, Deserialize)]
pub struct ProofStatistics {
    pub cycle_count: u64,
    pub cost: u64,
    pub total_time: u64,
    pub latency: u64,
}

/// A proof of a RISCV ELF execution with given inputs and outputs.
#[derive(Serialize, Deserialize)]
pub struct SP1ProofWithMetadata<P>
where
    P: Serialize + DeserializeOwned,
{
    #[serde(with = "proof_serde")]
    pub proof: P,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
    // TODO: Add proof statistics at a later point.
    // pub statistics: ProofStatistics,
}

pub enum SP1Proof {
    Mock(SP1ProofWithMetadata<PhantomData<()>>),
    Default(SP1ProofWithMetadata<SP1DefaultProof>),
    Compressed(SP1ProofWithMetadata<SP1CompressedProof>),
    Groth16(SP1ProofWithMetadata<SP1Groth16Proof>),
}

impl<P> SP1ProofWithMetadata<P> {
    pub fn read() -> Self;
    pub fn save(&self) -> Result<()>;

    // Return none if the proof is not of the correct type.
    pub fn as_groth16() -> Option<&SP1Groth16Proof>;
    pub fn as_default() -> Option<&SP1DefaultProof>;
    pub fn as_compressed() -> Option<&SP1CompressedProof>;
    pub fn as_mock() -> Option<&PhantomData>;

    pub fn statistics(&self) -> ProofStatistics {
        unimplemented!()
    }
    pub fn stdin(&self) -> SP1Stdin {
        unimplemented!()
    }
    pub fn public_values(&self) -> SP1PublicValues {
        unimplemented!()
    }
}

// Now we have an enum to deal with provers.

pub enum ProofMode {
    Default,
    Compressed,
    Groth16,
}

pub trait Prover {
    fn prove(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1Proof>;
}

pub struct NetworkProver {
    pub mode: ProofMode,
}

impl NetworkProver {
    pub fn new(mode: ProofMode) -> Self {
        Self { mode }
    }
}

impl Prover for NetworkProver {
    // Depending on the mode, will send a request to the network
    // And will return the correct variant of the SP1Proof
    fn prove(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1Proof> {
        match self.mode {
            ProofMode::Default => {
                let proof = SP1ProverImpl::prove(elf, &stdin.buffer);
                Ok(SP1Proof::Default(SP1ProofWithMetadata {
                    proof,
                    stdin: stdin.clone(),
                    public_values: ProverClient::execute(elf, stdin)?,
                }))
            }
            // TODO: Add this when there's a nice API for local proving to fully recursed.
            ProofMode::Compressed => unimplemented!(),
            // TODO: Add this when there's a nice API for local groth16 proving.
            ProofMode::Groth16 => unimplemented!(),
        }
    }
}

pub struct LocalProver {
    pub mode: ProofMode,
}

impl LocalProver {
    pub fn new(mode: ProofMode) -> Self {
        Self { mode }
    }
}

impl Prover for LocalProver {
    // Depending on the mode, will run the prover locally
    // And will return the correct variant of the SP1Proof
    fn prove(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1Proof> {
        match self.mode {
            ProofMode::Default => {
                let proof = SP1ProverImpl::prove(elf, &stdin.buffer);
                Ok(SP1Proof::Default(SP1ProofWithMetadata {
                    proof,
                    stdin: stdin.clone(),
                    public_values: ProverClient::execute(elf, stdin)?,
                }))
            }
            // TODO: Add this when there's a nice API for local proving to fully recursed.
            ProofMode::Compressed => unimplemented!(),
            // TODO: Add this when there's a nice API for local groth16 proving.
            ProofMode::Groth16 => unimplemented!(),
        }
    }
}

pub struct MockProver {
    pub mode: ProofMode,
}

impl MockProver {
    pub fn new() -> Self {
        Self {
            mode: ProofMode::Default,
        }
    }
}

impl Prover for MockProver {
    fn prove(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1Proof> {
        // Execute the proof to get the public values.
        let public_values = ProverClient::execute(elf, stdin.clone())?;
        let proof_with_metadata = SP1ProofWithMetadata {
            proof: PhantomData::<()>,
            stdin: stdin.clone(),
            public_values,
        };
        Ok(SP1Proof::Mock(proof_with_metadata))
    }
}

pub struct ProverClient {
    pub prover: Box<dyn Prover>,
}

impl ProverClient {
    pub fn new(mode: ProofMode) -> Self {
        // Read environment variables.
        let remote_prove = std::env::var("REMOTE_PROVE")
            .map(|r| r == "true")
            .unwrap_or(false);
        let local_prove = std::env::var("LOCAL_PROVE")
            .map(|r| r == "true")
            .unwrap_or(false);

        let prover: Box<dyn Prover> = if remote_prove {
            Box::new(NetworkProver::new(mode))
        } else if local_prove {
            Box::new(LocalProver::new(mode))
        } else {
            Box::new(MockProver::new())
        };

        Self { prover }
    }

    /// Given an ELF and a SP1Stdin, will execute the program and return the public values.
    pub fn execute(elf: &[u8], stdin: SP1Stdin) -> Result<SP1PublicValues> {
        // Execute is the same for all provers.
        unimplemented!()
    }

    /// Given an ELF and a SP1Stdin, it will generate a proof using the stored prover.
    pub fn prove(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1Proof> {
        // Call prove on the prover.
        self.prover.prove(elf, stdin)
    }

    pub fn prove_from_id(&self, id: &[u8]) -> Result<SP1Proof> {
        // TODO: Implement this when there's a nice API for proving from id (program hash).
        unimplemented!()
    }

    pub fn verify(
        &self,
        elf: &[u8],
        proof: &SP1ProofWithIO<BabyBearPoseidon2>,
    ) -> Result<DeferredDigest, ProgramVerificationError> {
        self.verify_with_config(elf, proof, BabyBearPoseidon2::new())
    }

    pub fn verify_with_config<SC: StarkGenericConfig>(
        &self,
        elf: &[u8],
        proof: &SP1ProofWithIO<SC>,
        config: SC,
    ) -> Result<DeferredDigest, ProgramVerificationError>
    where
        SC::Challenger: Clone,
        OpeningProof<SC>: Send + Sync,
        Com<SC>: Send + Sync,
        PcsProverData<SC>: Send + Sync,
        ShardMainData<SC>: Serialize + DeserializeOwned,
        SC::Val: p3_field::PrimeField32,
    {
        let mut challenger = config.challenger();
        let machine = RiscvAir::machine(config);

        let (_, vk) = machine.setup(&Program::from(elf));
        let (pv_digest, deferred_digest) = machine.verify(&vk, &proof.proof, &mut challenger)?;

        let recomputed_hash = Sha256::digest(&proof.public_values.buffer.data);
        if recomputed_hash.as_slice() != pv_digest.0.as_slice() {
            return Err(ProgramVerificationError::InvalidPublicValuesDigest);
        }

        Result::Ok(deferred_digest)
    }

    pub fn relay() -> Result<()> {
        unimplemented!()
    }

    pub fn get_program_hash(elf: &[u8]) -> bytes32 {}

    /// Gets the Groth16 verification key for the given ELF.
    pub fn get_vkey(elf: &[u8]) -> Vkey {}
}
