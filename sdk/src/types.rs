use std::marker::PhantomData;

use anyhow::Result;
use p3_field::PrimeField32;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_core::{
    stark::ShardProof,
    utils::{BabyBearPoseidon2, BabyBearPoseidon2Inner},
};
use sp1_prover::{CoreSC, InnerSC, OuterSC, SP1CoreProof, SP1Prover, SP1ReduceProof};

use crate::{SP1PublicValues, SP1Stdin};

#[derive(Serialize, Deserialize)]
pub struct ProofStatistics {
    pub cycle_count: u64,
    pub cost: u64,
    pub total_time: u64,
    pub latency: u64,
}

/// A proof of a RISCV ELF execution with given inputs and outputs.
// #[derive(Serialize, Deserialize)]
pub struct SP1ProofWithMetadata<P>
where
    P: Serialize + DeserializeOwned,
{
    pub proof: P,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
}

pub type SP1CompressedProof = SP1ProofWithMetadata<ShardProof<InnerSC>>;

pub type SP1DefaultProof = SP1ProofWithMetadata<ShardProof<CoreSC>>;

pub trait Prover {
    type DefaultProof: Serialize + DeserializeOwned;

    type CompressedProof: Serialize + DeserializeOwned;

    type PlonkProof: Serialize + DeserializeOwned;

    fn prove(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> Result<SP1ProofWithMetadata<Self::DefaultProof>>;

    fn prove_compressed(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> Result<SP1ProofWithMetadata<Self::CompressedProof>>;

    // fn prove_plonk(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1ProofWIthMetadata<Self::PlonkProof>>;
}

pub struct LocalProver {
    pub(crate) prover: SP1Prover,
}

impl Prover for LocalProver {
    type DefaultProof = Vec<ShardProof<CoreSC>>;

    type CompressedProof = ShardProof<InnerSC>;

    type PlonkProof = ShardProof<OuterSC>; //TODO

    fn prove(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> Result<SP1ProofWithMetadata<Vec<ShardProof<CoreSC>>>> {
        let (pk, _) = self.prover.setup(elf);
        let proof = self.prover.prove_core(&pk, &stdin);
        Ok(SP1ProofWithMetadata {
            proof: proof.shard_proofs,
            stdin: proof.stdin,
            public_values: proof.public_values,
        })
    }

    fn prove_compressed(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1CompressedProof> {
        let (pk, vk) = self.prover.setup(elf);
        let proof = self.prover.prove_core(&pk, &stdin);
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.reduce(&vk, proof, deferred_proofs);
        Ok(SP1CompressedProof {
            proof: reduce_proof.proof,
            stdin,
            public_values,
        })
    }
}

pub struct MockProver {
    pub(crate) prover: SP1Prover,
}

enum MockProofCode {
    Default = 0,
    Compressed = 1,
    Plonk = 2,
}

impl Prover for MockProver {
    type DefaultProof = [u8; 32];

    type CompressedProof = [u8; 32];

    type PlonkProof = [u8; 32];

    fn prove(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1ProofWithMetadata<[u8; 32]>> {
        let (_, vkey) = self.prover.setup(elf);
        let vkey_digest = self
            .prover
            .hash_vkey(&vkey.vk)
            .into_iter()
            .flat_map(|b| b.as_canonical_u32().to_le_bytes())
            .collect::<Vec<_>>();
        let mut hasher_input = Vec::new();
        hasher_input.push(MockProofCode::Default as u8);
        hasher_input.extend_from_slice(&vkey_digest);
        let public_values = SP1Prover::execute(elf, &stdin);
        hasher_input.extend_from_slice(&stdin.buffer.iter().flatten().cloned().collect::<Vec<_>>());
        let proof = Sha256::digest(&hasher_input).into();
        Ok(SP1ProofWithMetadata {
            proof,
            stdin,
            public_values,
        })
    }

    fn prove_compressed(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> Result<SP1ProofWithMetadata<Self::CompressedProof>> {
        let (_, vkey) = self.prover.setup(elf);
        let vkey_digest = self
            .prover
            .hash_vkey(&vkey.vk)
            .into_iter()
            .flat_map(|b| b.as_canonical_u32().to_le_bytes())
            .collect::<Vec<_>>();
        let mut hasher_input = Vec::new();
        hasher_input.push(MockProofCode::Compressed as u8);
        hasher_input.extend_from_slice(&vkey_digest);
        // TODO: we could check that deferred proofs are correct here.
        let public_values = SP1Prover::execute(elf, &stdin);
        hasher_input.extend_from_slice(&stdin.buffer.iter().flatten().cloned().collect::<Vec<_>>());
        let proof = Sha256::digest(&hasher_input).into();
        Ok(SP1ProofWithMetadata {
            proof,
            stdin,
            public_values,
        })
    }
}

pub struct NetworkProver {}

impl Prover for NetworkProver {}

// pub struct LocalProver {
//     pub mode: ProofMode,
// }

// impl LocalProver {
//     pub fn new(mode: ProofMode) -> Self {
//         Self { mode }
//     }
// }

// impl Prover for LocalProver {
//     // Depending on the mode, will run the prover locally
//     // And will return the correct variant of the SP1Proof
//     fn prove(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1Proof> {
//         match self.mode {
//             ProofMode::Default => {
//                 let proof = SP1Prover::prove(elf, &stdin.buffer);
//                 Ok(SP1Proof::Default(SP1ProofWithMetadata {
//                     proof,
//                     stdin: stdin.clone(),
//                     public_values: ProverClient::execute(elf, stdin)?,
//                 }))
//             }
//             // TODO: Add this when there's a nice API for local proving to fully recursed.
//             ProofMode::Compressed => unimplemented!(),
//             // TODO: Add this when there's a nice API for local groth16 proving.
//             ProofMode::Groth16 => unimplemented!(),
//         }
//     }
// }

// pub struct MockProver {
//     pub mode: ProofMode,
// }

// impl MockProver {
//     pub fn new() -> Self {
//         Self {
//             mode: ProofMode::Default,
//         }
//     }
// }

// impl Prover for MockProver {
//     fn prove(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1Proof> {
//         // Execute the proof to get the public values.
//         let public_values = ProverClient::execute(elf, stdin.clone())?;
//         let proof_with_metadata = SP1ProofWithMetadata {
//             proof: PhantomData::<()>,
//             stdin: stdin.clone(),
//             public_values,
//         };
//         Ok(SP1Proof::Mock(proof_with_metadata))
//     }
// }

// pub struct ProverClient {
//     pub prover: Box<dyn Prover>,
// }

// /// Initialize a ProverClient with a mode: {Default, Compressed, Groth16} and it will generate the
// /// corresponding proof. Additionally, a ProverClient will
// impl ProverClient {
//     pub fn new(mode: ProofMode) -> Self {
//         // Read environment variables.
//         let remote_prove = std::env::var("REMOTE_PROVE")
//             .map(|r| r == "true")
//             .unwrap_or(false);
//         let local_prove = std::env::var("LOCAL_PROVE")
//             .map(|r| r == "true")
//             .unwrap_or(false);

//         let prover: Box<dyn Prover> = if remote_prove {
//             Box::new(NetworkProver::new(mode))
//         } else if local_prove {
//             Box::new(LocalProver::new(mode))
//         } else {
//             Box::new(MockProver::new())
//         };

//         Self { prover }
//     }

//     /// Given an ELF and a SP1Stdin, will execute the program and return the public values.
//     pub fn execute(elf: &[u8], stdin: SP1Stdin) -> Result<SP1PublicValues> {
//         // Execute is the same for all provers.
//         unimplemented!()
//     }

//     /// Given an ELF and a SP1Stdin, it will generate a proof using the stored prover.
//     pub fn prove(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1Proof> {
//         // Call prove on the prover.
//         self.prover.prove(elf, stdin)
//     }

//     pub fn prove_from_id(&self, id: &[u8]) -> Result<SP1Proof> {
//         // TODO: Implement this when there's a nice API for proving from id (program hash).
//         unimplemented!()
//     }

//     pub fn verify_groth16(
//         &self,
//         elf: &[u8],
//         proof: &SP1ProofWithIO<BabyBearPoseidon2>,
//     ) -> Result<DeferredDigest, ProgramVerificationError> {
//         self.verify_with_config(elf, proof, BabyBearPoseidon2::new())
//     }

//     pub fn verify_<SC: StarkGenericConfig>(
//         &self,
//         elf: &[u8],
//         proof: &SP1ProofWithIO<SC>,
//         config: SC,
//     ) -> Result<DeferredDigest, ProgramVerificationError>
//     where
//         SC::Challenger: Clone,
//         OpeningProof<SC>: Send + Sync,
//         Com<SC>: Send + Sync,
//         PcsProverData<SC>: Send + Sync,
//         ShardMainData<SC>: Serialize + DeserializeOwned,
//         SC::Val: p3_field::PrimeField32,
//     {
//         let mut challenger = config.challenger();
//         let machine = RiscvAir::machine(config);

//         let (_, vk) = machine.setup(&Program::from(elf));
//         let (pv_digest, deferred_digest) = machine.verify(&vk, &proof.proof, &mut challenger)?;

//         let recomputed_hash = Sha256::digest(&proof.public_values.buffer.data);
//         if recomputed_hash.as_slice() != pv_digest.0.as_slice() {
//             return Err(ProgramVerificationError::InvalidPublicValuesDigest);
//         }

//         Result::Ok(deferred_digest)
//     }

//     pub fn relay() -> Result<()> {
//         unimplemented!()
//     }

//     pub fn get_program_hash(elf: &[u8]) -> bytes32 {}

//     /// Gets the Groth16 verification key for the given ELF.
//     pub fn get_vkey(elf: &[u8]) -> VerificationKey {
//         // TODO: We should return the Groth16 verification key here.
//         unimplemented!()
//     }
// }
