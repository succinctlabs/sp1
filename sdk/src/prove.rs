#![allow(unused_variables)]

use std::{
    env,
    fs::File,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use p3_field::PrimeField32;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_core::stark::{MachineProof, ShardProof};
use sp1_core::{air::PublicValues, stark::StarkGenericConfig};
use sp1_prover::{
    CoreSC, Groth16Proof, InnerSC, PlonkBn254Proof, SP1Prover, SP1ProvingKey, SP1VerifyingKey,
};
use tokio::{runtime, time::sleep};

use crate::{
    client::NetworkClient,
    proto::network::{ProofStatus, TransactionStatus},
    SP1PublicValues, SP1Stdin,
};

#[derive(Serialize, Deserialize)]
pub struct ProofStatistics {
    pub cycle_count: u64,
    pub cost: u64,
    pub total_time: u64,
    pub latency: u64,
}

/// A proof of a RISCV ELF execution with given inputs and outputs.
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "P: Serialize"))]
#[serde(bound(deserialize = "P: DeserializeOwned"))]
pub struct SP1ProofWithMetadata<P> {
    pub proof: P,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
}

impl<P: Serialize + DeserializeOwned> SP1ProofWithMetadata<P> {
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        bincode::serialize_into(File::create(path).expect("failed to open file"), self)
            .map_err(Into::into)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        bincode::deserialize_from(File::open(path).expect("failed to open file"))
            .map_err(Into::into)
    }
}

impl<P: std::fmt::Debug> std::fmt::Debug for SP1ProofWithMetadata<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SP1ProofWithMetadata")
            .field("proof", &self.proof)
            .finish()
    }
}

pub type SP1DefaultProof = SP1ProofWithMetadata<Vec<ShardProof<CoreSC>>>;

pub type SP1CompressedProof = SP1ProofWithMetadata<ShardProof<InnerSC>>;

pub type SP1PlonkProof = SP1ProofWithMetadata<PlonkBn254Proof>;

pub type SP1Groth16Proof = SP1ProofWithMetadata<Groth16Proof>;

pub trait Prover: Send + Sync {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey);

    /// Prove the execution of a RISCV ELF with the given inputs.
    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1DefaultProof>;

    /// Generate a compressed proof of the execution of a RISCV ELF with the given inputs.
    fn prove_compressed(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CompressedProof>;

    /// Given an SP1 program and input, generate a PLONK proof that can be verified on-chain.
    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof>;

    /// Given an SP1 program and input, generate a Groth16 proof that can be verified on-chain.
    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof>;

    /// Verify that an SP1 proof is valid given its vkey and metadata.
    fn verify(&self, proof: &SP1DefaultProof, vkey: &SP1VerifyingKey) -> Result<()>;

    /// Verify that a compressed SP1 proof is valid given its vkey and metadata.
    fn verify_compressed(&self, proof: &SP1CompressedProof, vkey: &SP1VerifyingKey) -> Result<()>;

    /// Verify that a SP1 PLONK proof is valid given its vkey and metadata.
    fn verify_plonk(&self, proof: &SP1PlonkProof, vkey: &SP1VerifyingKey) -> Result<()>;

    /// Verify that a SP1 Groth16 proof is valid given its vkey and metadata.
    fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()>;
}

pub struct LocalProver {
    pub(crate) prover: SP1Prover,
}

impl Default for LocalProver {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalProver {
    pub fn new() -> Self {
        let prover = SP1Prover::new();
        Self { prover }
    }

    /// Get artifacts dir from SP1_CIRCUIT_DIR env var.
    fn get_artifacts_dir(&self) -> PathBuf {
        let artifacts_dir =
            std::env::var("SP1_CIRCUIT_DIR").expect("SP1_CIRCUIT_DIR env var not set");
        PathBuf::from(artifacts_dir)
    }
}

impl Prover for LocalProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1DefaultProof> {
        let proof = self.prover.prove_core(pk, &stdin);
        Ok(SP1ProofWithMetadata {
            proof: proof.shard_proofs,
            stdin: proof.stdin,
            public_values: proof.public_values,
        })
    }

    fn prove_compressed(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CompressedProof> {
        let proof = self.prover.prove_core(pk, &stdin);
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.reduce(&pk.vk, proof, deferred_proofs);
        Ok(SP1CompressedProof {
            proof: reduce_proof.proof,
            stdin,
            public_values,
        })
    }

    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof> {
        let artifacts_dir = self.get_artifacts_dir();
        let proof = self.prover.prove_core(pk, &stdin);
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.reduce(&pk.vk, proof, deferred_proofs);
        let outer_proof = self.prover.wrap_bn254(&pk.vk, reduce_proof);
        let proof = self.prover.wrap_groth16(outer_proof, artifacts_dir);
        Ok(SP1ProofWithMetadata {
            proof,
            stdin,
            public_values,
        })
    }

    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof> {
        let artifacts_dir = self.get_artifacts_dir();
        let proof = self.prover.prove_core(pk, &stdin);
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.reduce(&pk.vk, proof, deferred_proofs);
        let outer_proof = self.prover.wrap_bn254(&pk.vk, reduce_proof);
        let proof = self.prover.wrap_plonk(outer_proof, artifacts_dir);
        Ok(SP1ProofWithMetadata {
            proof,
            stdin,
            public_values,
        })
    }

    fn verify(&self, proof: &SP1DefaultProof, vkey: &SP1VerifyingKey) -> Result<()> {
        let pv = PublicValues::from_vec(proof.proof[0].public_values.clone());
        let pv_digest: [u8; 32] = Sha256::digest(&proof.public_values.buffer.data).into();
        if pv_digest != *pv.commit_digest_bytes() {
            return Err(anyhow::anyhow!("Public values digest mismatch"));
        }
        let machine_proof = MachineProof {
            shard_proofs: proof.proof.clone(),
        };
        let mut challenger = self.prover.core_machine.config().challenger();
        Ok(self
            .prover
            .core_machine
            .verify(&vkey.vk, &machine_proof, &mut challenger)?)
    }

    fn verify_compressed(&self, proof: &SP1CompressedProof, vkey: &SP1VerifyingKey) -> Result<()> {
        todo!()
    }

    fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()> {
        todo!()
    }

    fn verify_plonk(&self, proof: &SP1PlonkProof, vkey: &SP1VerifyingKey) -> Result<()> {
        todo!()
    }
}

pub struct MockProver {
    pub(crate) prover: SP1Prover,
}

#[derive(Clone)]
pub enum MockProofCode {
    Default = 0,
    Compressed = 1,
    Groth16 = 2,
    Plonk = 3,
}

pub type MockProof = [u8; 32];

impl Default for MockProver {
    fn default() -> Self {
        Self::new()
    }
}

impl MockProver {
    pub fn new() -> Self {
        let prover = SP1Prover::new();
        Self { prover }
    }

    pub fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    /// Returns the vkey digest for the given ELF.
    pub fn get_vk_digest(&self, elf: &[u8]) -> Vec<u8> {
        let (_, vkey) = self.prover.setup(elf);
        vkey.hash()
            .into_iter()
            .flat_map(|b| b.as_canonical_u32().to_le_bytes())
            .collect::<Vec<_>>()
    }

    /// Executes the program and returns vkey_digest and public values.
    fn execute(&self, elf: &[u8], stdin: &SP1Stdin) -> (Vec<u8>, SP1PublicValues) {
        let (_, vkey) = self.prover.setup(elf);
        let vkey_digest = self.get_vk_digest(elf);
        let public_values = SP1Prover::execute(elf, stdin);
        (vkey_digest, public_values)
    }

    /// Generates a mock proof which is sha256( code || vkey_digest || public_values ).
    fn mock_proof(
        &self,
        code: MockProofCode,
        vkey_digest: &[u8],
        public_values: &[u8],
    ) -> MockProof {
        let mut hasher_input = Vec::new();
        hasher_input.push(code as u8);
        hasher_input.extend_from_slice(vkey_digest);
        hasher_input.extend_from_slice(public_values);
        Sha256::digest(&hasher_input).into()
    }

    pub fn prove(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1ProofWithMetadata<MockProof>> {
        let (vkey_digest, public_values) = self.execute(elf, &stdin);
        let proof = self.mock_proof(
            MockProofCode::Default,
            &vkey_digest,
            &public_values.buffer.data,
        );
        Ok(SP1ProofWithMetadata {
            proof,
            stdin,
            public_values,
        })
    }

    pub fn prove_compressed(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> Result<SP1ProofWithMetadata<MockProof>> {
        // TODO: we could check that deferred proofs are correct here.
        let (vkey_digest, public_values) = self.execute(elf, &stdin);
        let proof = self.mock_proof(
            MockProofCode::Compressed,
            &vkey_digest,
            &public_values.buffer.data,
        );
        Ok(SP1ProofWithMetadata {
            proof,
            stdin,
            public_values,
        })
    }

    pub fn prove_groth16(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> Result<SP1ProofWithMetadata<MockProof>> {
        let (vkey_digest, public_values) = self.execute(elf, &stdin);
        let proof = self.mock_proof(
            MockProofCode::Groth16,
            &vkey_digest,
            &public_values.buffer.data,
        );
        Ok(SP1ProofWithMetadata {
            proof,
            stdin,
            public_values,
        })
    }

    pub fn prove_plonk(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> Result<SP1ProofWithMetadata<MockProof>> {
        let (vkey_digest, public_values) = self.execute(elf, &stdin);
        let proof = self.mock_proof(
            MockProofCode::Plonk,
            &vkey_digest,
            &public_values.buffer.data,
        );
        Ok(SP1ProofWithMetadata {
            proof,
            stdin,
            public_values,
        })
    }
}

pub struct NetworkProver {
    client: NetworkClient,
    local_prover: LocalProver,
}

impl Default for NetworkProver {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkProver {
    pub fn new() -> Self {
        let private_key = env::var("SP1_PRIVATE_KEY")
            .unwrap_or_else(|_| panic!("SP1_PRIVATE_KEY must be set for remote proving"));
        let local_prover = LocalProver::new();
        Self {
            client: NetworkClient::new(&private_key),
            local_prover,
        }
    }

    pub async fn prove_async(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1DefaultProof> {
        let client = &self.client;
        // Execute the runtime before creating the proof request.
        // TODO: Maybe we don't want to always do this locally, with large programs. Or we may want
        // to disable events at least.
        let public_values = SP1Prover::execute(elf, &stdin);
        println!("Simulation complete");

        let proof_id = client.create_proof(elf, &stdin).await?;
        println!("Proof request ID: {:?}", proof_id);

        let mut is_claimed = false;
        loop {
            let (status, maybe_proof) = client.get_proof_status(&proof_id).await?;

            match status.status() {
                ProofStatus::ProofFulfilled => {
                    return Ok(SP1ProofWithMetadata {
                        proof: maybe_proof.unwrap().shard_proofs,
                        stdin,
                        public_values,
                    });
                }
                ProofStatus::ProofClaimed => {
                    if !is_claimed {
                        println!("Proving...");
                        is_claimed = true;
                    }
                }
                ProofStatus::ProofFailed => {
                    return Err(anyhow::anyhow!("Proof generation failed"));
                }
                _ => {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Remotely relay a proof to a set of chains with their callback contracts.
    pub fn remote_relay(
        &self,
        proof_id: &str,
        chain_ids: Vec<u32>,
        callbacks: Vec<[u8; 20]>,
        callback_datas: Vec<Vec<u8>>,
    ) -> Result<Vec<String>> {
        let rt = runtime::Runtime::new()?;
        rt.block_on(async {
            let client = &self.client;

            let verifier = NetworkClient::get_sp1_verifier_address();

            let mut tx_details = Vec::new();
            for ((i, callback), callback_data) in
                callbacks.iter().enumerate().zip(callback_datas.iter())
            {
                if let Some(&chain_id) = chain_ids.get(i) {
                    let tx_id = client
                        .relay_proof(proof_id, chain_id, verifier, *callback, callback_data)
                        .await
                        .with_context(|| format!("Failed to relay proof to chain {}", chain_id))?;
                    tx_details.push((tx_id.clone(), chain_id));
                }
            }

            let mut tx_ids = Vec::new();
            for (tx_id, chain_id) in tx_details.iter() {
                loop {
                    let (status_res, maybe_tx_hash, maybe_simulation_url) =
                        client.get_relay_status(tx_id).await?;

                    match status_res.status() {
                        TransactionStatus::TransactionFinalized => {
                            println!(
                                "Relaying to chain {} succeeded with tx hash: {:?}",
                                chain_id,
                                maybe_tx_hash.as_deref().unwrap_or("None")
                            );
                            tx_ids.push(tx_id.clone());
                            break;
                        }
                        TransactionStatus::TransactionFailed
                        | TransactionStatus::TransactionTimedout => {
                            return Err(anyhow::anyhow!(
                                "Relaying to chain {} failed with tx hash: {:?}, simulation url: {:?}",
                                chain_id,
                                maybe_tx_hash.as_deref().unwrap_or("None"),
                                maybe_simulation_url.as_deref().unwrap_or("None")
                            ));
                        }
                        _ => {
                            sleep(Duration::from_secs(5)).await;
                        }
                    }
                }
            }

            Ok(tx_ids)
        })
    }
}

impl Prover for NetworkProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.local_prover.setup(elf)
    }

    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1DefaultProof> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async { self.prove_async(&pk.elf, stdin).await })
    }

    fn prove_compressed(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CompressedProof> {
        todo!()
    }

    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof> {
        todo!()
    }

    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof> {
        todo!()
    }

    fn verify(&self, proof: &SP1DefaultProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.local_prover.verify(proof, vkey)
    }

    fn verify_compressed(&self, proof: &SP1CompressedProof, vkey: &SP1VerifyingKey) -> Result<()> {
        todo!()
    }

    fn verify_plonk(&self, proof: &SP1PlonkProof, vkey: &SP1VerifyingKey) -> Result<()> {
        todo!()
    }

    fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()> {
        todo!()
    }
}
