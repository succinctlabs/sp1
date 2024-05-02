#![allow(unused_variables)]
use std::{env, time::Duration};

use crate::{
    client::NetworkClient,
    local::LocalProver,
    proto::network::{ProofStatus, TransactionStatus},
    Prover, SP1Groth16ProofData, SP1PlonkProofData, SP1ProofWithMetadata, SP1ProvingKey,
    SP1VerifyingKey,
};
use anyhow::{Context, Result};
use sp1_prover::{SP1CoreProof, SP1Prover, SP1Stdin};
use tokio::{runtime, time::sleep};

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

    pub async fn prove_async(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1CoreProof> {
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
                        proof: maybe_proof.unwrap().0,
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
    pub fn _remote_relay(
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

    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProofData> {
        todo!()
    }

    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16ProofData> {
        todo!()
    }

    fn verify(&self, proof: &SP1DefaultProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.local_prover.verify(proof, vkey)
    }

    fn verify_compressed(&self, proof: &SP1CompressedProof, vkey: &SP1VerifyingKey) -> Result<()> {
        todo!()
    }

    fn verify_plonk(&self, proof: &SP1PlonkProofData, vkey: &SP1VerifyingKey) -> Result<()> {
        todo!()
    }

    fn verify_groth16(&self, proof: &SP1Groth16ProofData, vkey: &SP1VerifyingKey) -> Result<()> {
        todo!()
    }
}
