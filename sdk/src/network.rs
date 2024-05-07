#![allow(unused_variables)]
use std::{env, time::Duration};

use crate::proto::network::ProofMode;
use crate::{
    client::NetworkClient,
    local::LocalProver,
    proto::network::{ProofStatus, TransactionStatus},
    Prover,
};
use anyhow::{Context, Result};
use futures::Future;
use serde::de::DeserializeOwned;
use sp1_prover::{
    SP1CoreProof, SP1Groth16Proof, SP1PlonkProof, SP1Prover, SP1ProvingKey, SP1ReducedProof,
    SP1Stdin, SP1VerifyingKey,
};
use tokio::runtime::Handle;
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

    pub async fn prove_async<P: DeserializeOwned>(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        mode: ProofMode,
    ) -> Result<P> {
        let client = &self.client;
        // Execute the runtime before creating the proof request.
        // TODO: Maybe we don't want to always do this locally, with large programs. Or we may want
        // to disable events at least.
        let public_values = SP1Prover::execute(elf, &stdin);
        println!("Simulation complete");

        let proof_id = client.create_proof(elf, &stdin, mode).await?;
        println!("Proof request ID: {:?}", proof_id);

        let mut is_claimed = false;
        loop {
            let (status, maybe_proof) = client.get_proof_status::<P>(&proof_id).await?;

            match status.status() {
                ProofStatus::ProofFulfilled => {
                    return Ok(maybe_proof.unwrap());
                }
                ProofStatus::ProofClaimed => {
                    if !is_claimed {
                        println!("Proof request claimed, proving...");
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

    #[allow(dead_code)]
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

    fn block_on<T>(&self, fut: impl Future<Output = T>) -> T {
        // Handle case if we're already in an tokio runtime.
        if let Ok(handle) = Handle::try_current() {
            handle.block_on(fut)
        } else {
            // Otherwise create a new runtime.
            let rt = runtime::Runtime::new().unwrap();
            rt.block_on(fut)
        }
    }
}

impl Prover for NetworkProver {
    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.local_prover.setup(elf)
    }

    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CoreProof> {
        self.block_on(self.prove_async(&pk.elf, stdin, ProofMode::Core))
    }

    fn prove_reduced(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1ReducedProof> {
        if let Ok(handle) = Handle::try_current() {
            handle.block_on(self.prove_async(&pk.elf, stdin, ProofMode::Compressed))
        } else {
            // Otherwise create a new runtime.
            let rt = runtime::Runtime::new().unwrap();
            rt.block_on(async {
                self.prove_async(&pk.elf, stdin, ProofMode::Compressed)
                    .await
            })
        }
    }

    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkProof> {
        self.block_on(self.prove_async(&pk.elf, stdin, ProofMode::Plonk))
    }

    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof> {
        self.block_on(self.prove_async(&pk.elf, stdin, ProofMode::Groth16))
    }

    fn verify(&self, proof: &SP1CoreProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.local_prover.verify(proof, vkey)
    }

    fn verify_reduced(&self, proof: &SP1ReducedProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.local_prover.verify_reduced(proof, vkey)
    }

    fn verify_plonk(&self, proof: &SP1PlonkProof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.local_prover.verify_plonk(proof, vkey)
    }

    fn verify_groth16(&self, proof: &SP1Groth16Proof, vkey: &SP1VerifyingKey) -> Result<()> {
        self.local_prover.verify_groth16(proof, vkey)
    }
}
