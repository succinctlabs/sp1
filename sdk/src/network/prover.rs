use std::{env, time::Duration};

use crate::proto::network::ProofMode;
use crate::{
    network::client::{NetworkClient, DEFAULT_PROVER_NETWORK_RPC},
    proto::network::{ProofStatus, TransactionStatus},
    Prover,
};
use crate::{SP1CompressedProof, SP1PlonkBn254Proof, SP1Proof, SP1ProvingKey, SP1VerifyingKey};
use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use sp1_prover::install::PLONK_BN254_ARTIFACTS_COMMIT;
use sp1_prover::utils::block_on;
use sp1_prover::{SP1Prover, SP1Stdin};
use tokio::{runtime, time::sleep};

use crate::provers::{LocalProver, ProverType};

/// An implementation of [crate::ProverClient] that can generate proofs on a remote RPC server.
pub struct NetworkProver {
    client: NetworkClient,
    local_prover: LocalProver,
}

impl NetworkProver {
    /// Creates a new [NetworkProver].
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

        let skip_simulation = env::var("SKIP_SIMULATION")
            .map(|val| val == "true")
            .unwrap_or(false);

        if !skip_simulation {
            let (_, report) = SP1Prover::execute(elf, &stdin)?;
            log::info!(
                "Simulation complete, cycles: {}",
                report.total_instruction_count()
            );
        } else {
            log::info!("Skipping simulation");
        }

        let version = PLONK_BN254_ARTIFACTS_COMMIT;
        log::info!("Client version {}", version);

        let proof_id = client.create_proof(elf, &stdin, mode, version).await?;
        log::info!("Created {}", proof_id);

        if NetworkClient::rpc_url() == DEFAULT_PROVER_NETWORK_RPC {
            log::info!(
                "View in explorer: https://explorer.succinct.xyz/{}",
                proof_id.split('_').last().unwrap_or(&proof_id)
            );
        }

        let mut is_claimed = false;
        loop {
            let (status, maybe_proof) = client.get_proof_status::<P>(&proof_id).await?;

            match status.status() {
                ProofStatus::ProofFulfilled => {
                    return Ok(maybe_proof.unwrap());
                }
                ProofStatus::ProofClaimed => {
                    if !is_claimed {
                        log::info!("Proof request claimed, proving...");
                        is_claimed = true;
                    }
                }
                ProofStatus::ProofUnclaimed => {
                    return Err(anyhow::anyhow!(
                        "Proof generation failed: {}",
                        status.unclaim_description()
                    ));
                }
                _ => {}
            }
            sleep(Duration::from_secs(2)).await;
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
}

impl Prover for NetworkProver {
    fn id(&self) -> ProverType {
        ProverType::Network
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.local_prover.setup(elf)
    }

    fn sp1_prover(&self) -> &SP1Prover {
        self.local_prover.sp1_prover()
    }

    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Proof> {
        block_on(self.prove_async(&pk.elf, stdin, ProofMode::Core))
    }

    fn prove_compressed(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CompressedProof> {
        block_on(self.prove_async(&pk.elf, stdin, ProofMode::Compressed))
    }

    fn prove_plonk(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1PlonkBn254Proof> {
        block_on(self.prove_async(&pk.elf, stdin, ProofMode::Plonk))
    }
}

impl Default for NetworkProver {
    fn default() -> Self {
        Self::new()
    }
}
