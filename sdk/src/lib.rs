#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
pub mod proto {
    #[rustfmt::skip]
    #[allow(clippy::all)]
    pub mod network;
}
pub mod auth;
pub mod client;
mod io;
mod util;
pub mod utils {
    pub use sp1_core::utils::{
        setup_logger, setup_tracer, BabyBearBlake3, BabyBearKeccak, BabyBearPoseidon2,
    };
}

pub use sp1_core::air::PublicValues;

pub use crate::io::*;
use proto::network::{ProofStatus, TransactionStatus};
use utils::*;

use crate::client::NetworkClient;
use anyhow::{Context, Ok, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sp1_core::runtime::{Program, Runtime};
use sp1_core::stark::{Com, PcsProverData, RiscvAir};
use sp1_core::stark::{
    OpeningProof, ProgramVerificationError, Proof, ShardMainData, StarkGenericConfig,
};
use sp1_core::utils::run_and_prove;
use std::env;
use std::fs;
use std::time::Duration;
use tokio::runtime;
use tokio::time::sleep;
use util::StageProgressBar;

/// A proof of a RISCV ELF execution with given inputs and outputs.
#[derive(Serialize, Deserialize)]
pub struct SP1ProofWithIO<SC: StarkGenericConfig + Serialize + DeserializeOwned> {
    #[serde(with = "proof_serde")]
    pub proof: Proof<SC>,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
}

/// A client that can prove RISCV ELFs and verify those proofs.
pub struct ProverClient {
    /// An optional prover network client used for remote operations.
    pub client: Option<NetworkClient>,
}

impl ProverClient {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let private_key = env::var("PRIVATE_KEY").unwrap_or_default();
        if private_key.is_empty() {
            Self { client: None }
        } else {
            Self {
                client: Some(NetworkClient::new(&private_key)),
            }
        }
    }

    pub fn with_network(mut self, private_key: &str) -> Self {
        self.client = Some(NetworkClient::new(private_key));
        self
    }

    /// Executes the elf with the given inputs and returns the output.
    pub fn execute(elf: &[u8], stdin: SP1Stdin) -> Result<SP1PublicValues> {
        let program = Program::from(elf);
        let mut runtime = Runtime::new(program);
        runtime.write_vecs(&stdin.buffer);
        runtime.run();
        Ok(SP1PublicValues::from(&runtime.state.public_values_stream))
    }

    /// Generate a proof for the execution of the ELF with the given public inputs. If a
    /// NetworkClient is configured, it uses remote proving, otherwise, it proves locally.
    pub fn prove(&self, elf: &[u8], stdin: SP1Stdin) -> Result<SP1ProofWithIO<BabyBearPoseidon2>> {
        if self.client.is_some() {
            println!("Proving remotely");
            self.prove_remote(elf, stdin)
        } else {
            println!("Proving locally");
            self.prove_local(elf, stdin, BabyBearPoseidon2::new())
        }
    }

    pub fn prove_remote(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> Result<SP1ProofWithIO<BabyBearPoseidon2>, anyhow::Error> {
        let rt = runtime::Runtime::new()?;
        rt.block_on(async {
            let client = self
                .client
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Network client not initialized"))?;

            let flat_stdin = stdin
                .buffer
                .iter()
                .flat_map(|v| v.iter())
                .copied()
                .collect::<Vec<u8>>();

            let proof_id = client.create_proof(elf, &flat_stdin).await?;

            let mut pb = StageProgressBar::new();
            loop {
                let (status, maybe_proof) = client
                    .get_proof_status::<BabyBearPoseidon2>(&proof_id)
                    .await?;

                match status.status() {
                    ProofStatus::ProofSucceeded => {
                        println!("Proof succeeded");
                        pb.finish();
                        if let Some(proof) = maybe_proof {
                            return Ok(proof);
                        } else {
                            return Err(anyhow::anyhow!("Proof succeeded but no proof available"));
                        }
                    }
                    ProofStatus::ProofFailed => {
                        pb.finish();
                        return Err(anyhow::anyhow!("Proof generation failed"));
                    }
                    _ => {
                        pb.update(
                            status.stage,
                            status.total_stages,
                            &status.stage_name,
                            status.stage_progress.map(|p| (p, status.stage_total())),
                        );
                        sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        })
    }

    pub fn prove_local<SC: StarkGenericConfig>(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        config: SC,
    ) -> Result<SP1ProofWithIO<SC>>
    where
        SC: StarkGenericConfig,
        SC::Challenger: Clone,
        OpeningProof<SC>: Send + Sync,
        Com<SC>: Send + Sync,
        PcsProverData<SC>: Send + Sync,
        ShardMainData<SC>: Serialize + DeserializeOwned,
        SC::Val: p3_field::PrimeField32,
    {
        let program = Program::from(elf);
        let (proof, public_values_vec) = run_and_prove(program, &stdin.buffer, config);
        let public_values = SP1PublicValues::from(&public_values_vec);
        Ok(SP1ProofWithIO {
            proof,
            stdin,
            public_values,
        })
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
            let client = self
                .client
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Network client not initialized"))?;

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

    pub fn verify(
        &self,
        elf: &[u8],
        proof: &SP1ProofWithIO<BabyBearPoseidon2>,
    ) -> Result<(), ProgramVerificationError> {
        self.verify_with_config(elf, proof, BabyBearPoseidon2::new())
    }

    pub fn verify_with_config<SC: StarkGenericConfig>(
        &self,
        elf: &[u8],
        proof: &SP1ProofWithIO<SC>,
        config: SC,
    ) -> Result<(), ProgramVerificationError>
    where
        SC: StarkGenericConfig,
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
        machine.verify(&vk, &proof.proof, &mut challenger)
    }
}

impl<SC: StarkGenericConfig + Serialize + DeserializeOwned> SP1ProofWithIO<SC> {
    /// Saves the proof as a JSON to the given path.
    pub fn save(&self, path: &str) -> Result<()> {
        let data = serde_json::to_string(self).unwrap();
        fs::write(path, data).unwrap();
        Ok(())
    }
}
