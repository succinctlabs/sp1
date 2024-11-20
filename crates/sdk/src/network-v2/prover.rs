use std::time::{Duration, Instant};

use crate::{
    network_v2::client::NetworkClient,
    network_v2::proto::network::{ProofMode, ProofStatus, ProofStrategy},
    NetworkProverBuilder, Prover, SP1Context, SP1ProofKind, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1VerifyingKey,
};
use anyhow::Result;
use backoff::{future::retry, ExponentialBackoff};
use serde::de::DeserializeOwned;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{components::DefaultProverComponents, SP1Prover, SP1_CIRCUIT_VERSION};
use sp1_stark::SP1ProverOpts;
use tonic::Code;

use {crate::block_on, tokio::time::sleep};

use crate::provers::{CpuProver, ProofOpts, ProverType};

/// The timeout for a proof request to be fulfilled.
const TIMEOUT_SECS: u64 = 14400;

/// The default cycle limit for a proof request if simulation is skipped.
const DEFAULT_CYCLE_LIMIT: u64 = 100_000_000;

/// An implementation of [crate::ProverClient] that can generate proofs on a remote RPC server.
pub struct NetworkProver {
    client: NetworkClient,
    local_prover: CpuProver,
    skip_simulation: bool,
}

impl NetworkProver {
    /// Creates a new [NetworkProver] with the given private key.
    pub fn new(private_key: &str, rpc_url: Option<String>, skip_simulation: bool) -> Self {
        let version = SP1_CIRCUIT_VERSION;
        log::info!("Client circuit version: {}", version);
        let local_prover = CpuProver::new();
        let client = NetworkClient::new(private_key, rpc_url);
        Self { client, local_prover, skip_simulation }
    }

    /// Creates a new network prover builder. See [`NetworkProverBuilder`] for more details.
    pub fn builder() -> NetworkProverBuilder {
        NetworkProverBuilder::default()
    }

    /// Requests a proof from the prover network, returning the request ID.
    pub async fn request_proof(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        mode: ProofMode,
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>> {
        // Simulate and get the cycle limit.
        let cycle_limit = if !self.skip_simulation {
            let (_, report) =
                self.local_prover.sp1_prover().execute(elf, &stdin, Default::default())?;
            let cycles = report.total_instruction_count();
            log::info!("Simulation complete, cycles: {}", cycles);
            cycles
        } else {
            log::info!("Skipping simulation");
            DEFAULT_CYCLE_LIMIT
        };

        // Get the verifying key.
        let (_, vk) = self.setup(elf);

        // Get the timeout.
        let timeout_secs = timeout.map(|dur| dur.as_secs()).unwrap_or(TIMEOUT_SECS);

        log::info!("Requesting proof with cycle limit: {}", cycle_limit);

        // Request the proof.
        let response = self
            .client
            .request_proof(
                elf,
                &stdin,
                &vk,
                mode,
                SP1_CIRCUIT_VERSION,
                ProofStrategy::Hosted,
                timeout_secs,
                cycle_limit,
            )
            .await?;

        // Log the request ID and transaction hash.
        let tx_hash_hex = "0x".to_string() + &hex::encode(response.tx_hash);
        let request_id = response.body.unwrap().request_id;
        let request_id_hex = "0x".to_string() + &hex::encode(request_id.clone());
        log::info!("Created request {} in transaction {}", request_id_hex, tx_hash_hex);

        Ok(request_id)
    }

    /// Waits for a proof to be generated and returns the proof. If a timeout is supplied, the
    /// function will return an error if the proof is not generated within the timeout.
    pub async fn wait_proof<P: DeserializeOwned>(
        &self,
        request_id: &[u8],
        timeout: Option<Duration>,
    ) -> Result<P> {
        let mut is_assigned = false;
        let start_time = Instant::now();

        // Configure retries with exponential backoff.
        let backoff = ExponentialBackoff {
            initial_interval: Duration::from_secs(1),
            max_interval: Duration::from_secs(30),
            max_elapsed_time: timeout,
            ..Default::default()
        };

        loop {
            if let Some(timeout) = timeout {
                if start_time.elapsed() > timeout {
                    return Err(anyhow::anyhow!("Proof request timed out."));
                }
            }

            // Try to get proof status with retries.
            let status_result = retry(backoff.clone(), || async {
                match self.client.get_proof_request_status::<P>(request_id).await {
                    Ok(result) => Ok(result),
                    Err(e) => {
                        if let Some(status) = e.downcast_ref::<tonic::Status>() {
                            match status.code() {
                                Code::NotFound => {
                                    log::error!("Proof request not found: {}", status.message());
                                    Err(backoff::Error::permanent(e))
                                }
                                Code::Unavailable => {
                                    log::warn!(
                                        "Network temporarily unavailable, retrying: {}",
                                        status.message()
                                    );
                                    Err(backoff::Error::transient(e))
                                }
                                Code::DeadlineExceeded => {
                                    log::warn!(
                                        "Request deadline exceeded, retrying: {}",
                                        status.message()
                                    );
                                    Err(backoff::Error::transient(e))
                                }
                                _ => {
                                    log::error!(
                                        "Permanent error encountered: {} ({})",
                                        status.message(),
                                        status.code()
                                    );
                                    Err(backoff::Error::permanent(e))
                                }
                            }
                        } else {
                            log::error!("Unexpected error type: {}", e);
                            Err(backoff::Error::permanent(e))
                        }
                    }
                }
            })
            .await;

            match status_result {
                Ok((status, maybe_proof)) => match status.proof_status() {
                    ProofStatus::Fulfilled => {
                        return Ok(maybe_proof.unwrap());
                    }
                    ProofStatus::Assigned => {
                        if !is_assigned {
                            log::info!("Proof request assigned, proving...");
                            is_assigned = true;
                        }
                    }
                    _ => {}
                },
                Err(e) => {
                    return Err(e);
                }
            }

            sleep(Duration::from_secs(2)).await;
        }
    }

    /// Requests a proof from the prover network and waits for it to be generated.
    pub async fn prove(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        mode: ProofMode,
        timeout: Option<Duration>,
    ) -> Result<SP1ProofWithPublicValues> {
        let request_id = self.request_proof(elf, stdin, mode, timeout).await?;
        self.wait_proof(&request_id, timeout).await
    }
}

impl Prover<DefaultProverComponents> for NetworkProver {
    fn id(&self) -> ProverType {
        ProverType::Network
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.local_prover.setup(elf)
    }

    fn sp1_prover(&self) -> &SP1Prover {
        self.local_prover.sp1_prover()
    }

    fn prove<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        opts: ProofOpts,
        context: SP1Context<'a>,
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
        warn_if_not_default(&opts.sp1_prover_opts, &context);
        block_on(self.prove(&pk.elf, stdin, kind.into(), opts.timeout))
    }
}

/// Warns if `opts` or `context` are not default values, since they are currently unsupported.
fn warn_if_not_default(opts: &SP1ProverOpts, context: &SP1Context) {
    let _guard = tracing::warn_span!("network_prover").entered();
    if opts != &SP1ProverOpts::default() {
        tracing::warn!("non-default opts will be ignored: {:?}", opts.core_opts);
        tracing::warn!("custom SP1ProverOpts are currently unsupported by the network prover");
    }
    // Exhaustive match is done to ensure we update the warnings if the types change.
    let SP1Context { hook_registry, subproof_verifier, .. } = context;
    if hook_registry.is_some() {
        tracing::warn!("non-default context.hook_registry will be ignored: {:?}", hook_registry);
        tracing::warn!("custom runtime hooks are currently unsupported by the network prover");
        tracing::warn!("proving may fail due to missing hooks");
    }
    if subproof_verifier.is_some() {
        tracing::warn!("non-default context.subproof_verifier will be ignored");
        tracing::warn!("custom subproof verifiers are currently unsupported by the network prover");
    }
}

impl From<SP1ProofKind> for ProofMode {
    fn from(value: SP1ProofKind) -> Self {
        match value {
            SP1ProofKind::Core => Self::Core,
            SP1ProofKind::Compressed => Self::Compressed,
            SP1ProofKind::Plonk => Self::Plonk,
            SP1ProofKind::Groth16 => Self::Groth16,
        }
    }
}
