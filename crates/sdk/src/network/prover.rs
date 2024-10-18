use std::{
    env,
    time::{Duration, Instant},
};

use crate::{
    network::client::{NetworkClient, DEFAULT_PROVER_NETWORK_RPC},
    network::proto::network::{ProofMode, ProofStatus},
    Prover, SP1Context, SP1ProofKind, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey,
};
use anyhow::Result;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{components::DefaultProverComponents, SP1Prover, SP1_CIRCUIT_VERSION};
use sp1_stark::SP1ProverOpts;

use super::proto::network::GetProofStatusResponse;

use {crate::block_on, tokio::time::sleep};

use crate::provers::{CpuProver, ProofOpts, ProverType};

/// Number of consecutive errors to tolerate before returning an error while polling proof status.
const MAX_CONSECUTIVE_ERRORS: usize = 10;

/// An implementation of [crate::ProverClient] that can generate proofs on a remote RPC server.
pub struct NetworkProver {
    client: NetworkClient,
    local_prover: CpuProver,
}

impl NetworkProver {
    /// Creates a new [NetworkProver] with the private key set in `SP1_PRIVATE_KEY`.
    pub fn new() -> Self {
        let private_key = env::var("SP1_PRIVATE_KEY")
            .unwrap_or_else(|_| panic!("SP1_PRIVATE_KEY must be set for remote proving"));
        Self::new_from_key(&private_key)
    }

    /// Creates a new [NetworkProver] with the given private key.
    pub fn new_from_key(private_key: &str) -> Self {
        let version = SP1_CIRCUIT_VERSION;
        log::info!("Client circuit version: {}", version);

        let local_prover = CpuProver::new();
        Self { client: NetworkClient::new(private_key), local_prover }
    }

    /// Requests a proof from the prover network, returning the proof ID.
    pub async fn request_proof(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        mode: ProofMode,
    ) -> Result<String> {
        let client = &self.client;

        let skip_simulation = env::var("SKIP_SIMULATION").map(|val| val == "true").unwrap_or(false);

        if !skip_simulation {
            let (_, report) =
                self.local_prover.sp1_prover().execute(elf, &stdin, Default::default())?;
            log::info!("Simulation complete, cycles: {}", report.total_instruction_count());
        } else {
            log::info!("Skipping simulation");
        }

        let proof_id = client.create_proof(elf, &stdin, mode, SP1_CIRCUIT_VERSION).await?;
        log::info!("Created {}", proof_id);

        if NetworkClient::rpc_url() == DEFAULT_PROVER_NETWORK_RPC {
            log::info!("View in explorer: https://explorer.succinct.xyz/{}", proof_id);
        }
        Ok(proof_id)
    }

    /// Waits for a proof to be generated and returns the proof. If a timeout is supplied, the
    /// function will return an error if the proof is not generated within the timeout.
    pub async fn wait_proof(
        &self,
        proof_id: &str,
        timeout: Option<Duration>,
    ) -> Result<SP1ProofWithPublicValues> {
        let client = &self.client;
        let mut is_claimed = false;
        let start_time = Instant::now();
        let mut consecutive_errors = 0;
        loop {
            if let Some(timeout) = timeout {
                if start_time.elapsed() > timeout {
                    return Err(anyhow::anyhow!("Proof generation timed out."));
                }
            }

            let result = client.get_proof_status(proof_id).await;

            if let Err(e) = result {
                consecutive_errors += 1;
                log::warn!(
                    "Failed to get proof status ({}/{}): {:?}",
                    consecutive_errors,
                    MAX_CONSECUTIVE_ERRORS,
                    e
                );
                if consecutive_errors == MAX_CONSECUTIVE_ERRORS {
                    return Err(anyhow::anyhow!(
                        "Proof generation failed: {} consecutive errors.",
                        MAX_CONSECUTIVE_ERRORS
                    ));
                }
                continue;
            }
            consecutive_errors = 0;

            let (status, maybe_proof) = result.unwrap();

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

    /// Get the status and the proof if available of a given proof request. The proof is returned
    /// only if the status is Fulfilled.
    pub async fn get_proof_status(
        &self,
        proof_id: &str,
    ) -> Result<(GetProofStatusResponse, Option<SP1ProofWithPublicValues>)> {
        self.client.get_proof_status(proof_id).await
    }

    /// Requests a proof from the prover network and waits for it to be generated.
    pub async fn prove(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        mode: ProofMode,
        timeout: Option<Duration>,
    ) -> Result<SP1ProofWithPublicValues> {
        let proof_id = self.request_proof(elf, stdin, mode).await?;
        self.wait_proof(&proof_id, timeout).await
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

impl Default for NetworkProver {
    fn default() -> Self {
        Self::new()
    }
}

/// Warns if `opts` or `context` are not default values, since they are currently unsupported.
fn warn_if_not_default(opts: &SP1ProverOpts, context: &SP1Context) {
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
