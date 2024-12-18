use std::time::{Duration, Instant};

use super::proto::network::GetProofStatusResponse;
use crate::provers::{LocalProver, ProverType};
use crate::util::dump_proof_input;
use crate::{
    network::{
        client::NetworkClient,
        proto::network::{ProofMode, ProofStatus},
    },
    Prover, SP1ProofKind, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey,
};
use anyhow::Result;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{components::DefaultProverComponents, SP1Prover, SP1_CIRCUIT_VERSION};
use {crate::block_on, tokio::time::sleep};

/// Number of consecutive errors to tolerate before returning an error while polling proof status.
const MAX_CONSECUTIVE_ERRORS: usize = 10;

/// An implementation of [crate::ProverClient] that can generate proofs on a remote RPC server.
pub struct NetworkProver {
    client: NetworkClient,
    local_prover: LocalProver,
}

impl NetworkProver {
    /// Creates a new [NetworkProver] with the given private key.
    pub fn new(private_key: &str, rpc_url: Option<String>) -> Self {
        let version = SP1_CIRCUIT_VERSION;
        log::info!("Client circuit version: {}", version);

        let local_prover = LocalProver::new(false);
        Self { client: NetworkClient::new(private_key, rpc_url), local_prover }
    }

    /// Requests a proof from the prover network, returning the proof ID.
    pub(crate) async fn request_proof(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        mode: ProofMode,
        skip_simulation: bool,
    ) -> Result<String> {
        let client = &self.client;

        if !skip_simulation {
            let (_, report) =
                self.local_prover.sp1_prover().execute(elf, &stdin, Default::default())?;
            log::info!("Simulation complete, cycles: {}", report.total_instruction_count());
        } else {
            log::info!("Skipping simulation");
        }

        let proof_id = client.create_proof(elf, &stdin, mode, SP1_CIRCUIT_VERSION).await?;
        log::info!("Created {}", proof_id);

        if self.client.is_using_prover_network {
            log::info!("View in explorer: https://explorer.succinct.xyz/{}", proof_id);
        }
        Ok(proof_id)
    }

    /// Waits for a proof to be generated and returns the proof. If a timeout is supplied, the
    /// function will return an error if the proof is not generated within the timeout.
    pub(crate) async fn wait_proof(
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
    pub(crate) async fn prove(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        mode: ProofMode,
        timeout: Option<Duration>,
        skip_simulation: bool,
    ) -> Result<SP1ProofWithPublicValues> {
        let proof_id = self.request_proof(elf, stdin, mode, skip_simulation).await?;
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
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
        block_on(self.prove(&pk.elf, stdin, kind.into(), None, false))
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

/// Builder to prepare and configure proving execution of a program on an input.
/// May be run with [Self::run].
pub struct NetworkProve<'a> {
    prover: &'a NetworkProver,
    kind: SP1ProofKind,
    pk: &'a SP1ProvingKey,
    stdin: SP1Stdin,
    timeout: Option<Duration>,
    skip_simulation: bool,
}

impl<'a> NetworkProve<'a> {
    /// Prove the execution of the program on the input, consuming the built action `self`.
    pub async fn run(self) -> Result<SP1ProofWithPublicValues> {
        let Self { prover, kind, pk, stdin, timeout, skip_simulation } = self;

        dump_proof_input(&pk.elf, &stdin);

        prover.prove(&pk.elf, stdin, kind.into(), timeout, skip_simulation).await
    }

    /// Set the proof kind to the core mode. This is the default.
    pub fn core(mut self) -> Self {
        self.kind = SP1ProofKind::Core;
        self
    }

    /// Set the proof kind to the compressed mode.
    pub fn compressed(mut self) -> Self {
        self.kind = SP1ProofKind::Compressed;
        self
    }

    /// Set the proof mode to the plonk bn254 mode.
    pub fn plonk(mut self) -> Self {
        self.kind = SP1ProofKind::Plonk;
        self
    }

    /// Set the proof mode to the groth16 bn254 mode.
    pub fn groth16(mut self) -> Self {
        self.kind = SP1ProofKind::Groth16;
        self
    }

    /// Set the proof mode to the given mode.
    pub fn mode(mut self, mode: SP1ProofKind) -> Self {
        self.kind = mode;
        self
    }

    /// Set the timeout for the proof's generation.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Enable skipping the simulation step.
    pub fn skip_simulation(mut self, skip_simulation: bool) -> Self {
        self.skip_simulation = skip_simulation;
        self
    }
}
