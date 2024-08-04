#[rustfmt::skip]
pub mod proto {
    pub mod api;
}

use core::time::Duration;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::proto::api::ProverServiceClient;

use serde::{Deserialize, Serialize};
use sp1_core::io::SP1Stdin;
use sp1_core::stark::ShardProof;
use sp1_core::utils::SP1CoreProverError;
use sp1_prover::types::SP1ProvingKey;
use sp1_prover::InnerSC;
use sp1_prover::SP1CoreProof;
use sp1_prover::SP1RecursionProverError;
use sp1_prover::SP1ReduceProof;
use sp1_prover::SP1VerifyingKey;
use tokio::runtime::Runtime;
use twirp::url::Url;
use twirp::Client;

/// A remote client to [sp1_prover::SP1Prover] that runs inside a container.
///
/// This is currently used to provide experimental support for GPU hardware acceleration.
///
/// **WARNING**: This is an experimental feature and may not work as expected.
pub struct SP1ProverServer {
    /// The gRPC client to communicate with the container.
    client: Client,
    /// The name of the container.
    container_name: String,
    /// A flag to indicate whether the container has already been cleaned up.
    cleaned_up: Arc<AtomicBool>,
}

/// The payload for the [sp1_prover::SP1Prover::prove_core] method.
///
/// We use this object to serialize and deserialize the payload from the client to the server.
#[derive(Serialize, Deserialize)]
pub struct ProveCoreRequestPayload {
    /// The proving key.
    pub pk: SP1ProvingKey,
    /// The input stream.
    pub stdin: SP1Stdin,
}

/// The payload for the [sp1_prover::SP1Prover::compress] method.
///
/// We use this object to serialize and deserialize the payload from the client to the server.
#[derive(Serialize, Deserialize)]
pub struct CompressRequestPayload {
    /// The verifying key.
    pub vk: SP1VerifyingKey,
    /// The core proof.
    pub proof: SP1CoreProof,
    /// The deferred proofs.
    pub deferred_proofs: Vec<ShardProof<InnerSC>>,
}

impl SP1ProverServer {
    /// Creates a new [SP1Prover] that runs inside a Docker container and returns a
    /// [SP1ProverClient] that can be used to communicate with the container.
    pub fn new() -> Self {
        let container_name = "sp1-gpu";
        let image_name = "jtguibas/sp1-gpu:v1.1.0";

        let cleaned_up = Arc::new(AtomicBool::new(false));
        let cleanup_name = container_name;
        let cleanup_flag = cleaned_up.clone();

        // Spawn a new thread to start the Docker container.
        std::thread::spawn(move || {
            Command::new("sudo")
                .args([
                    "docker",
                    "run",
                    "-e",
                    "RUST_LOG=debug",
                    "-p",
                    "3000:3000",
                    "--rm",
                    "--runtime=nvidia",
                    "--gpus",
                    "all",
                    "--name",
                    container_name,
                    image_name,
                ])
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .expect("failed to start Docker container");
        });

        ctrlc::set_handler(move || {
            tracing::debug!("received Ctrl+C, cleaning up...");
            if !cleanup_flag.load(Ordering::SeqCst) {
                cleanup_container(cleanup_name);
                cleanup_flag.store(true, Ordering::SeqCst);
            }
            std::process::exit(0);
        })
        .unwrap();

        tracing::debug!("sleeping for 20 seconds to allow server to start");
        std::thread::sleep(Duration::from_secs(20));

        SP1ProverServer {
            client: Client::from_base_url(
                Url::parse("http://localhost:3000/twirp/").expect("failed to parse url"),
            )
            .expect("failed to create client"),
            container_name: container_name.to_string(),
            cleaned_up: cleaned_up.clone(),
        }
    }

    /// Executes the [sp1_prover::SP1Prover::prove_core] method inside the container.
    ///
    /// TODO: We can probably create a trait to unify [sp1_prover::SP1Prover] and [SP1ProverClient].
    ///
    /// **WARNING**: This is an experimental feature and may not work as expected.
    pub fn prove_core(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
    ) -> Result<SP1CoreProof, SP1CoreProverError> {
        let payload = ProveCoreRequestPayload {
            pk: pk.clone(),
            stdin: stdin.clone(),
        };
        let request = crate::proto::api::ProveCoreRequest {
            data: bincode::serialize(&payload).unwrap(),
        };
        let rt = Runtime::new().unwrap();
        let response = rt
            .block_on(async { self.client.prove_core(request).await })
            .unwrap();
        let proof: SP1CoreProof = bincode::deserialize(&response.result).unwrap();
        Ok(proof)
    }

    /// Executes the [sp1_prover::SP1Prover::compress] method inside the container.
    ///
    /// TODO: We can probably create a trait to unify [sp1_prover::SP1Prover] and [SP1ProverClient].
    ///
    /// **WARNING**: This is an experimental feature and may not work as expected.
    pub fn compress(
        &self,
        vk: &SP1VerifyingKey,
        proof: SP1CoreProof,
        deferred_proofs: Vec<ShardProof<InnerSC>>,
    ) -> Result<SP1ReduceProof<InnerSC>, SP1RecursionProverError> {
        let payload = CompressRequestPayload {
            vk: vk.clone(),
            proof,
            deferred_proofs,
        };
        let request = crate::proto::api::CompressRequest {
            data: bincode::serialize(&payload).unwrap(),
        };

        let rt = Runtime::new().unwrap();
        let response = rt
            .block_on(async { self.client.compress(request).await })
            .unwrap();
        let proof: SP1ReduceProof<InnerSC> = bincode::deserialize(&response.result).unwrap();
        Ok(proof)
    }
}

impl Default for SP1ProverServer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SP1ProverServer {
    fn drop(&mut self) {
        if !self.cleaned_up.load(Ordering::SeqCst) {
            tracing::debug!("dropping SP1ProverClient, cleaning up...");
            cleanup_container(&self.container_name);
            self.cleaned_up.store(true, Ordering::SeqCst);
        }
    }
}

/// Cleans up the a docker container with the given name.
fn cleanup_container(container_name: &str) {
    tracing::debug!("cleaning up container: {}", container_name);
    if let Err(e) = Command::new("sudo")
        .args(["docker", "rm", "-f", container_name])
        .status()
    {
        eprintln!("failed to remove container: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use sp1_core::utils;
    use sp1_core::utils::tests::FIBONACCI_ELF;
    use sp1_prover::components::DefaultProverComponents;
    use sp1_prover::{InnerSC, SP1CoreProof, SP1Prover, SP1ReduceProof};
    use twirp::url::Url;
    use twirp::Client;

    use crate::SP1Stdin;
    use crate::{proto::api::ProverServiceClient, ProveCoreRequestPayload};
    use crate::{CompressRequestPayload, SP1ProverServer};

    #[ignore]
    #[test]
    fn test_client() {
        utils::setup_logger();

        let client = SP1ProverServer::new();

        let prover = SP1Prover::<DefaultProverComponents>::new();
        let (pk, vk) = prover.setup(FIBONACCI_ELF);

        println!("proving core");
        let proof = client.prove_core(&pk, &SP1Stdin::new()).unwrap();

        println!("verifying core");
        prover.verify(&proof.proof, &vk).unwrap();

        println!("proving compress");
        let proof = client.compress(&vk, proof, vec![]).unwrap();

        println!("verifying compress");
        prover.verify_compressed(&proof, &vk).unwrap();
    }

    #[ignore]
    #[tokio::test]
    async fn test_prove_core() {
        let client =
            Client::from_base_url(Url::parse("http://localhost:3000/twirp/").unwrap()).unwrap();

        let prover = SP1Prover::<DefaultProverComponents>::new();
        let (pk, vk) = prover.setup(FIBONACCI_ELF);
        let payload = ProveCoreRequestPayload {
            pk,
            stdin: SP1Stdin::new(),
        };
        let request = crate::proto::api::ProveCoreRequest {
            data: bincode::serialize(&payload).unwrap(),
        };
        let proof = client.prove_core(request).await.unwrap();
        let proof: SP1CoreProof = bincode::deserialize(&proof.result).unwrap();
        prover.verify(&proof.proof, &vk).unwrap();

        tracing::info!("compress");
        let payload = CompressRequestPayload {
            vk: vk.clone(),
            proof,
            deferred_proofs: vec![],
        };
        let request = crate::proto::api::CompressRequest {
            data: bincode::serialize(&payload).unwrap(),
        };
        let compressed_proof = client.compress(request).await.unwrap();
        let compressed_proof: SP1ReduceProof<InnerSC> =
            bincode::deserialize(&compressed_proof.result).unwrap();

        tracing::info!("verify compressed");
        prover.verify_compressed(&compressed_proof, &vk).unwrap();
    }
}
