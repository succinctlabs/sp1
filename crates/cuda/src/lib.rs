use std::{
    error::Error as StdError,
    future::Future,
    io::{BufReader, Read, Write},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crate::proto::api::ProverServiceClient;
use async_trait::async_trait;
use proto::api::ReadyRequest;
use reqwest::{Request, Response};
use serde::{Deserialize, Serialize};
use sp1_core_machine::{io::SP1Stdin, reduce::SP1ReduceProof, utils::SP1CoreProverError};
use sp1_prover::{
    types::SP1ProvingKey, InnerSC, OuterSC, SP1CoreProof, SP1RecursionProverError, SP1VerifyingKey,
};
use tokio::task::block_in_place;
use twirp::{
    async_trait,
    reqwest::{self},
    url::Url,
    Client, ClientError, Middleware, Next,
};

#[rustfmt::skip]
pub mod proto {
    pub mod api;
}

/// A remote client to [sp1_prover::SP1Prover] that runs inside a container.
///
/// This is currently used to provide experimental support for GPU hardware acceleration.
///
/// **WARNING**: This is an experimental feature and may not work as expected.
pub struct SP1CudaProver {
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
    pub deferred_proofs: Vec<SP1ReduceProof<InnerSC>>,
}

/// The payload for the [sp1_prover::SP1Prover::shrink] method.
///
/// We use this object to serialize and deserialize the payload from the client to the server.
#[derive(Serialize, Deserialize)]
pub struct ShrinkRequestPayload {
    pub reduced_proof: SP1ReduceProof<InnerSC>,
}

/// The payload for the [sp1_prover::SP1Prover::wrap_bn254] method.
///
/// We use this object to serialize and deserialize the payload from the client to the server.
#[derive(Serialize, Deserialize)]
pub struct WrapRequestPayload {
    pub reduced_proof: SP1ReduceProof<InnerSC>,
}

impl SP1CudaProver {
    /// Creates a new [SP1Prover] that runs inside a Docker container and returns a
    /// [SP1ProverClient] that can be used to communicate with the container.
    pub fn new() -> Result<Self, Box<dyn StdError>> {
        let container_name = "sp1-gpu";
        let image_name = "public.ecr.aws/succinct-labs/sp1-gpu:7e66232";

        let cleaned_up = Arc::new(AtomicBool::new(false));
        let cleanup_name = container_name;
        let cleanup_flag = cleaned_up.clone();

        // Check if Docker is available and the user has necessary permissions
        if !Self::check_docker_availability()? {
            return Err("Docker is not available or you don't have the necessary permissions. Please ensure Docker is installed and you are part of the docker group.".into());
        }

        // Pull the docker image if it's not present
        if let Err(e) = Command::new("docker").args(["pull", image_name]).output() {
            return Err(format!("Failed to pull Docker image: {}. Please check your internet connection and Docker permissions.", e).into());
        }

        // Start the docker container
        let rust_log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "none".to_string());
        let mut child = Command::new("docker")
            .args([
                "run",
                "-e",
                &format!("RUST_LOG={}", rust_log_level),
                "-p",
                "3000:3000",
                "--rm",
                "--gpus",
                "all",
                "--name",
                container_name,
                image_name,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to start Docker container: {}. Please check your Docker installation and permissions.", e))?;

        let stderr = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut buffer = [0; 1024];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        std::io::stderr().write_all(&buffer[..n]).unwrap();
                        std::io::stderr().flush().unwrap();
                    }
                    Err(_) => break,
                }
            }
        });

        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut buffer = [0; 1024];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        std::io::stdout().write_all(&buffer[..n]).unwrap();
                        std::io::stdout().flush().unwrap();
                    }
                    Err(_) => break,
                }
            }
        });

        // Kill the container on control-c
        ctrlc::set_handler(move || {
            tracing::debug!("received Ctrl+C, cleaning up...");
            if !cleanup_flag.load(Ordering::SeqCst) {
                cleanup_container(cleanup_name);
                cleanup_flag.store(true, Ordering::SeqCst);
            }
            std::process::exit(0);
        })
        .unwrap();

        // Wait a few seconds for the container to start
        std::thread::sleep(Duration::from_secs(2));

        // Check if the container is ready
        let client = Client::from_base_url(
            Url::parse("http://localhost:3000/twirp/").expect("failed to parse url"),
        )
        .expect("failed to create client");

        let timeout = Duration::from_secs(300);
        let start_time = Instant::now();

        block_on(async {
            tracing::info!("waiting for proving server to be ready");
            loop {
                if start_time.elapsed() > timeout {
                    return Err("Timeout: proving server did not become ready within 60 seconds. Please check your Docker container and network settings.".to_string());
                }

                let request = ReadyRequest {};
                match client.ready(request).await {
                    Ok(response) if response.ready => {
                        tracing::info!("proving server is ready");
                        break;
                    }
                    Ok(_) => {
                        tracing::info!("proving server is not ready, retrying...");
                    }
                    Err(e) => {
                        tracing::warn!("Error checking server readiness: {}", e);
                    }
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Ok(())
        })?;

        let client = Client::new(
            Url::parse("http://localhost:3000/twirp/").expect("failed to parse url"),
            reqwest::Client::new(),
            vec![Box::new(LoggingMiddleware) as Box<dyn Middleware>],
        )
        .expect("failed to create client");

        Ok(SP1CudaProver {
            client,
            container_name: container_name.to_string(),
            cleaned_up: cleaned_up.clone(),
        })
    }

    fn check_docker_availability() -> Result<bool, Box<dyn std::error::Error>> {
        match Command::new("docker").arg("version").output() {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }

    /// Executes the [sp1_prover::SP1Prover::prove_core] method inside the container.
    ///
    /// You will need at least 24GB of VRAM to run this method.
    ///
    /// **WARNING**: This is an experimental feature and may not work as expected.
    pub fn prove_core(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
    ) -> Result<SP1CoreProof, SP1CoreProverError> {
        let payload = ProveCoreRequestPayload { pk: pk.clone(), stdin: stdin.clone() };
        let request =
            crate::proto::api::ProveCoreRequest { data: bincode::serialize(&payload).unwrap() };
        let response = block_on(async { self.client.prove_core(request).await }).unwrap();
        let proof: SP1CoreProof = bincode::deserialize(&response.result).unwrap();
        Ok(proof)
    }

    /// Executes the [sp1_prover::SP1Prover::compress] method inside the container.
    ///
    /// You will need at least 24GB of VRAM to run this method.
    ///
    /// **WARNING**: This is an experimental feature and may not work as expected.
    pub fn compress(
        &self,
        vk: &SP1VerifyingKey,
        proof: SP1CoreProof,
        deferred_proofs: Vec<SP1ReduceProof<InnerSC>>,
    ) -> Result<SP1ReduceProof<InnerSC>, SP1RecursionProverError> {
        let payload = CompressRequestPayload { vk: vk.clone(), proof, deferred_proofs };
        let request =
            crate::proto::api::CompressRequest { data: bincode::serialize(&payload).unwrap() };

        let response = block_on(async { self.client.compress(request).await }).unwrap();
        let proof: SP1ReduceProof<InnerSC> = bincode::deserialize(&response.result).unwrap();
        Ok(proof)
    }

    /// Executes the [sp1_prover::SP1Prover::shrink] method inside the container.
    ///
    /// You will need at least 40GB of VRAM to run this method.
    ///
    /// **WARNING**: This is an experimental feature and may not work as expected.
    pub fn shrink(
        &self,
        reduced_proof: SP1ReduceProof<InnerSC>,
    ) -> Result<SP1ReduceProof<InnerSC>, SP1RecursionProverError> {
        let payload = ShrinkRequestPayload { reduced_proof: reduced_proof.clone() };
        let request =
            crate::proto::api::ShrinkRequest { data: bincode::serialize(&payload).unwrap() };

        let response = block_on(async { self.client.shrink(request).await }).unwrap();
        let proof: SP1ReduceProof<InnerSC> = bincode::deserialize(&response.result).unwrap();
        Ok(proof)
    }

    /// Executes the [sp1_prover::SP1Prover::wrap_bn254] method inside the container.
    ///
    /// You will need at least 40GB of VRAM to run this method.
    ///
    /// **WARNING**: This is an experimental feature and may not work as expected.
    pub fn wrap_bn254(
        &self,
        reduced_proof: SP1ReduceProof<InnerSC>,
    ) -> Result<SP1ReduceProof<OuterSC>, SP1RecursionProverError> {
        let payload = WrapRequestPayload { reduced_proof: reduced_proof.clone() };
        let request =
            crate::proto::api::WrapRequest { data: bincode::serialize(&payload).unwrap() };

        let response = block_on(async { self.client.wrap(request).await }).unwrap();
        let proof: SP1ReduceProof<OuterSC> = bincode::deserialize(&response.result).unwrap();
        Ok(proof)
    }
}

impl Default for SP1CudaProver {
    fn default() -> Self {
        Self::new().expect("Failed to create SP1CudaProver")
    }
}

impl Drop for SP1CudaProver {
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
    if let Err(e) = Command::new("docker").args(["rm", "-f", container_name]).output() {
        eprintln!(
            "Failed to remove container: {}. You may need to manually remove it using 'docker rm -f {}'",
            e, container_name
        );
    }
}

/// Utility method for blocking on an async function.
///
/// If we're already in a tokio runtime, we'll block in place. Otherwise, we'll create a new
/// runtime.
pub fn block_on<T>(fut: impl Future<Output = T>) -> T {
    // Handle case if we're already in an tokio runtime.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        block_in_place(|| handle.block_on(fut))
    } else {
        // Otherwise create a new runtime.
        let rt = tokio::runtime::Runtime::new().expect("Failed to create a new runtime");
        rt.block_on(fut)
    }
}

struct LoggingMiddleware;

pub type Result<T, E = ClientError> = std::result::Result<T, E>;

#[async_trait]
impl Middleware for LoggingMiddleware {
    async fn handle(&self, req: Request, next: Next<'_>) -> Result<Response> {
        let response = next.run(req).await;
        match response {
            Ok(response) => {
                tracing::info!("{:?}", response);
                Ok(response)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(feature = "protobuf")]
#[cfg(test)]
mod tests {
    use sp1_core_machine::{
        reduce::SP1ReduceProof,
        utils::{setup_logger, tests::FIBONACCI_ELF},
    };
    use sp1_prover::{components::DefaultProverComponents, InnerSC, SP1CoreProof, SP1Prover};
    use twirp::{url::Url, Client};

    use crate::{
        proto::api::ProverServiceClient, CompressRequestPayload, ProveCoreRequestPayload,
        SP1CudaProver, SP1Stdin,
    };

    #[test]
    fn test_client() {
        setup_logger();

        let prover = SP1Prover::<DefaultProverComponents>::new();
        let client = SP1CudaProver::new().expect("Failed to create SP1CudaProver");
        let (pk, vk) = prover.setup(FIBONACCI_ELF);

        println!("proving core");
        let proof = client.prove_core(&pk, &SP1Stdin::new()).unwrap();

        println!("verifying core");
        prover.verify(&proof.proof, &vk).unwrap();

        println!("proving compress");
        let proof = client.compress(&vk, proof, vec![]).unwrap();

        println!("verifying compress");
        prover.verify_compressed(&proof, &vk).unwrap();

        println!("proving shrink");
        let proof = client.shrink(proof).unwrap();

        println!("verifying shrink");
        prover.verify_shrink(&proof, &vk).unwrap();

        println!("proving wrap_bn254");
        let proof = client.wrap_bn254(proof).unwrap();

        println!("verifying wrap_bn254");
        prover.verify_wrap_bn254(&proof, &vk).unwrap();
    }

    #[tokio::test]
    async fn test_prove_core() {
        let client =
            Client::from_base_url(Url::parse("http://localhost:3000/twirp/").unwrap()).unwrap();

        let prover = SP1Prover::<DefaultProverComponents>::new();
        let (pk, vk) = prover.setup(FIBONACCI_ELF);
        let payload = ProveCoreRequestPayload { pk, stdin: SP1Stdin::new() };
        let request =
            crate::proto::api::ProveCoreRequest { data: bincode::serialize(&payload).unwrap() };
        let proof = client.prove_core(request).await.unwrap();
        let proof: SP1CoreProof = bincode::deserialize(&proof.result).unwrap();
        prover.verify(&proof.proof, &vk).unwrap();

        tracing::info!("compress");
        let payload = CompressRequestPayload { vk: vk.clone(), proof, deferred_proofs: vec![] };
        let request =
            crate::proto::api::CompressRequest { data: bincode::serialize(&payload).unwrap() };
        let compressed_proof = client.compress(request).await.unwrap();
        let compressed_proof: SP1ReduceProof<InnerSC> =
            bincode::deserialize(&compressed_proof.result).unwrap();

        tracing::info!("verify compressed");
        prover.verify_compressed(&compressed_proof, &vk).unwrap();
    }
}
