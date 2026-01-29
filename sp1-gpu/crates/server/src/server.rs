use sp1_core_executor::SP1Context;
use sp1_cuda::{
    api::{Request, Response},
    client::socket_path,
};
use sp1_gpu_cudart::TaskScope;
use sp1_gpu_prover::cuda_worker_builder;
use sp1_primitives::Elf;
use sp1_prover::worker::{SP1LocalNode, SP1LocalNodeBuilder};
use sp1_prover::SP1VerifyingKey;
use std::collections::HashMap;

use std::io;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

/// A cached proving key and verifying key.
#[derive(Clone)]
struct CachedProgram {
    elf: Arc<Elf>,
    vk: SP1VerifyingKey,
}

/// The server for the sp1-gpu service.
pub struct Server {
    pub cuda_device_id: u32,
}

/// The context for a single connection to the server.
struct ConnectionCtx {
    pk_cache: HashMap<[u8; 32], CachedProgram>,
    prover: Arc<SP1LocalNode>,
}

impl Server {
    /// Run the server, indefinitely.
    pub async fn run(self, task_scope: TaskScope) {
        eprintln!(
            "Running sp1-gpu-server {} with device {}",
            sp1_primitives::SP1_VERSION,
            self.cuda_device_id
        );
        let socket_path = socket_path(self.cuda_device_id);

        // Try to remove the socket file socket incase the file was never cleaned up.
        if let Err(e) = std::fs::remove_file(&socket_path) {
            tracing::warn!("Failed to remove orphaned socket: {}", e);
        }

        let listener = UnixListener::bind(&socket_path).expect("Failed to bind to socket addr");

        let prover = Arc::new(
            SP1LocalNodeBuilder::from_worker_client_builder(
                cuda_worker_builder(task_scope.clone()).await,
            )
            .build()
            .await
            .unwrap(),
        );

        tracing::info!("Server listening @ {}", socket_path.display());
        loop {
            tokio::select! {
                res = listener.accept() => {
                    if let Ok((stream, _)) = res {
                        tracing::info!("Connection accepted");

                        let prover = prover.clone();

                        tokio::spawn(async move {
                            let mut stream = stream;

                            if let Err(e) = Self::handle_connection(prover, &mut stream).await {
                                if e.kind() == io::ErrorKind::UnexpectedEof
                                    || e.kind() == io::ErrorKind::BrokenPipe
                                {
                                    tracing::info!("Connection disconnected");
                                    let _ = send_response(&mut stream, Response::ConnectionClosed).await;
                                } else {
                                    tracing::error!("Error handling connection: {:?}", e);
                                }
                            }
                        });
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Ctrl-C received, shutting down");

                    // Remove the socket file, explicitly.
                    if let Err(e) = std::fs::remove_file(&socket_path) {
                        tracing::error!("Failed to remove orphaned socket: {}", e);
                    }

                    break;
                }
            }
        }
    }

    async fn handle_connection(
        prover: Arc<SP1LocalNode>,
        stream: &mut UnixStream,
    ) -> Result<(), io::Error> {
        let mut ctx = ConnectionCtx { pk_cache: Default::default(), prover };

        loop {
            let mut len = [0_u8; 4];
            stream.read_exact(&mut len).await?;

            let len = u32::from_le_bytes(len);
            let mut request_buf = vec![0; len as usize];
            stream.read_exact(&mut request_buf).await?;

            let request: Request = match bincode::deserialize(&request_buf) {
                Ok(request) => request,
                Err(e) => {
                    eprintln!("Error deserializing request: {e}");
                    let response = Response::InternalError(e.to_string());
                    send_response(stream, response).await?;
                    return Ok(());
                }
            };

            let response = Self::handle_request(&mut ctx, request).await;
            send_response(stream, response).await?;
        }
    }

    async fn handle_request(ctx: &mut ConnectionCtx, request: Request) -> Response {
        match request {
            Request::Setup { elf } => {
                tracing::info!("Running setup");
                let elf_hash = sha256(&elf);
                if let Some(pk) = ctx.pk_cache.get(&elf_hash) {
                    return Response::Setup { id: elf_hash, vk: pk.vk.clone() };
                }
                let vk = match ctx.prover.setup(&elf).await {
                    Ok(vk) => vk,
                    Err(e) => return Response::InternalError(e.to_string()),
                };
                let pk = CachedProgram { elf: Arc::new(Elf::Dynamic(elf.into())), vk: vk.clone() };
                ctx.pk_cache.insert(elf_hash, pk);
                Response::Setup { id: elf_hash, vk }
            }
            Request::Destroy { key } => {
                tracing::info!("Destroying key");
                ctx.pk_cache.remove(&key);
                Response::Ok
            }
            Request::ProveWithMode { mode, key, stdin, proof_nonce } => {
                tracing::info!("Proving with mode: {mode:?}");
                let Some(cached) = ctx.pk_cache.get(&key) else {
                    return Response::InternalError(
                        "Missing proving key, do not drop the prover while maintaing a proving key generated by it.".to_string(),
                    );
                };
                let context = SP1Context::builder().proof_nonce(proof_nonce).build();
                match ctx.prover.prove_with_mode(&cached.elf, stdin, context, mode).await {
                    Ok(proof) => Response::Proof { proof },
                    Err(e) => Response::ProverError(e.to_string()),
                }
            }
        }
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

async fn send_response(stream: &mut UnixStream, response: Response) -> Result<(), io::Error> {
    let response_bytes = bincode::serialize(&response).unwrap();
    let len = response_bytes.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&response_bytes).await?;

    Ok(())
}
