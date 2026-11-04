use std::sync::Arc;

use sp1_primitives::Elf;
use sp1_prover::SP1VerifyingKey;

use crate::client::CudaClient;

#[derive(Clone)]
pub struct CudaProvingKey {
    /// The inner session key type, tells the server
    /// to drop the key it holds when the last reference to this session is dropped.
    inner: Arc<SessionKey>,
}

impl CudaProvingKey {
    pub(crate) fn id(&self) -> [u8; 32] {
        self.inner.id
    }

    pub fn elf(&self) -> &Elf {
        &self.inner.elf
    }

    pub fn verifying_key(&self) -> &SP1VerifyingKey {
        &self.inner.vk
    }
}

impl CudaProvingKey {
    pub(crate) fn new(id: [u8; 32], elf: Elf, vk: SP1VerifyingKey, client: CudaClient) -> Self {
        Self { inner: Arc::new(SessionKey::new(id, elf, vk, client)) }
    }
}

/// A "reference" to a key held by the CUDA server.
pub(crate) struct SessionKey {
    /// THe ID of the actual proving key stored in the server.
    id: [u8; 32],
    /// The ELF of the program.
    elf: Elf,
    /// The verifying key of the program.
    vk: SP1VerifyingKey,
    /// A client to the server that created this key.
    client: CudaClient,
}

impl SessionKey {
    pub(crate) const fn new(
        id: [u8; 32],
        elf: Elf,
        vk: SP1VerifyingKey,
        client: CudaClient,
    ) -> Self {
        Self { id, elf, vk, client }
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        let client = self.client.clone();
        let id = std::mem::take(&mut self.id);

        // As in `CudaClientInner::drop`, this can run with no Tokio runtime in scope,
        // where `tokio::spawn` panics and the panic aborts the process from a destructor.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    if let Err(e) = client.destroy(id).await {
                        tracing::error!("Failed to destroy session key: {}", e);
                    }
                });
            }
            Err(_) => {
                // The server frees its keys when the connection closes, so skipping the
                // explicit destroy is preferable to aborting the process.
                tracing::debug!("No Tokio runtime available; skipping session key destroy");
            }
        }
    }
}
