use std::sync::Arc;

use serde::{de::DeserializeOwned, Serialize};
use sp1_jit::{TraceChunkRaw, MERKLE_PAGE_WORDS};
use sp1_prover_types::{Artifact, ArtifactClient};

use super::LeafDigest;

/// All per-chunk data the controller has after running the `MinimalExecutor`
/// and hashing the chunk's dirty-page leaves.
///
/// `chunk` holds the raw JIT trace chunk. `TraceChunkRaw` is `Clone` but the
/// underlying mmap/shm storage is `Arc`-backed, so cloning is cheap.
pub struct ChunkPayload {
    pub chunk_idx: u64,
    pub chunk: TraceChunkRaw,
    pub dirty_page_ids: Vec<u32>,
    pub prev_leaves: Vec<LeafDigest>,
    pub new_leaves: Vec<LeafDigest>,
    pub dirty_page_final_contents: Vec<[u64; MERKLE_PAGE_WORDS]>,
    pub pre_chunk_snapshot: Arc<Vec<(u32, LeafDigest)>>,
}

impl ChunkPayload {
    /// Number of dirty pages this chunk touched.
    #[inline]
    pub fn dirty_count(&self) -> usize {
        self.dirty_page_ids.len()
    }
}

/// Generic intra-/inter-node task input.
pub enum TaskInput<T> {
    /// Same-process. Producer and consumer share the same `Arc`.
    Local(Arc<T>),
    /// Cross-process via the artifact client. Only usable when
    /// `T: Serialize + DeserializeOwned`.
    Remote(Artifact),
}

impl<T> TaskInput<T> {
    /// Wrap an owned value as a `Local` input.
    #[inline]
    pub fn local(value: T) -> Self {
        Self::Local(Arc::new(value))
    }

    /// Already-shared local value.
    #[inline]
    pub fn from_arc(value: Arc<T>) -> Self {
        Self::Local(value)
    }

    /// Returns `true` iff this is a `Local` input.
    #[inline]
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local(_))
    }
}

impl<T> TaskInput<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    /// Materialize the value, downloading it via the artifact client if
    /// this is a `Remote` input. `Local` inputs return the existing `Arc`.
    pub async fn resolve<A: ArtifactClient>(self, client: &A) -> anyhow::Result<Arc<T>> {
        match self {
            Self::Local(arc) => Ok(arc),
            Self::Remote(artifact) => {
                let value: T = client.download(&artifact).await?;
                Ok(Arc::new(value))
            }
        }
    }
}

impl<T> TaskInput<T> {
    /// Local-only resolve.
    pub fn into_local(self) -> Option<Arc<T>> {
        match self {
            Self::Local(arc) => Some(arc),
            Self::Remote(_) => None,
        }
    }
}
