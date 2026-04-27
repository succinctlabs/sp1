//! Per-proof backpressure gate for the `ProveShard` producer path.
//!
//! Bundles the artifact store's [`ShardPermit`] pool with a per-proof
//! [`TaskSubscriber`] so a permit stays held for the artifact's full memory
//! lifetime (upload → task completion), not just the upload call.
//!
//! Producer flow:
//!
//! ```text
//! let permit = gate.acquire(&record_artifact).await;
//! artifact_client.upload(&record_artifact, trace).await?;
//! let task_id = worker_client.submit_task(ProveShard, task).await?;
//! gate.schedule_release(task_id, permit);
//! ```

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use sp1_prover_types::{ArtifactClient, ArtifactId, ShardPermit, TaskStatus};
use tokio::task::AbortHandle;

use crate::worker::{ProofId, TaskId, TaskSubscriber, WorkerClient};

/// Shared backpressure gate for one proof's ProveShard submissions.
///
/// Cheap to clone (refcounted). When the last clone drops, the subscriber
/// pump and any still-pending release tasks are aborted — aborting unwinds
/// each task's stack and drops its `ShardPermit`, so permits never leak even
/// if `wait_task` would have hung (e.g. proof torn down mid-flight).
pub struct ProveShardGate<A: ArtifactClient, W: WorkerClient> {
    inner: Arc<GateInner<A, W>>,
}

impl<A: ArtifactClient, W: WorkerClient> std::fmt::Debug for ProveShardGate<A, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProveShardGate").finish_non_exhaustive()
    }
}

struct GateInner<A: ArtifactClient, W: WorkerClient> {
    artifact_client: A,
    subscriber: TaskSubscriber<W>,
    release_handles: Mutex<Vec<AbortHandle>>,
}

impl<A: ArtifactClient, W: WorkerClient> Drop for GateInner<A, W> {
    fn drop(&mut self) {
        self.subscriber.close();
        // Abort pending release tasks so their `ShardPermit`s drop via stack
        // unwinding. Without this, a task awaiting a status update that will
        // never arrive (pump closed above) would hang forever holding its
        // permit. Load-bearing — exercised by the gate integration test.
        if let Ok(mut handles) = self.release_handles.lock() {
            for handle in handles.drain(..) {
                handle.abort();
            }
        }
    }
}

impl<A: ArtifactClient, W: WorkerClient> Clone for ProveShardGate<A, W> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<A: ArtifactClient, W: WorkerClient> ProveShardGate<A, W> {
    /// Build a gate scoped to `proof_id`, opening a per-proof task subscriber.
    pub async fn new(
        artifact_client: A,
        worker_client: W,
        proof_id: ProofId,
    ) -> anyhow::Result<Self> {
        let subscriber = worker_client.subscriber(proof_id).await?.per_task();
        Ok(Self {
            inner: Arc::new(GateInner {
                artifact_client,
                subscriber,
                release_handles: Mutex::new(Vec::new()),
            }),
        })
    }

    /// Reserve a slot for an in-flight shard upload. Blocks when the shard
    /// node this artifact hashes to is full.
    pub async fn acquire(&self, artifact: &impl ArtifactId) -> ShardPermit {
        self.inner.artifact_client.acquire_shard_permit(artifact).await
    }

    /// Release `permit` only when the coordinator reports a truly terminal
    /// status — [`TaskStatus::Succeeded`] or [`TaskStatus::FailedFatal`]. On
    /// [`TaskStatus::FailedRetryable`] the coordinator re-queues the same
    /// `task_id`, so we keep holding the permit (the record artifact is still
    /// referenced) and wait for the next status change.
    pub fn schedule_release(&self, task_id: TaskId, permit: ShardPermit) {
        let subscriber = self.inner.subscriber.clone();
        let handle = tokio::spawn(async move {
            let _permit = permit;
            loop {
                match subscriber.wait_task(task_id.clone()).await {
                    Ok(TaskStatus::Succeeded | TaskStatus::FailedFatal) => break,
                    Ok(_) => {
                        // Non-terminal status (e.g. FailedRetryable). Yield
                        // briefly so we don't spin on the cached watch value
                        // before the coordinator posts the next transition.
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(e) => {
                        tracing::warn!(%task_id, error = %e, "wait_task failed, releasing permit");
                        break;
                    }
                }
            }
        });
        if let Ok(mut handles) = self.inner.release_handles.lock() {
            handles.push(handle.abort_handle());
        }
    }
}
