use std::{collections::BTreeMap, sync::Arc};

use hashbrown::{HashMap, HashSet};
use mti::prelude::{MagicTypeIdExt, V7};
use sp1_prover_types::{ProofRequestStatus, TaskStatus, TaskType};
use tokio::sync::{mpsc, watch, RwLock};

use crate::worker::{
    ProofId, RawTaskRequest, SubscriberBuilder, TaskId, TaskMetadata, WorkerClient,
};

type LocalDb =
    Arc<RwLock<HashMap<TaskId, (watch::Sender<TaskStatus>, watch::Receiver<TaskStatus>)>>>;

type ProofIndex = Arc<RwLock<HashMap<ProofId, HashSet<TaskId>>>>;

pub struct LocalWorkerClientChannels {
    pub task_receivers: BTreeMap<TaskType, mpsc::Receiver<(TaskId, RawTaskRequest)>>,
}

pub struct LocalWorkerClientInner {
    db: LocalDb,
    proof_index: ProofIndex,
    input_task_queues: HashMap<TaskType, mpsc::Sender<(TaskId, RawTaskRequest)>>,
}

impl LocalWorkerClientInner {
    fn create_id() -> TaskId {
        TaskId::new("local_worker".create_type_id::<V7>().to_string())
    }

    fn init() -> (Self, LocalWorkerClientChannels) {
        let mut task_outputs = BTreeMap::new();
        let mut task_queues = HashMap::new();
        for task_type in [
            TaskType::UnspecifiedTaskType,
            TaskType::Controller,
            TaskType::ProveShard,
            TaskType::RecursionReduce,
            TaskType::RecursionDeferred,
            TaskType::ShrinkWrap,
            TaskType::SetupVkey,
            TaskType::MarkerDeferredRecord,
            TaskType::PlonkWrap,
            TaskType::Groth16Wrap,
            TaskType::ExecuteOnly,
            TaskType::UtilVkeyMapChunk,
            TaskType::UtilVkeyMapController,
        ] {
            let (tx, rx) = mpsc::channel(1);
            task_outputs.insert(task_type, rx);
            task_queues.insert(task_type, tx);
        }

        let db = Arc::new(RwLock::new(HashMap::new()));
        let proof_index = Arc::new(RwLock::new(HashMap::new()));
        let inner = Self { db, proof_index, input_task_queues: task_queues };
        (inner, LocalWorkerClientChannels { task_receivers: task_outputs })
    }
}

pub struct LocalWorkerClient {
    inner: Arc<LocalWorkerClientInner>,
}

impl LocalWorkerClient {
    /// Creates a new local worker client.
    #[must_use]
    pub fn init() -> (Self, LocalWorkerClientChannels) {
        let (inner, channels) = LocalWorkerClientInner::init();
        (Self { inner: Arc::new(inner) }, channels)
    }

    pub async fn update_task_status(
        &self,
        task_id: TaskId,
        status: TaskStatus,
    ) -> anyhow::Result<()> {
        // Get the sender for this task
        let (status_tx, _) = self
            .inner
            .db
            .read()
            .await
            .get(&task_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("task does not exist"))?;

        status_tx.send(status).map_err(|_| anyhow::anyhow!("failed to send status to task"))?;
        Ok(())
    }
}

impl Clone for LocalWorkerClient {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl WorkerClient for LocalWorkerClient {
    async fn submit_task(&self, kind: TaskType, task: RawTaskRequest) -> anyhow::Result<TaskId> {
        tracing::debug!("submitting task of kind {kind:?}");
        let task_id = LocalWorkerClientInner::create_id();
        // Add the task to the proof index.
        self.inner
            .proof_index
            .write()
            .await
            .entry(task.context.proof_id.clone())
            .or_insert_with(HashSet::new)
            .insert(task_id.clone());
        // Create a db entry for the task.
        let (tx, rx) = watch::channel(TaskStatus::Pending);
        self.inner.db.write().await.insert(task_id.clone(), (tx, rx));
        // Send the task to the input queue.
        self.inner.input_task_queues[&kind]
            .send((task_id.clone(), task))
            .await
            .map_err(|e| anyhow::anyhow!("failed to send task of kind {:?} to queue: {e}", kind))?;
        Ok(task_id)
    }

    async fn complete_task(
        &self,
        _proof_id: ProofId,
        task_id: TaskId,
        _metadata: TaskMetadata,
    ) -> anyhow::Result<()> {
        self.update_task_status(task_id, TaskStatus::Succeeded).await
    }

    async fn complete_proof(
        &self,
        proof_id: ProofId,
        _task_id: Option<TaskId>,
        _status: ProofRequestStatus,
        _extra_data: impl Into<String> + Send,
    ) -> anyhow::Result<()> {
        // Remove the proof from the proof index.
        let tasks = self
            .inner
            .proof_index
            .write()
            .await
            .remove(&proof_id)
            .ok_or_else(|| anyhow::anyhow!("proof does not exist for id {proof_id}"))?;
        // Prune the db for all tasks that are related to this proof and clean them up.
        for task_id in tasks {
            self.inner.db.write().await.remove(&task_id);
        }
        Ok(())
    }

    async fn subscriber(&self, _proof_id: ProofId) -> anyhow::Result<SubscriberBuilder<Self>> {
        let (subscriber_input_tx, mut subscriber_input_rx) = mpsc::unbounded_channel();
        let (subscriber_output_tx, subscriber_output_rx) = mpsc::unbounded_channel();

        tokio::task::spawn({
            let db = self.inner.db.clone();
            let output_tx = subscriber_output_tx.clone();
            async move {
                while let Some(id) = subscriber_input_rx.recv().await {
                    // Spawn a task to send the status to the output channel.
                    let db = db.clone();
                    let output_tx = output_tx.clone();
                    tokio::task::spawn(async move {
                        let (_, mut rx) =
                            db.read().await.get(&id).cloned().expect("task does not exist");
                        rx.mark_changed();
                        while let Ok(()) = rx.changed().await {
                            let value = *rx.borrow();
                            if matches!(
                                value,
                                TaskStatus::FailedFatal
                                    | TaskStatus::FailedRetryable
                                    | TaskStatus::Succeeded
                            ) {
                                output_tx.send((id, value)).ok();
                                return;
                            }
                        }
                    });
                }
            }
        });
        Ok(SubscriberBuilder::new(self.clone(), subscriber_input_tx, subscriber_output_rx))
    }
}

#[cfg(test)]
pub mod test_utils {
    use std::{ops::Range, time::Duration};

    use rand::Rng;

    use super::*;

    pub fn mock_worker_client(
        mut random_interval: HashMap<TaskType, Range<Duration>>,
    ) -> LocalWorkerClient {
        let (worker_client, mut channels) = LocalWorkerClient::init();

        for task_type in [
            TaskType::Controller,
            TaskType::SetupVkey,
            TaskType::ProveShard,
            TaskType::MarkerDeferredRecord,
            TaskType::RecursionReduce,
            TaskType::RecursionDeferred,
            TaskType::ShrinkWrap,
            TaskType::PlonkWrap,
            TaskType::Groth16Wrap,
            TaskType::ExecuteOnly,
        ] {
            let mut rx = channels.task_receivers.remove(&task_type).unwrap();
            let interval = random_interval.remove(&task_type).unwrap();
            let worker_client = worker_client.clone();
            tokio::task::spawn(async move {
                while let Some((task_id, request)) = rx.recv().await {
                    let client = worker_client.clone();
                    let interval = interval.clone();
                    tokio::spawn(async move {
                        let duration = {
                            let mut rng = rand::thread_rng();
                            rng.gen_range(interval)
                        };
                        tokio::time::sleep(duration).await;
                        client
                            .complete_task(
                                request.context.proof_id,
                                task_id,
                                TaskMetadata { gpu_time: None },
                            )
                            .await
                            .unwrap();
                    });
                }
            });
        }

        worker_client
    }
}
