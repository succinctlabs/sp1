use core::fmt;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
};

use futures::{prelude::*, stream::FuturesOrdered};
use hashbrown::{HashMap, HashSet};
use mti::prelude::{MagicTypeIdExt, V7};
use opentelemetry::Context;
use serde::{Deserialize, Serialize};
use sp1_prover_types::{
    Artifact, ArtifactClient, ArtifactType, ProofRequestStatus, TaskStatus, TaskType,
};

/// An event received from a task's subscriber channel.
///
/// Wraps both status transitions and custom messages sent by the task.
#[derive(Debug, Clone)]
pub enum TaskEvent {
    StatusChanged(TaskStatus),
    Message(Vec<u8>),
}

impl TaskEvent {
    /// Returns the status if this is a status event, or `None` for messages.
    pub fn status(&self) -> Option<TaskStatus> {
        match self {
            TaskEvent::StatusChanged(s) => Some(*s),
            TaskEvent::Message(_) => None,
        }
    }

    /// Returns the payload if this is a message event, or `None` for status changes.
    pub fn message(&self) -> Option<&[u8]> {
        match self {
            TaskEvent::Message(m) => Some(m),
            TaskEvent::StatusChanged(_) => None,
        }
    }

    pub fn is_terminal_status(&self) -> bool {
        matches!(
            self,
            TaskEvent::StatusChanged(
                TaskStatus::FailedFatal | TaskStatus::FailedRetryable | TaskStatus::Succeeded
            )
        )
    }
}
use thiserror::Error;
use tokio::{
    sync::{mpsc, watch, RwLock},
    task::AbortHandle,
};

mod local;

pub use local::*;

use crate::worker::{ProveShardTaskRequest, TaskError};

pub trait WorkerClient: Send + Sync + Clone + 'static {
    fn submit_task(
        &self,
        kind: TaskType,
        task: RawTaskRequest,
    ) -> impl Future<Output = anyhow::Result<TaskId>> + Send;

    fn complete_task(
        &self,
        proof_id: ProofId,
        task_id: TaskId,
        metadata: TaskMetadata,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn complete_proof(
        &self,
        proof_id: ProofId,
        task_id: Option<TaskId>,
        status: ProofRequestStatus,
        extra_data: impl Into<String> + Send,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn subscriber(
        &self,
        proof_id: ProofId,
    ) -> impl Future<Output = anyhow::Result<SubscriberBuilder<Self>>> + Send;

    fn send_message(
        &self,
        proof_id: ProofId,
        task_id: TaskId,
        message: Vec<u8>,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn submit_tasks(
        &self,
        kind: TaskType,
        tasks: impl IntoIterator<Item = RawTaskRequest> + Send,
    ) -> impl Future<Output = anyhow::Result<Vec<TaskId>>> + Send {
        tasks
            .into_iter()
            .map(move |task| self.submit_task(kind, task))
            .collect::<FuturesOrdered<_>>()
            .try_collect()
    }

    fn submit_all(
        &self,
        kind: TaskType,
        tasks: impl Stream<Item = RawTaskRequest> + Send,
    ) -> impl Future<Output = anyhow::Result<Vec<TaskId>>> + Send {
        tasks.then(move |task| self.submit_task(kind, task)).try_collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProofId(String);

impl ProofId {
    #[inline]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for ProofId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0) // TODO: nicely indicate that it is a proof id. Right now, it messes
                                // with the coordinator communication.
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TaskId(String);

impl TaskId {
    #[inline]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0) // TODO: nicely indicate that it is a task id. Right now, it messes
                                // with the coordinator communication.
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequesterId(String);

impl RequesterId {
    #[inline]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for RequesterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone)]
pub struct RawTaskRequest {
    pub inputs: Vec<Artifact>,
    pub outputs: Vec<Artifact>,
    pub context: TaskContext,
}

#[derive(Clone)]
pub struct TaskContext {
    pub proof_id: ProofId,
    pub parent_id: Option<TaskId>,
    pub parent_context: Option<Context>,
    pub requester_id: RequesterId,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct TaskMetadata {
    pub gpu_time: Option<u64>,
}

pub struct SubscriberBuilder<W> {
    client: W,
    subscriber_tx: mpsc::UnboundedSender<TaskId>,
    subscriber_rx: mpsc::UnboundedReceiver<(TaskId, TaskEvent)>,
}

impl<W> SubscriberBuilder<W> {
    pub fn new(
        client: W,
        subscriber_tx: mpsc::UnboundedSender<TaskId>,
        subscriber_rx: mpsc::UnboundedReceiver<(TaskId, TaskEvent)>,
    ) -> Self {
        Self { client, subscriber_tx, subscriber_rx }
    }

    pub fn per_task(self) -> TaskSubscriber<W> {
        TaskSubscriber::new(self)
    }

    pub fn stream(self) -> (StreamSubscriber<W>, EventStream) {
        StreamSubscriber::new(self)
    }
}

type TaskSubscriberDb =
    Arc<RwLock<HashMap<TaskId, (watch::Sender<TaskStatus>, watch::Receiver<TaskStatus>)>>>;

type TaskMessageDb = Arc<RwLock<HashMap<TaskId, mpsc::UnboundedSender<Vec<u8>>>>>;

// TODO: maybe traitify this struct to allow more flexibility in implementations.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct TaskSubscriber<W> {
    client: W,
    request_map: TaskSubscriberDb,
    message_map: TaskMessageDb,
    subscriber_tx: mpsc::UnboundedSender<TaskId>,
    abort_handle: AbortHandle,
}

impl<W> TaskSubscriber<W> {
    /// Get a reference to the client.
    #[inline]
    pub const fn client(&self) -> &W {
        &self.client
    }

    /// Create a new task subscriber.
    pub fn new(builder: SubscriberBuilder<W>) -> Self {
        let SubscriberBuilder { client, subscriber_tx, mut subscriber_rx, .. } = builder;
        let request_map = Arc::new(RwLock::new(HashMap::<
            TaskId,
            (watch::Sender<TaskStatus>, watch::Receiver<TaskStatus>),
        >::new()));
        let message_map: TaskMessageDb = Arc::new(RwLock::new(HashMap::new()));

        let handle = tokio::task::spawn({
            let request_map = request_map.clone();
            let message_map = message_map.clone();
            async move {
                while let Some((task_id, event)) = subscriber_rx.recv().await {
                    match event {
                        TaskEvent::StatusChanged(status) => {
                            let (sender, _) = request_map
                                .read()
                                .await
                                .get(&task_id)
                                .cloned()
                                .expect("task should be in request map");
                            sender.send(status).ok();
                        }
                        TaskEvent::Message(payload) => {
                            if let Some(tx) = message_map.read().await.get(&task_id).cloned() {
                                tx.send(payload).ok();
                            }
                        }
                    }
                }
            }
        });
        let abort_handle = handle.abort_handle();

        Self { client, request_map, message_map, subscriber_tx, abort_handle }
    }

    /// Close the task subscriber.
    ///
    /// The subscriber will no longer receive updates on the status of the tasks.
    pub fn close(&self) {
        self.abort_handle.abort();
    }

    /// Wait for a task to complete, discarding any custom messages.
    pub async fn wait_task(&self, task_id: TaskId) -> Result<TaskStatus, TaskError> {
        self.request_map
            .write()
            .await
            .entry(task_id.clone())
            .or_insert_with(|| watch::channel(TaskStatus::UnspecifiedStatus));

        let (_, mut watch) = self
            .request_map
            .read()
            .await
            .get(&task_id)
            .cloned()
            .ok_or(TaskError::Fatal(anyhow::anyhow!("task does not exist")))?;

        self.subscriber_tx.send(task_id.clone()).map_err(|e| {
            TaskError::Fatal(anyhow::anyhow!("failed to send task id to inner subscriber: {e}"))
        })?;

        watch.mark_changed();
        while let Ok(()) = watch.changed().await {
            let v = *watch.borrow();
            if matches!(
                v,
                TaskStatus::FailedFatal | TaskStatus::FailedRetryable | TaskStatus::Succeeded
            ) {
                return Ok(v);
            }
        }
        Err(TaskError::Fatal(anyhow::anyhow!("task status lost for task {task_id}")))
    }

    /// Wait for a task to complete while receiving custom messages on the returned channel.
    pub async fn wait_task_with_messages(
        &self,
        task_id: TaskId,
    ) -> Result<(TaskStatus, mpsc::UnboundedReceiver<Vec<u8>>), TaskError> {
        let (msg_tx, msg_rx) = mpsc::unbounded_channel();
        self.message_map.write().await.insert(task_id.clone(), msg_tx);

        let status = self.wait_task(task_id.clone()).await?;

        self.message_map.write().await.remove(&task_id);
        Ok((status, msg_rx))
    }
}

#[derive(Debug, Error)]
#[error("failed to subscribe to task {0}")]
pub struct SubscribeError(#[from] mpsc::error::SendError<TaskId>);

// TODO: maybe traitify this struct to allow more flexibility in implementations.
#[derive(Clone)]
pub struct StreamSubscriber<W> {
    client: W,
    subscriber_tx: mpsc::UnboundedSender<TaskId>,
}

impl<W> StreamSubscriber<W> {
    /// Get a reference to the client.
    #[inline]
    pub const fn client(&self) -> &W {
        &self.client
    }

    /// Create a new task subscriber.
    fn new(builder: SubscriberBuilder<W>) -> (Self, EventStream) {
        let SubscriberBuilder { client, subscriber_tx, subscriber_rx, .. } = builder;
        (Self { client, subscriber_tx }, EventStream { subscriber_rx })
    }

    pub fn subscribe(&self, task_id: TaskId) -> Result<(), SubscribeError> {
        self.subscriber_tx.send(task_id)?;
        Ok(())
    }
}

pub struct EventStream {
    subscriber_rx: mpsc::UnboundedReceiver<(TaskId, TaskEvent)>,
}

impl EventStream {
    pub async fn recv(&mut self) -> Option<(TaskId, TaskEvent)> {
        self.subscriber_rx.recv().await
    }

    /// Receive the next status event, skipping any custom messages.
    pub async fn recv_status(&mut self) -> Option<(TaskId, TaskStatus)> {
        loop {
            match self.subscriber_rx.recv().await {
                Some((id, TaskEvent::StatusChanged(status))) => return Some((id, status)),
                Some((_, TaskEvent::Message(_))) => continue,
                None => return None,
            }
        }
    }

    pub fn blocking_recv(&mut self) -> Option<(TaskId, TaskEvent)> {
        self.subscriber_rx.blocking_recv()
    }

    pub fn close(&mut self) {
        self.subscriber_rx.close();
    }
}

impl Stream for EventStream {
    type Item = (TaskId, TaskEvent);

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.subscriber_rx.poll_recv(cx)
    }
}

/// A trivial client that can be used for testing
#[derive(Clone, Debug)]
pub struct TrivialWorkerClient {
    inner: Arc<Mutex<HashSet<TaskId>>>,
    task_sender: mpsc::Sender<(TaskType, RawTaskRequest)>,
}

impl TrivialWorkerClient {
    pub fn new<A: ArtifactClient>(task_capacity: usize, artifact_client: A) -> Self {
        let (task_sender, mut task_receiver) =
            mpsc::channel::<(TaskType, RawTaskRequest)>(task_capacity);

        tokio::task::spawn(async move {
            while let Some((kind, task)) = task_receiver.recv().await {
                match kind {
                    TaskType::ProveShard => {
                        let request = ProveShardTaskRequest::from_raw(task).unwrap();
                        // remove the record artifact from the client
                        artifact_client
                            .delete(&request.record, ArtifactType::UnspecifiedArtifactType)
                            .await
                            .unwrap();
                    }
                    TaskType::MarkerDeferredRecord => {}
                    _ => unimplemented!("task type not supported"),
                }
            }
        });

        Self { inner: Arc::new(Mutex::new(HashSet::new())), task_sender }
    }
}

impl WorkerClient for TrivialWorkerClient {
    async fn submit_task(&self, kind: TaskType, task: RawTaskRequest) -> anyhow::Result<TaskId> {
        let task_id = TaskId::new("task".create_type_id::<V7>().to_string());
        self.inner.lock().unwrap().insert(task_id.clone());
        self.task_sender.send((kind, task)).await.unwrap();
        Ok(task_id)
    }

    async fn complete_task(
        &self,
        _proof_id: ProofId,
        _task_id: TaskId,
        _metadata: TaskMetadata,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn complete_proof(
        &self,
        _proof_id: ProofId,
        _task_id: Option<TaskId>,
        _status: ProofRequestStatus,
        _extra_data: impl Into<String> + Send,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn subscriber(&self, _proof_id: ProofId) -> anyhow::Result<SubscriberBuilder<Self>> {
        let (sub_input_tx, mut sub_input_rx) = mpsc::unbounded_channel();
        let (sub_output_tx, sub_output_rx) = mpsc::unbounded_channel();

        let task_map = self.inner.clone();
        tokio::task::spawn(async move {
            while let Some(task_id) = sub_input_rx.recv().await {
                if task_map.lock().unwrap().contains(&task_id) {
                    sub_output_tx
                        .send((task_id, TaskEvent::StatusChanged(TaskStatus::Succeeded)))
                        .unwrap();
                } else {
                    sub_output_tx
                        .send((task_id, TaskEvent::StatusChanged(TaskStatus::Pending)))
                        .unwrap();
                }
            }
        });

        Ok(SubscriberBuilder::new(self.clone(), sub_input_tx, sub_output_rx))
    }

    async fn send_message(
        &self,
        _proof_id: ProofId,
        _task_id: TaskId,
        _message: Vec<u8>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use mti::prelude::{MagicTypeIdExt, V7};
    use sp1_prover_types::{ArtifactClient, InMemoryArtifactClient};

    use super::*;

    /// A simnple test worker consisting a single thread that runs a single counter.
    ///
    /// This client support two tasks:
    ///    - Increment the counter
    //     - Read the current value
    #[derive(Clone)]
    #[allow(clippy::type_complexity)]
    pub struct TestWorkerClient {
        input_tx: mpsc::UnboundedSender<(TaskId, RawTaskRequest)>,
        db: TaskSubscriberDb,
    }

    #[derive(Serialize, Deserialize, Clone, Copy)]
    pub enum TestTaskKind {
        Increment,
        Read,
    }

    #[derive(Serialize, Deserialize)]
    pub struct TestTask {
        pub kind: TestTaskKind,
    }

    impl TestTask {
        pub async fn into_raw(self, client: &impl ArtifactClient) -> RawTaskRequest {
            let input_artifact = client.create_artifact().expect("failed to create input artifact");
            client.upload(&input_artifact, self.kind).await.unwrap();
            let outputs = if let TestTaskKind::Read = self.kind {
                let artifact = client.create_artifact().expect("failed to create output artifact");
                vec![artifact]
            } else {
                vec![]
            };
            RawTaskRequest {
                inputs: vec![input_artifact],
                outputs,
                context: TaskContext {
                    proof_id: ProofId::new("test_proof_id"),
                    parent_id: None,
                    parent_context: None,
                    requester_id: RequesterId::new("test_requester_id"),
                },
            }
        }

        async fn from_raw(
            raw: RawTaskRequest,
            client: &impl ArtifactClient,
        ) -> (Self, Option<Artifact>) {
            let kind = client.download::<TestTaskKind>(&raw.inputs[0]).await.unwrap();
            (Self { kind }, raw.outputs.into_iter().next())
        }
    }

    impl TestWorkerClient {
        fn new(artifact_client: impl ArtifactClient) -> Self {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let db = Arc::new(RwLock::new(HashMap::<
                TaskId,
                (watch::Sender<TaskStatus>, watch::Receiver<TaskStatus>),
            >::new()));

            tokio::task::spawn({
                let db = db.clone();
                async move {
                    let mut counter: usize = 0;
                    while let Some((id, task)) = rx.recv().await {
                        let (task, output) = TestTask::from_raw(task, &artifact_client).await;
                        match task.kind {
                            TestTaskKind::Increment => {
                                counter += 1;
                                let (tx, _) =
                                    db.read().await.get(&id).cloned().expect("task does not exist");
                                tx.send(TaskStatus::Succeeded).unwrap();
                            }
                            TestTaskKind::Read => {
                                let out_artifact = output.unwrap();
                                artifact_client.upload(&out_artifact, counter).await.unwrap();
                                let (tx, _) =
                                    db.read().await.get(&id).cloned().expect("task does not exist");
                                tx.send(TaskStatus::Succeeded).unwrap();
                            }
                        }
                    }
                }
            });

            Self { input_tx: tx, db }
        }
    }

    impl WorkerClient for TestWorkerClient {
        async fn submit_task(
            &self,
            _kind: TaskType,
            task: RawTaskRequest,
        ) -> anyhow::Result<TaskId> {
            let task_id = TaskId::new("task".create_type_id::<V7>().to_string());
            // Add the task to the db.
            let (tx, rx) = watch::channel(TaskStatus::Pending);
            self.db.write().await.insert(task_id.clone(), (tx, rx));
            self.input_tx.send((task_id.clone(), task)).unwrap();
            Ok(task_id)
        }

        async fn complete_task(
            &self,
            _proof_id: ProofId,
            _task_id: TaskId,
            _metadata: TaskMetadata,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }

        async fn complete_proof(
            &self,
            _proof_id: ProofId,
            _task_id: Option<TaskId>,
            _status: ProofRequestStatus,
            _extra_data: impl Into<String> + Send,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }

        async fn subscriber(&self, _proof_id: ProofId) -> anyhow::Result<SubscriberBuilder<Self>> {
            let (subscriber_input_tx, mut subscriber_input_rx) = mpsc::unbounded_channel();
            let (subscriber_output_tx, subscriber_output_rx) = mpsc::unbounded_channel();

            tokio::task::spawn({
                let db = self.db.clone();
                let output_tx = subscriber_output_tx.clone();
                async move {
                    while let Some(id) = subscriber_input_rx.recv().await {
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
                                    output_tx.send((id, TaskEvent::StatusChanged(value))).ok();
                                    return;
                                }
                            }
                        });
                    }
                }
            });
            Ok(SubscriberBuilder::new(self.clone(), subscriber_input_tx, subscriber_output_rx))
        }

        async fn send_message(
            &self,
            _proof_id: ProofId,
            _task_id: TaskId,
            _message: Vec<u8>,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    #[allow(clippy::print_stdout)]
    async fn test_worker_client() {
        let artifact_client = InMemoryArtifactClient::default();
        let worker_client = TestWorkerClient::new(artifact_client.clone());
        let increment_task = TestTask { kind: TestTaskKind::Increment };
        let increment_task = increment_task.into_raw(&artifact_client).await;
        let read_task = TestTask { kind: TestTaskKind::Read };
        let read_task = read_task.into_raw(&artifact_client).await;

        // Create a subscriber to receive the task status.
        let subscriber =
            worker_client.subscriber(ProofId::new("dummy proof id")).await.unwrap().per_task();

        // Submit tasks, single threaded.
        let mut increment_tasks = vec![];
        for i in 0..10 {
            let subscriber = subscriber.clone();
            let increment_task = increment_task.clone();
            let handle = tokio::task::spawn(async move {
                tokio::time::sleep(Duration::from_millis(100 * i)).await;
                subscriber
                    .client()
                    .submit_task(TaskType::UnspecifiedTaskType, increment_task.clone())
                    .await
                    .unwrap()
            });
            increment_tasks.push(handle);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let read_task_id = subscriber
            .client()
            .submit_task(TaskType::UnspecifiedTaskType, read_task.clone())
            .await
            .unwrap();

        // Read the value once the read task is complete.

        // Get the status of the read task.
        let status = subscriber.wait_task(read_task_id).await.unwrap();
        // Assert that the read task is complete.
        assert_eq!(status, TaskStatus::Succeeded);
        // Assert that the status of the increment tasks is complete.
        let mut increment_task_ids = vec![];
        for handle in increment_tasks {
            let task_id = handle.await.unwrap();
            increment_task_ids.push(task_id);
        }
        for task_id in increment_task_ids {
            let status = subscriber.wait_task(task_id).await.unwrap();
            assert_eq!(status, TaskStatus::Succeeded);
        }
        // // Read the value from the artifact client.
        let (_, output) = TestTask::from_raw(read_task, &artifact_client).await;
        let output = output.unwrap();
        let value: usize = artifact_client.download(&output).await.unwrap();
        println!("value: {}", value);
        assert!(value <= 10);
    }
}
