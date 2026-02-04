use std::sync::Arc;

use futures::StreamExt;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use sp1_core_executor::{ExecutionRecord, Program, SP1CoreOpts, SplitOpts, SyscallCode};
use sp1_hypercube::air::ShardRange;
use sp1_prover_types::{await_scoped_vec, Artifact, ArtifactClient, ArtifactType, TaskStatus};
use tokio::{sync::mpsc, task::JoinSet};
use tracing::Instrument;

use crate::worker::{
    controller::create_core_proving_task, ProofData, SpawnProveOutput, TaskContext, TaskError,
    TaskId, TraceData, WorkerClient,
};

/// String used as key for add_ref to ensure precompile artifacts are not cleaned up before they
/// are fully split into multiple shards.
const CONTROLLER_PRECOMPILE_ARTIFACT_REF: &str = "_controller";

/// An artifact of precompile events, and the range of indices to index into.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecompileArtifactSlice {
    pub artifact: Artifact,
    pub start_idx: usize,
    pub end_idx: usize,
}

/// A lightweight container for the precompile events in a shard.
///
/// Rather than actually holding all of the events, the events are represented as `Artifact`s with
/// start and end indices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredEvents(pub HashMap<SyscallCode, Vec<PrecompileArtifactSlice>>);

impl DeferredEvents {
    /// Defer all events in an ExecutionRecord by uploading each precompile in chunks.
    pub async fn defer_record<A: ArtifactClient>(
        record: ExecutionRecord,
        client: &A,
        split_opts: SplitOpts,
    ) -> Result<DeferredEvents, TaskError> {
        // Move all synchronous work (iteration, chunking) into spawn_blocking
        // to avoid blocking the async runtime.
        let chunk_data = tokio::task::spawn_blocking(move || {
            let mut chunk_data = Vec::new();
            for (code, events) in record.precompile_events.events.iter() {
                let threshold = split_opts.syscall_threshold[*code];
                for chunk in events.chunks(threshold) {
                    chunk_data.push((*code, chunk.to_vec()));
                }
            }
            chunk_data
        })
        .await
        .map_err(|e| TaskError::Fatal(e.into()))?;

        // Create all artifacts in batch (this is cheap - just generates IDs)
        let artifacts =
            client.create_artifacts(chunk_data.len()).map_err(TaskError::Fatal)?.to_vec();

        // Build futures with pre-created artifacts and run uploads in parallel
        let futures = chunk_data
            .into_iter()
            .zip(artifacts.into_iter())
            .map(|((code, chunk), artifact)| {
                let client = client.clone();
                async move {
                    client.upload(&artifact, &chunk).await.unwrap();
                    (code, artifact, chunk.len())
                }
            })
            .collect::<Vec<_>>();

        let res =
            await_scoped_vec(futures).await.map_err(|e| TaskError::Fatal(anyhow::anyhow!(e)))?;

        let mut deferred: HashMap<SyscallCode, Vec<PrecompileArtifactSlice>> = HashMap::new();
        for (code, artifact, count) in res {
            deferred.entry(code).or_default().push(PrecompileArtifactSlice {
                artifact,
                start_idx: 0,
                end_idx: count,
            });
        }
        Ok(DeferredEvents(deferred))
    }

    /// Create an empty DeferredEvents.
    pub fn empty() -> Self {
        Self(HashMap::new())
    }

    /// Append the events from another DeferredEvents to self. Analogous to
    /// `ExecutionRecord::append`.
    pub async fn append(&mut self, other: DeferredEvents, client: &impl ArtifactClient) {
        for (code, events) in other.0 {
            // Add task references for artifacts so they are not cleaned up before they are fully
            // split.
            for PrecompileArtifactSlice { artifact, .. } in &events {
                if let Err(e) = client.add_ref(artifact, CONTROLLER_PRECOMPILE_ARTIFACT_REF).await {
                    tracing::error!("Failed to add ref to artifact {:?}: {:?}", artifact, e);
                }
            }
            self.0.entry(code).or_default().extend(events);
        }
    }

    /// Split the DeferredEvents into multiple TraceData. Similar to `ExecutionRecord::split`.
    pub async fn split(
        &mut self,
        last: bool,
        opts: SplitOpts,
        client: &impl ArtifactClient,
    ) -> Vec<TraceData> {
        let mut shards = Vec::new();
        let keys = self.0.keys().cloned().collect::<Vec<_>>();
        for code in keys {
            let threshold = opts.syscall_threshold[code];
            // self.0[code] contains uploaded artifacts with start and end indices. start is
            // initially 0. Create shards of precompiles from self.0[code] up to
            // threshold, then update new [start, end) indices for future splits. If
            // last is true, don't leave any remainder.
            loop {
                let mut count = 0;
                // Loop through until we've found enough precompiles, and remove from self.0[code].
                // `index` will be set such that artifacts [0, index) will be made into a shard.
                let mut index = 0;
                for (i, artifact_slice) in self.0[&code].iter().enumerate() {
                    let PrecompileArtifactSlice { start_idx, end_idx, .. } = artifact_slice;
                    count += end_idx - start_idx;
                    // Break if we've found enough or it's the last Artifact and `last` is true.
                    if count >= threshold || (last && i == self.0[&code].len() - 1) {
                        index = i + 1;
                        break;
                    }
                }
                // If not enough was found, break.
                if index == 0 {
                    break;
                }
                // Otherwise remove the artifacts and handle remainder of last artifact if there is
                // any.
                let mut artifacts =
                    self.0.get_mut(&code).unwrap().drain(..index).collect::<Vec<_>>();
                // For each artifact, add refs for the range needed in prove_shard, and then remove
                // the controller ref if it's been fully split.
                for (i, slice) in artifacts.iter().enumerate() {
                    let PrecompileArtifactSlice { artifact, start_idx, end_idx } = slice;
                    if let Err(e) =
                        client.add_ref(artifact, &format!("{:?}_{:?}", start_idx, end_idx)).await
                    {
                        tracing::error!("Failed to add ref to artifact {}: {:?}", artifact, e);
                    }
                    // If there's a remainder, don't remove the controller ref yet.
                    if i == artifacts.len() - 1 && count > threshold {
                        break;
                    }
                    if let Err(e) = client
                        .remove_ref(
                            artifact,
                            ArtifactType::UnspecifiedArtifactType,
                            CONTROLLER_PRECOMPILE_ARTIFACT_REF,
                        )
                        .await
                    {
                        tracing::error!("Failed to remove ref to artifact {}: {:?}", artifact, e);
                    }
                }
                // If there's extra in the last artifact, truncate it and leave it in the front of
                // self.0[code].
                if count > threshold {
                    let mut new_range = artifacts.last().cloned().unwrap();
                    new_range.start_idx = new_range.end_idx - (count - threshold);
                    artifacts[index - 1].end_idx = new_range.start_idx;
                    self.0.get_mut(&code).unwrap().insert(0, new_range);
                }
                shards.push(TraceData::Precompile(artifacts, code));
            }
        }
        shards
    }
}

pub struct DeferredMessage {
    pub task_id: TaskId,
    pub record: Artifact,
}

pub fn precompile_channel(
    program: &Program,
    opts: &SP1CoreOpts,
) -> (mpsc::UnboundedSender<DeferredMessage>, PrecompileHandler) {
    let split_opts = SplitOpts::new(opts, program.instructions.len(), false);
    let (deferred_marker_tx, deferred_marker_rx) = mpsc::unbounded_channel();
    (deferred_marker_tx, PrecompileHandler { split_opts, deferred_marker_rx })
}

pub struct PrecompileHandler {
    split_opts: SplitOpts,
    deferred_marker_rx: mpsc::UnboundedReceiver<DeferredMessage>,
}

impl PrecompileHandler {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn emit_precompile_shards(
        self,
        elf_artifact: Artifact,
        common_input_artifact: Artifact,
        prove_shard_tx: mpsc::UnboundedSender<ProofData>,
        artifact_client: impl ArtifactClient,
        worker_client: impl WorkerClient,
        context: TaskContext,
    ) -> Result<(), TaskError> {
        let precompile_range = ShardRange::precompile();
        let mut join_set = JoinSet::new();
        let task_data_map = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        let PrecompileHandler { split_opts, mut deferred_marker_rx } = self;

        // This subscriber monitors for deferred marker task completion
        let (subscriber, mut event_stream) =
            worker_client.subscriber(context.proof_id.clone()).await?.stream();
        join_set.spawn({
            let task_data_map = task_data_map.clone();
            async move {
                while let Some(deferred_message) = deferred_marker_rx.recv().await {
                    tracing::debug!(
                        "received deferred message with task id {:?}",
                        deferred_message.task_id
                    );
                    let DeferredMessage { task_id, record: deferred_events } = deferred_message;
                    task_data_map.lock().await.insert(task_id.clone(), deferred_events);
                    subscriber.subscribe(task_id.clone()).map_err(|e| {
                        TaskError::Fatal(anyhow::anyhow!(
                            "error subscribing to task {}: {}",
                            task_id,
                            e
                        ))
                    })?;
                }
                Ok::<_, TaskError>(())
            }
            .instrument(tracing::debug_span!("deferred listener"))
        });

        join_set.spawn({
            let worker_client = worker_client.clone();
            let artifact_client = artifact_client.clone();
            async move {
                let mut deferred_accumulator = DeferredEvents::empty();
                while let Some((task_id, status)) = event_stream.next().await {
                    tracing::debug!(
                        task_id = task_id.to_string(),
                        "received deferred marker task status: {:?}",
                        status
                    );
                    if status != TaskStatus::Succeeded {
                        return Err(TaskError::Fatal(anyhow::anyhow!(
                            "deferred marker task failed: {}",
                            task_id
                        )));
                    }
                    let deferred_events_artifact = task_data_map.lock().await.remove(&task_id);
                    if let Some(deferred_events_artifact) = deferred_events_artifact {
                        let deferred_events = artifact_client
                            .download::<DeferredEvents>(&deferred_events_artifact)
                            .await;
                        if deferred_events.is_err() {
                            tracing::error!(
                                "failed to download deferred events artifact: {:?}",
                                deferred_events_artifact
                            );
                        }
                        // TODO: figure out how to return this as an error while still
                        // being able to run pure execution without proving.
                        let deferred_events =
                            deferred_events.unwrap_or_else(|_| DeferredEvents::empty());

                        deferred_accumulator.append(deferred_events, &artifact_client).await;
                        let new_shards =
                            deferred_accumulator.split(false, split_opts, &artifact_client).await;

                        for shard in new_shards {
                            let SpawnProveOutput { deferred_message, proof_data } =
                                create_core_proving_task(
                                    elf_artifact.clone(),
                                    common_input_artifact.clone(),
                                    context.clone(),
                                    precompile_range,
                                    shard,
                                    worker_client.clone(),
                                    artifact_client.clone(),
                                )
                                .await
                                .map_err(|e| TaskError::Fatal(e.into()))?;

                            if deferred_message.is_some() {
                                return Err(TaskError::Fatal(anyhow::anyhow!(
                                    "deferred message is not none",
                                )));
                            }
                            prove_shard_tx.send(proof_data).map_err(|e| {
                                TaskError::Fatal(anyhow::anyhow!(
                                    "error sending to proving tx: {}",
                                    e
                                ))
                            })?;
                        }
                    } else {
                        tracing::debug!(
                            "deferred events artifact not found for task id: {}",
                            task_id
                        );
                    }
                }
                let final_shards = deferred_accumulator
                    .split(true, split_opts, &artifact_client)
                    .instrument(tracing::debug_span!("split last"))
                    .await;
                for shard in final_shards {
                    let SpawnProveOutput { deferred_message, proof_data } =
                        create_core_proving_task(
                            elf_artifact.clone(),
                            common_input_artifact.clone(),
                            context.clone(),
                            precompile_range,
                            shard,
                            worker_client.clone(),
                            artifact_client.clone(),
                        )
                        .await
                        .map_err(|e| TaskError::Fatal(e.into()))?;

                    debug_assert!(deferred_message.is_none());
                    prove_shard_tx.send(proof_data).map_err(|e| {
                        TaskError::Fatal(anyhow::anyhow!("error sending to proving tx: {}", e))
                    })?;
                }
                tracing::debug!("deferred listener task finished");
                Ok::<_, TaskError>(())
            }
            .instrument(tracing::debug_span!("deferred sender"))
        });

        while let Some(result) = join_set.join_next().await {
            result.map_err(|e| {
                TaskError::Fatal(anyhow::anyhow!("deferred listener task panicked: {}", e))
            })??;
        }
        Ok::<(), TaskError>(())
    }
}
