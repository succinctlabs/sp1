//! `SpliceChunkWorker` — the node body: proves one chunk end to end.
//!
//! Runs the SplicingVM over the chunk, generates every global commitment
//! in-process and broadcasts them as the chunk's Fiat-Shamir set, then proves
//! each shard (core + merkle) and emits the proofs. No cluster coordination.

use std::sync::Arc;

use futures::stream::{FuturesUnordered, StreamExt};
use slop_challenger::IopCtx;
use slop_futures::pipeline::{AsyncEngine, AsyncWorker, Pipeline};
use sp1_core_executor::{ExecutionError, ExecutionRecord, Program, SP1CoreOpts};
use sp1_core_machine::executor::trace_chunk;
use sp1_hypercube::{air::ShardRange, prover::ProverSemaphore};
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_prover_types::{Artifact, ArtifactClient};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
};

use sp1_core_machine::merkle_prover::BatchMerkleProver;

use crate::{
    worker::{
        controller::{ChunkPayload, TaskInput},
        order_commitments, AirProverWorker, CommitKind, CommonProverInput, MessageSender,
        ProofData, ProofKind, TaskError, WorkerClient,
    },
    SP1ProverComponents,
};

use super::{SendSpliceTask, SplicingTask, SplicingWorker};

/// AsyncEngine alias for the new chunk-splicing pipeline.
pub type SpliceChunkEngine<A, W, C> =
    AsyncEngine<SpliceChunkTask<W>, Result<(), ExecutionError>, SpliceChunkWorker<A, W, C>>;

/// One per-chunk task to be processed by [`SpliceChunkWorker`].
pub struct SpliceChunkTask<W: WorkerClient> {
    pub payload: TaskInput<ChunkPayload>,
    pub program: Arc<Program>,
    pub num_deferred_proofs: usize,
    pub common_input_artifact: Artifact,
    pub prove_shard_tx: MessageSender<W, ProofData>,
    pub opts: SP1CoreOpts,
}

/// The node body: owns one chunk end to end. Runs SplicingVM, generates all
/// global commitments + the barrier in-process, then proves every shard via
/// the shared prove path — no cluster coordination.
#[derive(Clone)]
pub struct SpliceChunkWorker<A: ArtifactClient, W: WorkerClient, C: SP1ProverComponents> {
    /// The artifact client (downloads the per-proof `CommonProverInput` at the
    /// top of `call` to extract the proof_nonce + global_dependencies_opt).
    artifact_client: A,
    /// The inner SplicingVM worker.
    inner: SplicingWorker<A>,
    /// The node's core AIR prover.
    core_prover: Arc<C::CoreProver>,
    /// The GPU permit pool.
    permits: ProverSemaphore,
    _marker: std::marker::PhantomData<W>,
}

impl<A, W, C> SpliceChunkWorker<A, W, C>
where
    A: ArtifactClient,
    W: WorkerClient,
    C: SP1ProverComponents,
{
    pub fn new(
        artifact_client: A,
        core_prover: Arc<C::CoreProver>,
        permits: ProverSemaphore,
    ) -> Self {
        let inner = SplicingWorker::new(artifact_client.clone());
        Self { artifact_client, inner, core_prover, permits, _marker: std::marker::PhantomData }
    }
}

impl<A, W, C> AsyncWorker<SpliceChunkTask<W>, Result<(), ExecutionError>>
    for SpliceChunkWorker<A, W, C>
where
    A: ArtifactClient,
    W: WorkerClient,
    C: SP1ProverComponents,
{
    async fn call(&self, input: SpliceChunkTask<W>) -> Result<(), ExecutionError> {
        let SpliceChunkTask {
            payload,
            program,
            num_deferred_proofs,
            common_input_artifact,
            prove_shard_tx,
            opts,
        } = input;

        let payload_arc: Arc<ChunkPayload> = payload.into_local().ok_or_else(|| {
            ExecutionError::Other(
                "SpliceChunkWorker received TaskInput::Remote(ChunkPayload) — \
                 ChunkPayload is local-only for now"
                    .into(),
            )
        })?;

        // One per-proof download of `CommonProverInput`.
        let common_prover_input = self
            .artifact_client
            .download::<CommonProverInput>(&common_input_artifact)
            .await
            .map_err(|e| ExecutionError::Other(format!("download common prover input: {e}")))?;
        let proof_nonce = common_prover_input.nonce;
        let global_dependencies_opt = opts.global_dependencies_opt;

        // Start the streaming splice. Cuts arrive on `cuts_rx`.
        // The final return carries the chunk's `MerkleProvingInput`.
        let splicing_task = SplicingTask {
            program: program.clone(),
            chunk: payload_arc.chunk.clone(),
            num_deferred_proofs,
            common_input_artifact,
            opts: opts.clone(),
            dirty_page_ids: payload_arc.dirty_page_ids.clone(),
            dirty_page_final_contents: payload_arc.dirty_page_final_contents.clone(),
        };
        let (cuts_tx, mut cuts_rx) = mpsc::channel::<SendSpliceTask>(2);
        let splice_handle = tokio::spawn({
            let inner = self.inner.clone();
            let payload_for_splice = payload_arc.clone();
            async move { inner.call_streaming(splicing_task, payload_for_splice, cuts_tx).await }
        });

        // Broadcasts the ordered global commitments to every shard task.
        let (commits_tx, commits_rx) =
            watch::channel::<Option<Arc<Vec<<SP1GlobalContext as IopCtx>::Digest>>>>(None);

        let mut commit_jobs: JoinSet<(CommitKind, u32, <SP1GlobalContext as IopCtx>::Digest)> =
            JoinSet::new();
        let mut shard_jobs: JoinSet<Result<(), ExecutionError>> = JoinSet::new();

        // Receive the shard cuts.
        while let Some(cut) = cuts_rx.recv().await {
            let seed = ExecutionRecord::from_shard_data(
                program.clone(),
                proof_nonce,
                global_dependencies_opt,
                cut.shard_data.clone(),
            );
            // Generate the global commitment from the shard data.
            {
                let rec = Arc::new(seed.clone());
                let prover = self.core_prover.clone();
                let permits = self.permits.clone();
                let shard_idx = cut.shard_index;
                commit_jobs.spawn(async move {
                    let commit = prover.generate_global_commitment(&rec, permits).await;
                    (CommitKind::Core, shard_idx, commit)
                });
            }
            // TracingVM runs without waiting for the global commitments.
            {
                let prover = self.core_prover.clone();
                let permits = self.permits.clone();
                let tx = prove_shard_tx.clone();
                let mut rx = commits_rx.clone();
                let prog = program.clone();
                let opts_c = opts.clone();
                let chunk = cut.chunk.clone();
                let range = cut.range;
                shard_jobs.spawn(async move {
                    let rec = tokio::task::spawn_blocking(move || {
                        let (_, rec, _) =
                            trace_chunk::<SP1Field>(prog, opts_c, chunk, proof_nonce, seed)?;
                        Ok::<_, ExecutionError>(rec)
                    })
                    .await
                    .map_err(|e| ExecutionError::Other(format!("trace_chunk join: {e}")))??;
                    // TODO(rkm): need to generate dependencies here.
                    // Once all the global commitments arrive, the shard proving begins.
                    rx.changed()
                        .await
                        .map_err(|_| ExecutionError::Other("commits sender dropped".into()))?;
                    let commitments: Arc<Vec<_>> =
                        rx.borrow().as_ref().expect("commits_tx sent Some").clone();
                    let proof = Box::new(prover.prove_shard(&rec, &commitments, permits).await);
                    tx.send(ProofData::InMemory { kind: ProofKind::Execution, range, proof })
                        .await
                        .map_err(|e| ExecutionError::Other(format!("send proof: {e}")))?;
                    Ok(())
                });
            }
            // `cut` drops here — the clones we needed (chunk, shard_data,
            // range, shard_index) are already inside the spawned tasks.
        }

        // SplicingVM is done, so merkle proving is ready to run.
        let merkle_input = splice_handle
            .await
            .map_err(|e| ExecutionError::Other(format!("splice task join: {e}")))??;
        let merkle_seed = self
            .core_prover
            .prepare_merkle_proof(
                merkle_input,
                program.clone(),
                proof_nonce,
                global_dependencies_opt,
                self.permits.clone(),
            )
            .await;
        // TODO(rkm): cut the merkle proof accordingly with the `SplitOpts`.
        let merkle_records: Vec<ExecutionRecord> = vec![merkle_seed];

        // Generate the global commitments from each merkle shard.
        for (m, rec) in merkle_records.iter().enumerate() {
            let rec_arc = Arc::new(rec.clone());
            let prover = self.core_prover.clone();
            let permits = self.permits.clone();
            let m_idx = m as u32;
            commit_jobs.spawn(async move {
                let commit = prover.generate_global_commitment(&rec_arc, permits).await;
                (CommitKind::Merkle, m_idx, commit)
            });
        }
        // Generate the proof for each merkle shard.
        for rec in merkle_records.into_iter() {
            let prover = self.core_prover.clone();
            let permits = self.permits.clone();
            let tx = prove_shard_tx.clone();
            let mut rx = commits_rx.clone();
            shard_jobs.spawn(async move {
                // TODO(rkm): generate the dependencies here.
                rx.changed()
                    .await
                    .map_err(|_| ExecutionError::Other("commits sender dropped".into()))?;
                let commitments: Arc<Vec<_>> =
                    rx.borrow().as_ref().expect("commits_tx sent Some").clone();
                let proof = Box::new(prover.prove_shard(&rec, &commitments, permits).await);
                tx.send(ProofData::InMemory {
                    kind: ProofKind::Merkle,
                    range: ShardRange::default(),
                    proof,
                })
                .await
                .map_err(|e| ExecutionError::Other(format!("send proof: {e}")))?;
                Ok(())
            });
        }

        // Drain all the global commitment work.
        let mut commits = Vec::new();
        while let Some(joined) = commit_jobs.join_next().await {
            commits.push(
                joined.map_err(|e| ExecutionError::Other(format!("commit job panicked: {e}")))?,
            );
        }
        // Sort the commitments, and send it in order.
        let commitments = order_commitments(commits);
        let _ = commits_tx.send(Some(Arc::new(commitments)));
        drop(commits_tx);

        // Drain shard jobs — each emits its own proof on completion.
        while let Some(joined) = shard_jobs.join_next().await {
            joined.map_err(|e| ExecutionError::Other(format!("shard job panicked: {e}")))??;
        }
        // Explicit drop makes `commits_tx.send` safe.
        drop(commits_rx);

        Ok(())
    }
}

/// Drive the node's per-chunk splice/commit/prove pipeline.
///
/// Pulls each chunk task off the bounded channel, submits it to the splice
/// `engine`, and drains every chunk's handle before returning — so a chunk still
/// proving when the JIT finishes (channel closed) is awaited before the
/// `CoreExecute` task completes, and no proof is dropped.
pub async fn drive_chunk_consumer<T, P>(
    engine: Arc<P>,
    mut chunk_rx: mpsc::Receiver<T>,
) -> Result<(), TaskError>
where
    T: 'static + Send + Sync,
    P: Pipeline<Input = T, Output = Result<(), ExecutionError>>,
{
    let mut handles = FuturesUnordered::new();
    loop {
        tokio::select! {
            maybe_task = chunk_rx.recv() => match maybe_task {
                Some(task) => {
                    let handle = engine.submit(task).await.map_err(|e| {
                        TaskError::Fatal(anyhow::anyhow!("submit SpliceChunk task: {e}"))
                    })?;
                    handles.push(handle);
                }
                // Producer (JIT) done — drain whatever is still proving.
                None => {
                    while let Some(result) = handles.next().await {
                        result
                            .map_err(|e| {
                                TaskError::Fatal(anyhow::anyhow!("splice task join error: {e}"))
                            })?
                            .map_err(TaskError::Execution)?;
                    }
                    break;
                }
            },
            Some(result) = handles.next() => {
                result
                    .map_err(|e| TaskError::Fatal(anyhow::anyhow!("splice task join error: {e}")))?
                    .map_err(TaskError::Execution)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use slop_futures::pipeline::AsyncEngine;
    use tokio::sync::Notify;

    use super::*;

    /// Per-task instruction for the stub worker.
    enum Behavior {
        /// Park until `release` is notified, then succeed.
        GatedOk,
        /// Return an execution error immediately.
        Err,
        /// Never complete.
        BlockForever,
    }

    struct TestTask {
        behavior: Behavior,
    }

    /// Stub worker whose `call` follows the task's [`Behavior`], so a chunk can
    /// be held "in flight", made to error, or blocked forever on demand.
    struct ControlWorker {
        release: Arc<Notify>,
        started: Arc<AtomicUsize>,
        finished: Arc<AtomicUsize>,
    }

    impl AsyncWorker<TestTask, Result<(), ExecutionError>> for ControlWorker {
        async fn call(&self, task: TestTask) -> Result<(), ExecutionError> {
            self.started.fetch_add(1, Ordering::SeqCst);
            match task.behavior {
                Behavior::GatedOk => {
                    self.release.notified().await;
                    self.finished.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
                Behavior::Err => Err(ExecutionError::Other("stub worker error".into())),
                Behavior::BlockForever => {
                    std::future::pending::<()>().await;
                    unreachable!()
                }
            }
        }
    }

    fn engine(
        n: usize,
        release: &Arc<Notify>,
        started: &Arc<AtomicUsize>,
        finished: &Arc<AtomicUsize>,
    ) -> Arc<AsyncEngine<TestTask, Result<(), ExecutionError>, ControlWorker>> {
        let workers = (0..n)
            .map(|_| ControlWorker {
                release: release.clone(),
                started: started.clone(),
                finished: finished.clone(),
            })
            .collect();
        Arc::new(AsyncEngine::new(workers, 4))
    }

    /// The lifetime crux: a chunk still proving when the JIT finishes (its
    /// channel closes) must be awaited by the consumer before it returns —
    /// otherwise the chunk's proof would be emitted after the `CoreExecute` task
    /// completed and be dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drains_in_flight_chunk_after_channel_close() {
        let release = Arc::new(Notify::new());
        let started = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let engine = engine(1, &release, &started, &finished);

        let (chunk_tx, chunk_rx) = mpsc::channel::<TestTask>(4);
        let consumer = tokio::spawn(drive_chunk_consumer(engine, chunk_rx));

        // Hand off one chunk and wait until the worker has picked it up.
        chunk_tx.send(TestTask { behavior: Behavior::GatedOk }).await.unwrap();
        while started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }

        // JIT finishes: the channel closes with the chunk still in flight.
        drop(chunk_tx);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The consumer must still be draining — it has neither returned nor lost
        // the in-flight chunk.
        assert!(!consumer.is_finished(), "consumer returned before draining the in-flight chunk");
        assert_eq!(finished.load(Ordering::SeqCst), 0, "in-flight chunk completed unexpectedly");

        // Let the chunk finish; the consumer drains it and returns.
        release.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), consumer)
            .await
            .expect("consumer did not finish after the chunk completed")
            .expect("consumer task panicked");
        assert!(result.is_ok(), "consumer returned an error: {result:?}");
        assert_eq!(finished.load(Ordering::SeqCst), 1, "in-flight chunk was not awaited");
    }

    /// A chunk that errors must make the consumer return `Err` promptly — it
    /// must not hang waiting on another chunk that is still in flight (the
    /// abort-on-first-error path).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn aborts_on_worker_error_without_waiting_on_other_chunks() {
        let release = Arc::new(Notify::new());
        let started = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        // Two workers so the blocking chunk and the erroring chunk run at once.
        let engine = engine(2, &release, &started, &finished);

        let (chunk_tx, chunk_rx) = mpsc::channel::<TestTask>(4);
        let consumer = tokio::spawn(drive_chunk_consumer(engine, chunk_rx));

        // One chunk blocks forever; wait until a worker has picked it up.
        chunk_tx.send(TestTask { behavior: Behavior::BlockForever }).await.unwrap();
        while started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        // A second chunk errors.
        chunk_tx.send(TestTask { behavior: Behavior::Err }).await.unwrap();
        // Keep `chunk_tx` alive (the error must short-circuit the select loop,
        // not a channel-close drain that would block on the forever chunk).

        let result = tokio::time::timeout(Duration::from_secs(5), consumer)
            .await
            .expect("consumer hung instead of aborting on the worker error")
            .expect("consumer task panicked");
        assert!(result.is_err(), "consumer should surface the worker error, got {result:?}");
    }
}
