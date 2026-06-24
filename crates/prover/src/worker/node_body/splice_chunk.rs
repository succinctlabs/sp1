//! `SpliceChunkWorker` — the node body: proves one chunk end to end.
//!
//! Runs the SplicingVM over the chunk, generates every global commitment
//! in-process and broadcasts them as the chunk's Fiat-Shamir set, then proves
//! each shard (core + merkle) and emits the proofs. No cluster coordination.

use std::{collections::BTreeMap, sync::Arc};

use futures::{
    future::BoxFuture,
    stream::{FuturesUnordered, StreamExt},
};
use slop_algebra::PrimeField32;
use slop_challenger::IopCtx;
use slop_futures::pipeline::{AsyncEngine, AsyncWorker, Pipeline, SubmitHandle};
use sp1_core_executor::{
    ExecutionError, ExecutionRecord, Program, SP1CoreOpts, SHARD_KIND_EXECUTION, SHARD_KIND_MERKLE,
};
use sp1_core_machine::executor::trace_chunk;
use sp1_hypercube::{
    air::ShardRange, prover::ProverSemaphore, SP1PcsProofInner, SP1RecursionProof,
};
use sp1_jit::MinimalTrace;
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_prover_types::{network_base_types::ProofMode, Artifact, ArtifactClient};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
};

use sp1_core_machine::merkle_prover::{split_merkle_proof_record, BatchMerkleProver};

use crate::{
    worker::{
        controller::{ChunkPayload, TaskInput},
        order_commitments, AirProverWorker, ChunkChallengeCtx, ChunkRange, CommitKind,
        CommonProverInput, MessageSender, ProofData, ProofKind, RecursionStages, TaskError,
        WorkerClient,
    },
    SP1ProverComponents,
};

use super::{SendSpliceTask, SplicingTask, SplicingWorker};

/// AsyncEngine alias for the new chunk-splicing pipeline.
pub type SpliceChunkEngine<A, W, C> =
    AsyncEngine<SpliceChunkTask<W>, Result<(), ExecutionError>, SpliceChunkWorker<A, W, C>>;

/// One in-chunk leaf recursion proof.
type LeafProof = SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>;

/// Broadcast to every shard task once the chunk's commitments are ordered:
/// the commitments plus shard counts only known after splicing completes.
struct ChunkProveData {
    commitments: Vec<<SP1GlobalContext as IopCtx>::Digest>,
    num_execution_shards: u32,
    num_merkle_shards: u32,
    prev_root: [u32; 8],
    cur_root: [u32; 8],
}

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
    /// Recursion seam (normalize + within-chunk reduce). In compress mode the node drives
    /// it to fold the chunk's shards into one chunk proof; a mock stands in under test. `None` for a
    /// core-only worker (e.g. the executor bench), which never reaches the compress path.
    recursion: Option<Arc<dyn RecursionStages>>,
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
        recursion: Option<Arc<dyn RecursionStages>>,
    ) -> Self {
        let inner = SplicingWorker::new(artifact_client.clone());
        Self {
            artifact_client,
            inner,
            core_prover,
            permits,
            recursion,
            _marker: std::marker::PhantomData,
        }
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

        // One per-proof download of `CommonProverInput`. Shared (`Arc`) with every shard task so the
        // compress path can hand the vk/nonce to `normalize`.
        let common_prover_input = Arc::new(
            self.artifact_client
                .download::<CommonProverInput>(&common_input_artifact)
                .await
                .map_err(|e| ExecutionError::Other(format!("download common prover input: {e}")))?,
        );
        let proof_nonce = common_prover_input.nonce;
        let is_compress = common_prover_input.mode != ProofMode::Core;
        let recursion = if is_compress {
            Some(self.recursion.clone().ok_or_else(|| {
                ExecutionError::Other(
                    "compress mode requires a recursion seam, but none was wired".into(),
                )
            })?)
        } else {
            None
        };
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

        // Broadcasts the ordered global commitments + shard counts to every shard task.
        let (commits_tx, commits_rx) = watch::channel::<Option<Arc<ChunkProveData>>>(None);
        let chunk_idx = payload_arc.chunk_idx as u32;
        // The chunk's starting pc.
        let chunk_pc_start = payload_arc.chunk.pc_start();

        let mut commit_jobs: JoinSet<(CommitKind, u32, <SP1GlobalContext as IopCtx>::Digest)> =
            JoinSet::new();
        // Each job returns `Ok(())` and emits its proof by side effect: core mode sends an `InMemory`
        // proof per shard; compress mode streams its normalized leaf to the within-chunk reducer.
        let mut shard_jobs: JoinSet<Result<(), ExecutionError>> = JoinSet::new();
        // Compress mode streams each shard's normalized leaf to the reducer keyed by its within-chunk
        // position — merkle shards `[0, num_merkle)`, then execution shards `[num_merkle, num_shards)`
        // — so the reduce tree overlaps the shards still proving. Unused (dropped) in core mode.
        let (leaf_tx, leaf_rx) = mpsc::unbounded_channel::<(u32, LeafProof)>();

        // Receive the shard cuts.
        let mut num_execution_shards: u32 = 0;
        while let Some(cut) = cuts_rx.recv().await {
            num_execution_shards += 1;
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
                let prove_prog = program.clone();
                let opts_c = opts.clone();
                let chunk = cut.chunk.clone();
                let range = cut.range;
                let shard_index = cut.shard_index;
                let recursion = recursion.clone();
                let common = common_prover_input.clone();
                let artifact_client = self.artifact_client.clone();
                let leaf_tx = leaf_tx.clone();
                shard_jobs.spawn(async move {
                    let mut rec = tokio::task::spawn_blocking(move || {
                        let (_, rec, _) =
                            trace_chunk::<SP1Field>(prog, opts_c, chunk, proof_nonce, seed)?;
                        Ok::<_, ExecutionError>(rec)
                    })
                    .await
                    .map_err(|e| ExecutionError::Other(format!("trace_chunk join: {e}")))??;
                    // Once all the global commitments arrive, the shard proving begins.
                    rx.changed()
                        .await
                        .map_err(|_| ExecutionError::Other("commits sender dropped".into()))?;
                    let data = rx.borrow().as_ref().expect("commits_tx sent Some").clone();
                    rec.trace_chunk_idx = chunk_idx;
                    rec.shard_kind = SHARD_KIND_EXECUTION;
                    rec.shard_index = shard_index;
                    rec.num_execution_shards = data.num_execution_shards;
                    rec.num_merkle_shards = data.num_merkle_shards;
                    rec.prev_root = data.prev_root;
                    rec.cur_root = data.cur_root;
                    rec.public_values.prev_merkle_root = data.prev_root;
                    rec.public_values.merkle_root = data.cur_root;
                    rec.public_values.trace_chunk_idx = rec.trace_chunk_idx;
                    rec.public_values.shard_kind = rec.shard_kind;
                    rec.public_values.shard_index = rec.shard_index;
                    rec.public_values.num_execution_shard = data.num_execution_shards;
                    rec.public_values.num_merkle_shard = data.num_merkle_shards;
                    let dep_prover = prover.clone();
                    let rec = tokio::task::spawn_blocking(move || {
                        dep_prover.machine().generate_dependencies(std::iter::once(&mut rec), None);
                        rec
                    })
                    .await
                    .map_err(|e| {
                        ExecutionError::Other(format!("generate_dependencies join: {e}"))
                    })?;
                    // Core shard proof. Its permit is released on return, so the compress-mode
                    // normalize below takes its own from the shared pool without deadlocking.
                    let proof =
                        prover.prove_shard(prove_prog, &rec, &data.commitments, permits).await;
                    if let Some(recursion) = recursion {
                        let ctx = chunk_challenge_ctx(&data, shard_index);
                        let out = artifact_client.create_artifact().map_err(|e| {
                            ExecutionError::Other(format!("create leaf artifact: {e}"))
                        })?;
                        let leaf =
                            recursion.normalize(&common, proof, &ctx, out).await.map_err(|e| {
                                ExecutionError::Other(format!("normalize execution shard: {e}"))
                            })?;
                        // Execution shards follow the merkle shards in the within-chunk order.
                        let position = data.num_merkle_shards + shard_index;
                        leaf_tx.send((position, leaf)).map_err(|_| {
                            ExecutionError::Other("within-chunk leaf channel closed".into())
                        })?;
                        Ok(())
                    } else {
                        let proof = Box::new(proof);
                        tx.send(ProofData::InMemory { kind: ProofKind::Execution, range, proof })
                            .await
                            .map_err(|e| ExecutionError::Other(format!("send proof: {e}")))?;
                        Ok(())
                    }
                });
            }
            // `cut` drops here — the clones we needed (chunk, shard_data,
            // range, shard_index) are already inside the spawned tasks.
        }

        // SplicingVM is done, so merkle proving is ready to run.
        let merkle_input = splice_handle
            .await
            .map_err(|e| ExecutionError::Other(format!("splice task join: {e}")))??;
        let mut merkle_seed = self
            .core_prover
            .prepare_merkle_proof(
                merkle_input,
                program.clone(),
                proof_nonce,
                global_dependencies_opt,
                self.permits.clone(),
            )
            .await;
        // Roots bracketing this chunk's memory update, broadcast to every shard.
        let (prev_root, cur_root) = merkle_seed
            .merkle_proof_record
            .as_ref()
            .map(|m| {
                (
                    m.proof.prev_root.map(|x| x.as_canonical_u32()),
                    m.proof.cur_root.map(|x| x.as_canonical_u32()),
                )
            })
            .unwrap_or_default();

        // Split the chunk's merkle proof into shard-sized pieces (one if it fits). The proving loop
        // below sets each piece's shard_index and public values.
        let merkle_records: Vec<ExecutionRecord> = match merkle_seed.merkle_proof_record.take() {
            Some(record) => split_merkle_proof_record(record, program.instructions.len(), &opts)
                .into_iter()
                .map(|piece| {
                    ExecutionRecord::from_merkle_proof_record(
                        program.clone(),
                        proof_nonce,
                        global_dependencies_opt,
                        piece,
                    )
                })
                .collect(),
            None => vec![merkle_seed],
        };
        let num_merkle_shards = merkle_records.len() as u32;

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
        for (m_idx, mut rec) in merkle_records.into_iter().enumerate() {
            let prover = self.core_prover.clone();
            let permits = self.permits.clone();
            let tx = prove_shard_tx.clone();
            let mut rx = commits_rx.clone();
            let prove_prog = program.clone();
            let shard_index = m_idx as u32;
            let recursion = recursion.clone();
            let common = common_prover_input.clone();
            let artifact_client = self.artifact_client.clone();
            let leaf_tx = leaf_tx.clone();
            shard_jobs.spawn(async move {
                rx.changed()
                    .await
                    .map_err(|_| ExecutionError::Other("commits sender dropped".into()))?;
                let data = rx.borrow().as_ref().expect("commits_tx sent Some").clone();
                rec.trace_chunk_idx = chunk_idx;
                rec.shard_kind = SHARD_KIND_MERKLE;
                rec.shard_index = shard_index;
                rec.num_execution_shards = data.num_execution_shards;
                rec.num_merkle_shards = data.num_merkle_shards;
                rec.prev_root = data.prev_root;
                rec.cur_root = data.cur_root;
                rec.public_values.prev_merkle_root = data.prev_root;
                rec.public_values.merkle_root = data.cur_root;
                rec.public_values.trace_chunk_idx = rec.trace_chunk_idx;
                rec.public_values.shard_kind = rec.shard_kind;
                rec.public_values.shard_index = rec.shard_index;
                rec.public_values.num_execution_shard = data.num_execution_shards;
                rec.public_values.num_merkle_shard = data.num_merkle_shards;
                // The merkle shard sits at the head of the chunk.
                rec.public_values.update_initialized_state(
                    chunk_pc_start,
                    prove_prog.enable_untrusted_programs,
                    prove_prog.trap_context,
                    prove_prog.untrusted_memory,
                );
                if m_idx == 0 {
                    rec.public_values.is_first_merkle_shard = 1;
                }
                let dep_prover = prover.clone();
                let rec = tokio::task::spawn_blocking(move || {
                    dep_prover.machine().generate_dependencies(std::iter::once(&mut rec), None);
                    rec
                })
                .await
                .map_err(|e| ExecutionError::Other(format!("generate_dependencies join: {e}")))?;
                let proof = prover.prove_shard(prove_prog, &rec, &data.commitments, permits).await;
                if let Some(recursion) = recursion {
                    let ctx = chunk_challenge_ctx(&data, shard_index);
                    let out = artifact_client
                        .create_artifact()
                        .map_err(|e| ExecutionError::Other(format!("create leaf artifact: {e}")))?;
                    let leaf =
                        recursion.normalize(&common, proof, &ctx, out).await.map_err(|e| {
                            ExecutionError::Other(format!("normalize merkle shard: {e}"))
                        })?;
                    // Merkle shards lead the within-chunk order, so `shard_index` is the position.
                    leaf_tx.send((shard_index, leaf)).map_err(|_| {
                        ExecutionError::Other("within-chunk leaf channel closed".into())
                    })?;
                    Ok(())
                } else {
                    let proof = Box::new(proof);
                    tx.send(ProofData::InMemory {
                        kind: ProofKind::Merkle,
                        range: ShardRange::default(),
                        proof,
                    })
                    .await
                    .map_err(|e| ExecutionError::Other(format!("send proof: {e}")))?;
                    Ok(())
                }
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
        let num_shards = num_execution_shards + num_merkle_shards;
        let _ = commits_tx.send(Some(Arc::new(ChunkProveData {
            commitments,
            num_execution_shards,
            num_merkle_shards,
            prev_root,
            cur_root,
        })));
        drop(commits_tx);
        // The node holds no leaf of its own; drop its sender so the channel closes once the last
        // shard job's clone drops.
        drop(leaf_tx);

        // Drain the shard jobs to surface their errors/panics. In compress mode each has already
        // streamed its leaf to the reducer; in core mode each has already sent its `InMemory` proof.
        // Every `prove_shard`/`normalize` permit is released within its own job, so the streaming
        // reduce can take permits from the shared pool without deadlocking.
        let drain_shards = async {
            while let Some(joined) = shard_jobs.join_next().await {
                joined.map_err(|e| ExecutionError::Other(format!("shard job panicked: {e}")))??;
            }
            Ok::<(), ExecutionError>(())
        };

        // In compress mode, stream-reduce the chunk's leaves into one *ready* `ChunkProof`
        // concurrently with the shards still proving. Running the reducer alongside `drain_shards`
        // overlaps the reduce tree with proving; a shard-job error makes `try_join!` cancel the
        // reducer instead of leaving it to hang on a leaf that never arrives. The across-chunk tree
        // (controller) consumes one chunk proof per `trace_chunk_idx`.
        if let Some(recursion) = recursion {
            let reduce = within_chunk_reduce_streaming(
                recursion.as_ref(),
                &self.artifact_client,
                leaf_rx,
                num_shards,
            );
            let (chunk_proof, ()) = tokio::try_join!(reduce, drain_shards)?;
            drop(commits_rx);
            prove_shard_tx
                .send(ProofData::ChunkProof {
                    chunk_range: ChunkRange::single(chunk_idx),
                    proof: chunk_proof,
                })
                .await
                .map_err(|e| ExecutionError::Other(format!("send chunk proof: {e}")))?;
        } else {
            drain_shards.await?;
            drop(commits_rx);
        }

        Ok(())
    }
}

/// Build the per-shard shared Fiat-Shamir context [`normalize`](RecursionStages::normalize) needs to
/// re-derive the chunk's global challenge: the chunk's ordered commitments + bracketing roots, plus
/// this shard's position. The placeholder normalize ignores it; the real one drives the
/// shared-challenge logic from it.
fn chunk_challenge_ctx(data: &ChunkProveData, shard_index: u32) -> ChunkChallengeCtx {
    ChunkChallengeCtx {
        commitments: data.commitments.clone(),
        prev_root: data.prev_root,
        cur_root: data.cur_root,
        shard_index,
        num_shards: data.num_execution_shards + data.num_merkle_shards,
    }
}

/// One pending within-chunk node: an in-memory (leaf or already-reduced) proof covering the
/// contiguous shard-position range `[start, end)`.
struct PendingNode {
    start: u32,
    end: u32,
    leaf: LeafProof,
}

/// The result of one in-flight reduce: the merged node, the artifact it wrote, and whether it was the
/// chunk root (range `[0, num_shards)`).
struct ReduceOutput {
    start: u32,
    end: u32,
    leaf: LeafProof,
    out: Artifact,
    is_root: bool,
}

/// A boxed in-flight within-chunk reduce, borrowing the recursion seam for the reducer's lifetime.
type ReduceFuture<'a> = BoxFuture<'a, Result<ReduceOutput, ExecutionError>>;

/// Fold the chunk's leaves into one chunk proof, reducing adjacent siblings as they arrive
/// so the reduce tree overlaps the shards still proving. Leaves arrive on `leaf_rx` as
/// `(position, leaf)`, with `position` a contiguous integer in `[0, num_shards)` (merkle shards
/// first, then execution shards by index); only adjacent `[a,b)+[b,c)` siblings are ever merged, so
/// the within-chunk PV chaining is preserved exactly as in the bounded version. `num_shards` is known
/// up front, so completion is deterministic (no holdback): the reduce whose merged range is
/// `[0, num_shards)` is the chunk root (`is_chunk_complete = true`) and its artifact is the returned
/// chunk proof. Chunks always have `num_shards >= 2`, so the root is an arity-2 reduce.
async fn within_chunk_reduce_streaming<'a, A: ArtifactClient>(
    recursion: &'a dyn RecursionStages,
    artifact_client: &A,
    mut leaf_rx: mpsc::UnboundedReceiver<(u32, LeafProof)>,
    num_shards: u32,
) -> Result<Artifact, ExecutionError> {
    debug_assert!(num_shards >= 2, "a chunk always has >= 1 merkle and >= 1 execution shard");
    // Pending nodes keyed by range start; never holds two adjacent nodes (adjacency reduces at once).
    let mut pending: BTreeMap<u32, PendingNode> = BTreeMap::new();
    let mut in_flight: FuturesUnordered<ReduceFuture<'a>> = FuturesUnordered::new();
    let mut leaf_closed = false;

    loop {
        tokio::select! {
            maybe_leaf = leaf_rx.recv(), if !leaf_closed => match maybe_leaf {
                Some((pos, leaf)) => {
                    let node = PendingNode { start: pos, end: pos + 1, leaf };
                    submit_if_adjacent(
                        node, &mut pending, &mut in_flight, recursion, artifact_client, num_shards,
                    )?;
                }
                None => leaf_closed = true,
            },
            Some(done) = in_flight.next(), if !in_flight.is_empty() => {
                let out = done?;
                if out.is_root {
                    return Ok(out.out);
                }
                let node = PendingNode { start: out.start, end: out.end, leaf: out.leaf };
                submit_if_adjacent(
                    node, &mut pending, &mut in_flight, recursion, artifact_client, num_shards,
                )?;
            }
            else => break,
        }
    }

    // Only reached if the leaf stream closed and no reduces remain without the root forming — i.e. a
    // leaf never arrived (a shard job failed); `try_join!` normally cancels us before this.
    Err(ExecutionError::Other(
        "within-chunk reducer ran out of leaves before producing a chunk root".into(),
    ))
}

/// Insert `node` into the within-chunk tree, immediately kicking off an arity-2 reduce if it already
/// has an adjacent sibling present: a left sibling ending at `node.start` (preferred), else a right
/// sibling starting at `node.end`. The reduce future is pushed onto `in_flight`; its merged output
/// re-enters the tree when it completes. With only adjacent merges, the tree converges to one node.
fn submit_if_adjacent<'a, A: ArtifactClient>(
    node: PendingNode,
    pending: &mut BTreeMap<u32, PendingNode>,
    in_flight: &mut FuturesUnordered<ReduceFuture<'a>>,
    recursion: &'a dyn RecursionStages,
    artifact_client: &A,
    num_shards: u32,
) -> Result<(), ExecutionError> {
    // Left sibling: the pending node ending exactly at `node.start`.
    let left_start = pending
        .range(..node.start)
        .next_back()
        .filter(|(_, n)| n.end == node.start)
        .map(|(&start, _)| start);
    if let Some(start) = left_start {
        let left = pending.remove(&start).unwrap();
        return push_reduce(left, node, in_flight, recursion, artifact_client, num_shards);
    }
    // Right sibling: the pending node starting exactly at `node.end`.
    if let Some(right) = pending.remove(&node.end) {
        return push_reduce(node, right, in_flight, recursion, artifact_client, num_shards);
    }
    pending.insert(node.start, node);
    Ok(())
}

/// Kick off the arity-2 reduce of two adjacent nodes (`left.end == right.start`), pushing it onto
/// `in_flight`. The reduce covering the whole `[0, num_shards)` range is flagged as the chunk root
/// (`is_chunk_complete = true`), where the within-chunk program binds the shared transcript and closes
/// `Σ global_cumulative_sum = 0`; all other reduces carry `false`.
fn push_reduce<'a, A: ArtifactClient>(
    left: PendingNode,
    right: PendingNode,
    in_flight: &mut FuturesUnordered<ReduceFuture<'a>>,
    recursion: &'a dyn RecursionStages,
    artifact_client: &A,
    num_shards: u32,
) -> Result<(), ExecutionError> {
    debug_assert_eq!(left.end, right.start, "within-chunk reduce of non-adjacent siblings");
    let start = left.start;
    let end = right.end;
    let is_root = start == 0 && end == num_shards;
    let out = artifact_client
        .create_artifact()
        .map_err(|e| ExecutionError::Other(format!("create within-chunk reduce artifact: {e}")))?;
    in_flight.push(Box::pin(async move {
        let leaf = recursion
            .within_chunk_reduce(vec![left.leaf, right.leaf], is_root, out.clone())
            .await
            .map_err(|e| ExecutionError::Other(format!("within-chunk reduce: {e}")))?;
        Ok(ReduceOutput { start, end, leaf, out, is_root })
    }));
    Ok(())
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
    let mut handles: FuturesUnordered<SubmitHandle<P>> = FuturesUnordered::new();
    loop {
        tokio::select! {
            maybe_task = chunk_rx.recv() => match maybe_task {
                Some(task) => {
                    // Submit while CONCURRENTLY draining completed handles. The `AsyncEngine`
                    // hands each worker back to its pool only when the handle's `(worker, output)`
                    // is consumed; if we block on `submit()` without draining, `submit()` can wait
                    // forever for a worker still owned by an already-finished but undrained chunk —
                    // deadlocking the pipeline after exactly `num_splicing_workers` chunks.
                    let submit_fut = engine.submit(task);
                    tokio::pin!(submit_fut);
                    let handle = loop {
                        tokio::select! {
                            biased;
                            res = &mut submit_fut => {
                                break res.map_err(|e| {
                                    TaskError::Fatal(anyhow::anyhow!("submit SpliceChunk task: {e}"))
                                })?;
                            }
                            Some(result) = handles.next() => {
                                result
                                    .map_err(|e| {
                                        TaskError::Fatal(anyhow::anyhow!("splice task join error: {e}"))
                                    })?
                                    .map_err(TaskError::Execution)?;
                            }
                        }
                    };
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

    /// Drive [`within_chunk_reduce_streaming`] over a fixed leaf set: feed positions `0..n` and close
    /// the channel, returning the chunk-proof artifact. Order doesn't matter to the reducer, but the
    /// production caller streams merkle-first then execution-by-index.
    async fn reduce_streaming<A: ArtifactClient>(
        stages: &dyn RecursionStages,
        artifact_client: &A,
        leaves: Vec<LeafProof>,
    ) -> Result<Artifact, ExecutionError> {
        let num_shards = leaves.len() as u32;
        let (tx, rx) = mpsc::unbounded_channel::<(u32, LeafProof)>();
        for (pos, leaf) in leaves.into_iter().enumerate() {
            tx.send((pos as u32, leaf)).expect("leaf channel open");
        }
        drop(tx);
        within_chunk_reduce_streaming(stages, artifact_client, rx, num_shards).await
    }

    /// The streaming within-chunk reduce folds any (`>= 2`) leaf count into exactly one chunk proof,
    /// covering even and odd (carry) shapes. Uses the mock stages so the tree's control flow is
    /// exercised without real recursion crypto.
    #[tokio::test]
    async fn within_chunk_reduce_streaming_folds_any_leaf_count_into_one_proof() {
        use sp1_hypercube::{create_dummy_recursion_proof, SP1VerifyingKey};
        use sp1_prover_types::InMemoryArtifactClient;
        use sp1_recursion_circuit::dummy::dummy_vk;

        use crate::worker::MockRecursionStages;

        let vk = SP1VerifyingKey { vk: dummy_vk() };
        let artifact_client = InMemoryArtifactClient::new();
        let stages = MockRecursionStages::new(artifact_client.clone());

        for n in [2usize, 3, 4, 5, 8] {
            let leaves: Vec<LeafProof> =
                (0..n).map(|_| create_dummy_recursion_proof(&vk)).collect();
            let out = reduce_streaming(&stages, &artifact_client, leaves)
                .await
                .unwrap_or_else(|e| panic!("reduce of {n} leaves failed: {e}"));
            artifact_client
                .download::<LeafProof>(&out)
                .await
                .unwrap_or_else(|_| panic!("chunk proof artifact missing for {n} leaves"));
        }
    }

    /// Records the `(arity, is_chunk_complete)` of every `within_chunk_reduce` and notifies
    /// `reduce_started` when one is kicked off, so a test can pin the tree shape (exactly one root
    /// reduce) and observe streaming. Uploads to `out` so the returned chunk-proof artifact is
    /// downloadable.
    struct RecordingStages {
        vk: sp1_hypercube::SP1VerifyingKey,
        artifact_client: sp1_prover_types::InMemoryArtifactClient,
        calls: std::sync::Arc<std::sync::Mutex<Vec<(usize, bool)>>>,
        reduce_started: std::sync::Arc<Notify>,
    }

    impl RecursionStages for RecordingStages {
        fn normalize<'a>(
            &'a self,
            _common: &'a CommonProverInput,
            _core_proof: sp1_hypercube::ShardProof<SP1GlobalContext, SP1PcsProofInner>,
            _chunk_ctx: &'a ChunkChallengeCtx,
            _out: Artifact,
        ) -> futures::future::BoxFuture<'a, Result<LeafProof, TaskError>> {
            unreachable!("the within-chunk reduce never calls normalize")
        }

        fn within_chunk_reduce<'a>(
            &'a self,
            children: Vec<LeafProof>,
            is_chunk_complete: bool,
            out: Artifact,
        ) -> futures::future::BoxFuture<'a, Result<LeafProof, TaskError>> {
            self.calls.lock().unwrap().push((children.len(), is_chunk_complete));
            self.reduce_started.notify_one();
            let vk = self.vk.clone();
            let artifact_client = self.artifact_client.clone();
            Box::pin(async move {
                let proof = sp1_hypercube::create_dummy_recursion_proof(&vk);
                artifact_client.upload(&out, proof.clone()).await?;
                Ok(proof)
            })
        }
    }

    /// Exactly one reduce — the chunk root — is marked `is_chunk_complete`, it is an arity-2 reduce
    /// (chunks always have `num_shards >= 2`), and the binary tree does `n - 1` reduces total.
    #[tokio::test]
    async fn within_chunk_reduce_streaming_marks_only_the_root_complete() {
        use sp1_prover_types::InMemoryArtifactClient;
        use sp1_recursion_circuit::dummy::dummy_vk;

        let vk = sp1_hypercube::SP1VerifyingKey { vk: dummy_vk() };
        let artifact_client = InMemoryArtifactClient::new();

        for n in [2usize, 3, 5, 8] {
            let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let stages = RecordingStages {
                vk: vk.clone(),
                artifact_client: artifact_client.clone(),
                calls: calls.clone(),
                reduce_started: std::sync::Arc::new(Notify::new()),
            };
            let leaves: Vec<LeafProof> =
                (0..n).map(|_| sp1_hypercube::create_dummy_recursion_proof(&vk)).collect();
            reduce_streaming(&stages, &artifact_client, leaves)
                .await
                .unwrap_or_else(|e| panic!("reduce of {n} leaves failed: {e}"));

            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), n - 1, "{n} leaves: a binary tree does n-1 reduces");
            let roots: Vec<_> = calls.iter().filter(|(_, c)| *c).collect();
            assert_eq!(roots.len(), 1, "{n} leaves: exactly one reduce closes the chunk");
            assert_eq!(roots[0].0, 2, "{n} leaves: the chunk root is an arity-2 reduce");
        }
    }

    /// The streaming property the fix exists for: the reducer kicks off a reduce of adjacent siblings
    /// as soon as they arrive, *before* the last leaf is fed — it does not wait for every leaf. Guards
    /// against silently re-bounding it to collect-then-reduce later.
    #[tokio::test]
    async fn within_chunk_reduce_streaming_reduces_before_the_last_leaf() {
        use sp1_hypercube::{create_dummy_recursion_proof, SP1VerifyingKey};
        use sp1_prover_types::InMemoryArtifactClient;
        use sp1_recursion_circuit::dummy::dummy_vk;

        let vk = SP1VerifyingKey { vk: dummy_vk() };
        let artifact_client = InMemoryArtifactClient::new();
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let reduce_started = std::sync::Arc::new(Notify::new());
        let stages = RecordingStages {
            vk: vk.clone(),
            artifact_client: artifact_client.clone(),
            calls: calls.clone(),
            reduce_started: reduce_started.clone(),
        };

        let num_shards = 4u32;
        let (leaf_tx, leaf_rx) = mpsc::unbounded_channel::<(u32, LeafProof)>();

        let reducer = within_chunk_reduce_streaming(&stages, &artifact_client, leaf_rx, num_shards);
        let feeder = async {
            // Two adjacent leaves are enough to form a reducible sibling pair `[0,2)`.
            leaf_tx.send((0, create_dummy_recursion_proof(&vk))).unwrap();
            leaf_tx.send((1, create_dummy_recursion_proof(&vk))).unwrap();
            // Block until that reduce is kicked off — i.e. the reducer did not wait for all leaves.
            reduce_started.notified().await;
            assert!(
                !calls.lock().unwrap().is_empty(),
                "a within-chunk reduce fired before the last leaf was fed",
            );
            // Feed the remaining leaves and close the stream so the reducer can reach the root.
            leaf_tx.send((2, create_dummy_recursion_proof(&vk))).unwrap();
            leaf_tx.send((3, create_dummy_recursion_proof(&vk))).unwrap();
            drop(leaf_tx);
        };

        let (reduce_result, ()) = tokio::join!(reducer, feeder);
        let chunk_proof = reduce_result.expect("streaming reducer produced a chunk proof");
        artifact_client
            .download::<LeafProof>(&chunk_proof)
            .await
            .expect("chunk proof artifact downloadable");

        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            num_shards as usize - 1,
            "binary tree over 4 leaves does 3 reduces"
        );
        let roots: Vec<_> = calls.iter().filter(|(_, c)| *c).collect();
        assert_eq!(roots.len(), 1, "exactly one reduce closes the chunk");
        assert_eq!(roots[0].0, 2, "the chunk root is an arity-2 reduce");
    }

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
