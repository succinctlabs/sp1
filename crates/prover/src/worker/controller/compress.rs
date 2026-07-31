use std::collections::{BTreeMap, VecDeque};

use futures::future::try_join_all;
use hashbrown::HashMap;
use sp1_hypercube::{SP1PcsProofInner, SP1RecursionProof};
use sp1_primitives::SP1GlobalContext;
use sp1_prover_types::{Artifact, ArtifactClient, ArtifactId, ArtifactType, TaskStatus, TaskType};
use sp1_recursion_circuit::machine::SP1ShapedWitnessValues;
use tokio::sync::mpsc;

use super::DuplicateProofFilter;
use crate::{
    worker::{
        ChunkRange, ProofData, RecursionProverData, ReduceTaskRequest, TaskContext, TaskError,
        TaskId, WorkerClient,
    },
    ComposeScope, SP1CircuitWitness, SP1CompressWitness, SP1ProverComponents,
};

pub struct CompressTask {
    pub witness: SP1CompressWitness,
}

/// A proof in the recursion tree.
///
/// A recursion proof consists of a proof artifact along with its representative chunk range. The
/// range represents the portion of the execution trace that this proof attests to, and is used in
/// the compression process to combine multiple proofs into a single proof.
#[derive(Debug, Clone)]
pub struct RecursionProof {
    pub chunk_range: ChunkRange,
    pub proof: Artifact,
}

/// A collection of recursion proofs covering a contiguous chunk range.
///
/// The `RangeProofs` struct encapsulates a series of recursion proofs that together cover a
/// specific chunk range. It provides methods to manipulate and access these proofs, including
/// downloading their witnesses and converting them to and from artifacts.
#[derive(Clone, Debug)]
pub struct RangeProofs {
    pub chunk_range: ChunkRange,
    pub proofs: VecDeque<RecursionProof>,
}

impl RangeProofs {
    pub fn new(chunk_range: ChunkRange, proofs: VecDeque<RecursionProof>) -> Self {
        Self { chunk_range, proofs }
    }

    pub fn as_artifacts(self) -> impl Iterator<Item = Artifact> + Send + Sync {
        let range_artifact = Artifact::from(
            serde_json::to_string(&self.chunk_range).expect("Failed to serialize chunk range"),
        );
        std::iter::once(range_artifact).chain(self.proofs.into_iter().flat_map(|proof| {
            let range_str =
                serde_json::to_string(&proof.chunk_range).expect("Failed to serialize chunk range");
            let range_artifact = Artifact::from(range_str);
            let proof_artifact = proof.proof;
            [range_artifact, proof_artifact]
        }))
    }

    pub fn from_artifacts(artifacts: &[Artifact]) -> Result<Self, TaskError> {
        if artifacts.len() % 2 != 1 || artifacts.len() <= 1 {
            return Err(TaskError::Fatal(anyhow::anyhow!(
                "Invalid number of artifacts: {:?}",
                artifacts.len()
            )));
        }
        let chunk_range =
            serde_json::from_str(artifacts[0].id()).map_err(|e| TaskError::Fatal(e.into()))?;
        let proofs = artifacts[1..]
            .chunks_exact(2)
            .map(|chunk| -> Result<RecursionProof, TaskError> {
                let chunk_range =
                    serde_json::from_str(chunk[0].id()).map_err(|e| TaskError::Fatal(e.into()))?;
                let proof = chunk[1].clone();
                Ok(RecursionProof { chunk_range, proof })
            })
            .collect::<Result<VecDeque<RecursionProof>, TaskError>>()?;
        Ok(RangeProofs { chunk_range, proofs })
    }

    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    pub fn single(proof: RecursionProof) -> Self {
        Self { chunk_range: proof.chunk_range, proofs: VecDeque::from([proof]) }
    }

    /// Prepend a proof ending where this batch starts.
    pub fn push_right(&mut self, proof: RecursionProof) {
        assert_eq!(proof.chunk_range.end, self.chunk_range.start);
        self.chunk_range.start = proof.chunk_range.start;
        self.proofs.push_front(proof);
    }

    /// Append a proof starting where this batch ends.
    pub fn push_left(&mut self, proof: RecursionProof) {
        assert_eq!(proof.chunk_range.start, self.chunk_range.end);
        self.chunk_range.end = proof.chunk_range.end;
        self.proofs.push_back(proof);
    }

    /// Split the proofs at `at`, keeping `[0, at)` here and returning `[at, len)`; `None` if `at`
    /// is not an interior index (nothing to split off).
    pub fn split_off(&mut self, at: usize) -> Option<Self> {
        if at >= self.proofs.len() {
            return None;
        }
        let proofs = self.proofs.split_off(at);
        let split_range = ChunkRange {
            start: proofs.front().unwrap().chunk_range.start,
            end: proofs.back().unwrap().chunk_range.end,
        };
        self.chunk_range = ChunkRange {
            start: self.proofs.front().unwrap().chunk_range.start,
            end: self.proofs.back().unwrap().chunk_range.end,
        };
        Some(Self { chunk_range: split_range, proofs })
    }

    /// Stitch `middle` then `right` onto this batch (this | middle | right are adjacent in order).
    pub fn push_both(&mut self, middle: RecursionProof, right: Self) {
        assert_eq!(middle.chunk_range.start, self.chunk_range.end);
        assert_eq!(right.chunk_range.start, middle.chunk_range.end);
        self.proofs.push_back(middle);
        for proof in right.proofs {
            self.proofs.push_back(proof);
        }
        self.chunk_range.end = right.chunk_range.end;
    }

    pub fn range(&self) -> ChunkRange {
        self.chunk_range
    }

    pub async fn download_witness<C: SP1ProverComponents>(
        &self,
        is_complete: bool,
        artifact_client: &impl ArtifactClient,
        recursion_data: &RecursionProverData<C>,
    ) -> Result<SP1CircuitWitness, TaskError> {
        // Download the proofs
        let proofs = try_join_all(self.proofs.iter().map(|proof| async {
            let downloaded_proof = artifact_client
                .download::<SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>>(&proof.proof)
                .await?;

            Ok::<_, TaskError>(downloaded_proof)
        }))
        .await?;

        // TODO: This is because of a mismatch between `SP1CompressWithVKeyWitnessValues` and `SP1RecursionProof`
        // structs. Should refactor the former struct at some point to resemble the latter.
        let (vks_and_proofs, merkle_proofs): (Vec<_>, Vec<_>) = proofs
            .into_iter()
            .map(|proof| ((proof.vk, proof.proof), proof.vk_merkle_proof))
            .unzip();

        let witness = SP1ShapedWitnessValues { vks_and_proofs, is_complete };

        let witness = recursion_data.append_merkle_proofs_to_witness(witness, merkle_proofs)?;

        // The reduce-task pipeline (`PrepareReduceTaskWorker`) is the across-chunk reduce.
        let witness = SP1CircuitWitness::Compress { witness, scope: ComposeScope::AcrossChunk };
        Ok(witness)
    }

    pub async fn try_delete_proofs(
        &self,
        artifact_client: &impl ArtifactClient,
    ) -> Result<(), TaskError> {
        try_join_all(self.proofs.iter().map(|proof| async {
            // Delete the proof artifact.
            artifact_client.try_delete(&proof.proof, ArtifactType::UnspecifiedArtifactType).await?;
            Ok::<_, TaskError>(())
        }))
        .await?;
        Ok(())
    }
}

/// An enum marking which sibling was found.
#[derive(Debug)]
enum Sibling {
    Left(RangeProofs),
    Right(RangeProofs),
    Both(RangeProofs, RangeProofs),
}

/// The across-chunk reduce arity: a binary (arity-2) tree. The across-chunk compose family only
/// has programs for arities `{1, 2}`, so the batch size must be 2.
pub(super) const ACROSS_CHUNK_ARITY: usize = 2;

/// The across-chunk reduction tree.
///
/// Retargets the flat compress tree of `sp1-private/main` from shard ranges to **chunk indices**.
/// The two-stage split made the within-chunk reduce produce one independent, range-mergeable proof
/// per [`TraceChunk`](crate), so this tree only has to fold those per-chunk proofs into a single
/// root via a binary (arity-2) reduction keyed by chunk index.
///
/// # Reduction Process
///
/// The tree keeps [`RangeProofs`] indexed by their starting key in a single `u32` keyspace: the `n`
/// deferred leaves occupy `[0, n)` and each chunk `j` is shifted to `[n + j, n + j + 1)`, so the
/// reduce folds `deferred[0..n]` ahead of chunk 0. Each `ChunkProof` arrives **ready** (the
/// within-chunk reduce already finished in the node) — its arrival *is* its completion. The
/// exception is the deferred leaves: each is backed by a `RecursionDeferred` task and only enters
/// the tree once that task succeeds. When a node enters the tree, the tree looks for adjacent
/// siblings (a left sibling ends where the node starts; a right sibling starts where the node ends)
/// and merges them. A batch reaching `batch_size` (2), or the final batch covering the whole
/// `[0, n + num_chunks)` range with nothing pending, is submitted to an across-chunk reduce;
/// otherwise it waits in the tree for a future neighbour.
///
/// # Completion
///
/// The chunk count is known only when the executor closes the proof stream, so the last-arrived
/// chunk proof is **held back** until then (a held-back chunk leaves a gap, so the tree cannot reach
/// the full range early and submit the root with `is_complete = false`). The final batch — covering
/// `[0, n + num_chunks)` with no reduce tasks or deferred leaves pending — is submitted with
/// `is_complete = true` and its output is the root artifact; there is no separate finalize layer. A
/// single-chunk execution with no deferred proofs has no sibling to merge with, so its lone chunk
/// proof is wrapped in the one legitimate arity-1 across-chunk reduce (needed to apply the
/// whole-execution assertions the within-chunk root does not). The reduction is done when that root
/// (`is_complete`) reduce task finishes.
pub(super) struct CompressTree {
    map: BTreeMap<u32, RangeProofs>,
    batch_size: usize,
}

impl CompressTree {
    /// Create an empty tree with the given reduce arity (2 for the binary across-chunk tree).
    pub fn new(batch_size: usize) -> Self {
        Self { map: BTreeMap::new(), batch_size }
    }

    /// Insert a batch into the tree, keyed by its starting chunk index.
    fn insert(&mut self, proofs: RangeProofs) {
        self.map.insert(proofs.chunk_range.start, proofs);
    }

    /// Find and remove the sibling batches adjacent to `node` by chunk index: a left sibling ends
    /// where `node` starts, a right sibling starts where `node` ends.
    fn sibling(&mut self, node: &RecursionProof) -> Option<Sibling> {
        // Check for a left sibling: the batch with the greatest start <= node.start.
        if let Some((start, proofs)) = self.map.range(..=node.chunk_range.start).next_back() {
            if proofs.chunk_range.end == node.chunk_range.start {
                let start = *start;
                let left = self.map.remove(&start).unwrap();
                // Check for a right sibling too.
                if let Some(right) = self.map.remove(&node.chunk_range.end) {
                    return Some(Sibling::Both(left, right));
                }
                return Some(Sibling::Left(left));
            }
        }
        // No left sibling: check for a right sibling.
        if let Some(right) = self.map.remove(&node.chunk_range.end) {
            return Some(Sibling::Right(right));
        }
        None
    }

    /// The tree is complete once `range` covers the full range, no reduce tasks or deferred leaves
    /// are pending, and the tree is empty.
    fn is_complete(
        &self,
        range: &ChunkRange,
        pending_tasks: usize,
        deferred_pending: usize,
        full_range: &Option<ChunkRange>,
    ) -> bool {
        let is_range_equal = full_range.as_ref().is_some_and(|full| range == full);
        (pending_tasks == 0) && (deferred_pending == 0) && self.map.is_empty() && is_range_equal
    }

    /// Fold the per-chunk proofs arriving on `core_proofs_rx` into one root compress proof, written
    /// to `output`. Returns once the root (`is_complete`) across-chunk reduce completes.
    pub async fn reduce_proofs(
        &mut self,
        context: TaskContext,
        output: Artifact,
        num_deferred: u32,
        mut core_proofs_rx: mpsc::UnboundedReceiver<ProofData>,
        artifact_client: &impl ArtifactClient,
        worker_client: &impl WorkerClient,
    ) -> Result<(), TaskError> {
        // Ready chunk proofs and reduce-task outputs both funnel through `proof_tx`; one branch
        // places them into the tree.
        let (proof_tx, mut proof_rx) = mpsc::unbounded_channel::<RecursionProof>();
        // Subscribe to the across-chunk reduce tasks this tree submits and the deferred tasks that
        // back the deferred leaves.
        let (subscriber, mut event_stream) =
            worker_client.subscriber(context.proof_id.clone()).await?.stream();
        let mut proof_map = HashMap::<TaskId, RecursionProof>::new();
        // Deferred leaves keyed by their `RecursionDeferred` task id, pending until it succeeds.
        let mut deferred_map = HashMap::<TaskId, RecursionProof>::new();

        // Last-arrived chunk proof, held back until the stream closes (see the type-level docs).
        let mut held: Option<RecursionProof> = None;
        let mut num_chunks: u32 = 0;
        let mut stream_closed = false;
        let mut full_range: Option<ChunkRange> = None;
        let mut pending_tasks: usize = 0;
        // Deferred leaves emitted but not yet folded in (their `RecursionDeferred` task is running).
        let mut deferred_pending: usize = 0;
        // The is_complete reduce that yields the root; the reduction is done when its task finishes.
        let mut root_task: Option<TaskId> = None;
        let mut duplicates = DuplicateProofFilter::default();

        loop {
            tokio::select! {
                maybe_proof = core_proofs_rx.recv(), if !stream_closed => {
                    // The tree is keyed by chunk index, so a duplicate would overwrite the original
                    // and inflate the chunk count — drop it before it reaches the tree.
                    if maybe_proof.as_ref().is_some_and(|proof| duplicates.seen(proof)) {
                        continue;
                    }
                    match maybe_proof {
                        Some(ProofData::ChunkProof { chunk_range, proof }) => {
                            num_chunks += 1;
                            // Deferred leaves occupy [0, num_deferred); shift each chunk past them so
                            // chunk j keys at [num_deferred + j, num_deferred + j + 1).
                            let chunk_range = ChunkRange {
                                start: chunk_range.start + num_deferred,
                                end: chunk_range.end + num_deferred,
                            };
                            let node = RecursionProof { chunk_range, proof };
                            // A newer chunk proof arrived, so the previously-held one is not the last;
                            // release it into the tree.
                            if let Some(prev) = held.replace(node) {
                                pending_tasks += 1;
                                proof_tx.send(prev).map_err(|_| channel_closed())?;
                            }
                        }
                        // A deferred leaf is task-backed: its `RecursionDeferred` proof exists only once
                        // that task succeeds. Subscribe and fold it in on success (in the event arm); it
                        // keys ahead of chunk 0 at [i, i + 1) for deferred index i, so the reduce feeds
                        // deferred[0..n] before chunk 0.
                        Some(ProofData::Artifact { task_id, range, proof }) => {
                            let idx = range.deferred_proof_range.0 as u32;
                            let node = RecursionProof { chunk_range: ChunkRange::single(idx), proof };
                            deferred_map.insert(task_id.clone(), node);
                            subscriber.subscribe(task_id).map_err(|_| {
                                TaskError::Fatal(anyhow::anyhow!("subscriber closed"))
                            })?;
                            deferred_pending += 1;
                        }
                        Some(ProofData::InMemory { .. }) => {
                            return Err(TaskError::Fatal(anyhow::anyhow!(
                                "in-memory shard proofs never reach the across-chunk tree (compress \
                                 mode emits ChunkProof per chunk)"
                            )));
                        }
                        // Executor done: the chunk count, and thus the full range, are now known.
                        None => {
                            stream_closed = true;
                            let Some(last) = held.take() else {
                                return Err(TaskError::Fatal(anyhow::anyhow!(
                                    "across-chunk tree received no chunk proofs"
                                )));
                            };
                            full_range =
                                Some(ChunkRange { start: 0, end: num_deferred + num_chunks });
                            pending_tasks += 1;
                            proof_tx.send(last).map_err(|_| channel_closed())?;
                        }
                    }
                },
                Some(node) = proof_rx.recv() => {
                    pending_tasks -= 1;
                    // Decide the batch to submit (all synchronous: sibling lookup mutates the tree)
                    // before the asynchronous submit below.
                    let to_submit: Option<(RangeProofs, bool)> = match self.sibling(&node) {
                        Some(sibling) => {
                            let mut proofs = match sibling {
                                Sibling::Left(mut proofs) => {
                                    proofs.push_left(node);
                                    proofs
                                }
                                Sibling::Right(mut proofs) => {
                                    proofs.push_right(node);
                                    proofs
                                }
                                Sibling::Both(mut proofs, right) => {
                                    proofs.push_both(node, right);
                                    proofs
                                }
                            };
                            // Trim any overflow beyond batch_size back into the tree.
                            if let Some(split) = proofs.split_off(self.batch_size) {
                                self.insert(split);
                            }
                            assert!(
                                proofs.len() <= self.batch_size,
                                "across-chunk merge exceeded batch size: {}",
                                proofs.len()
                            );
                            let is_complete = self.is_complete(
                                &proofs.chunk_range,
                                pending_tasks,
                                deferred_pending,
                                &full_range,
                            );
                            if proofs.len() == self.batch_size || is_complete {
                                Some((proofs, is_complete))
                            } else {
                                self.insert(proofs);
                                None
                            }
                        }
                        None => {
                            // No neighbour. A lone proof covering the whole range is a single-chunk
                            // execution: wrap it in the one legitimate arity-1 across-chunk reduce
                            // so the root applies the whole-execution assertions.
                            let is_complete = self.is_complete(
                                &node.chunk_range,
                                pending_tasks,
                                deferred_pending,
                                &full_range,
                            );
                            if is_complete {
                                Some((RangeProofs::single(node), true))
                            } else {
                                self.insert(RangeProofs::single(node));
                                None
                            }
                        }
                    };
                    if let Some((proofs, is_complete)) = to_submit {
                        let chunk_range = proofs.chunk_range;
                        // The root reduce writes the caller's `output`; intermediate reduces get a
                        // fresh artifact.
                        let output_artifact =
                            if is_complete { output.clone() } else { artifact_client.create_artifact()? };
                        let task_request = ReduceTaskRequest {
                            range_proofs: proofs,
                            is_complete,
                            output: output_artifact.clone(),
                            context: context.clone(),
                        };
                        let task_id = worker_client
                            .submit_task(TaskType::RecursionReduce, task_request.into_raw()?)
                            .await?;
                        proof_map.insert(
                            task_id.clone(),
                            RecursionProof { chunk_range, proof: output_artifact },
                        );
                        subscriber
                            .subscribe(task_id.clone())
                            .map_err(|_| TaskError::Fatal(anyhow::anyhow!("subscriber closed")))?;
                        pending_tasks += 1;
                        if is_complete {
                            root_task = Some(task_id);
                        }
                    }
                    // Once `full_range` is set the executor has closed the stream, so
                    // `pending_tasks` and `deferred_pending` together cover every proof that can
                    // still arrive. With neither outstanding and the full range unreached, the
                    // tree can never progress — fail now rather than wait out the proof deadline.
                    if pending_tasks == 0 && deferred_pending == 0 && full_range.is_some() {
                        return Err(TaskError::Fatal(anyhow::anyhow!(
                            "across-chunk tree wedged with no pending work: full_range={:?}, \
                             tree ranges={:?}",
                            full_range,
                            self.map.values().map(|p| p.chunk_range).collect::<Vec<_>>()
                        )));
                    }
                }
                Some((task_id, status)) = event_stream.recv() => {
                    if status != TaskStatus::Succeeded {
                        return Err(TaskError::Fatal(anyhow::anyhow!(
                            "across-chunk tree task {} failed",
                            task_id
                        )));
                    }
                    // The root reduce finishing means the compressed proof is in `output`.
                    if root_task.as_ref() == Some(&task_id) {
                        return Ok(());
                    }
                    if let Some(node) = proof_map.remove(&task_id) {
                        proof_tx.send(node).map_err(|_| channel_closed())?;
                    } else if let Some(node) = deferred_map.remove(&task_id) {
                        // The deferred leaf's proof now exists; release it into the tree.
                        deferred_pending -= 1;
                        pending_tasks += 1;
                        proof_tx.send(node).map_err(|_| channel_closed())?;
                    } else {
                        tracing::debug!("across-chunk task output not found for task {}", task_id);
                    }
                }
                else => break,
            }
        }

        Err(TaskError::Fatal(anyhow::anyhow!(
            "across-chunk tree exhausted all inputs without producing a root proof"
        )))
    }
}

/// The proof funnel closed before the tree finished — only happens if a send outlives the loop.
fn channel_closed() -> TaskError {
    TaskError::Fatal(anyhow::anyhow!("across-chunk tree proof channel closed early"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sp1_core_machine::utils::setup_logger;
    use sp1_prover_types::InMemoryArtifactClient;

    use crate::worker::{test_utils::mock_worker_client, ProofId, RequesterId};

    use super::*;

    /// The across-chunk tree folds N ready per-chunk proofs into exactly one root proof — covering
    /// single-chunk (arity-1 root), even, and odd chunk counts, and out-of-order arrival with gaps
    /// that fill later (chunks are sent evens-then-odds).
    #[tokio::test]
    async fn test_across_chunk_tree() {
        setup_logger();
        let random_intervals = HashMap::from([
            (TaskType::Controller, Duration::from_millis(1)..Duration::from_millis(5)),
            (TaskType::SetupVkey, Duration::from_millis(1)..Duration::from_millis(5)),
            (TaskType::RecursionReduce, Duration::from_millis(5)..Duration::from_millis(20)),
            (TaskType::RecursionDeferred, Duration::from_millis(5)..Duration::from_millis(20)),
            (TaskType::ShrinkWrap, Duration::from_millis(1)..Duration::from_millis(5)),
            (TaskType::PlonkWrap, Duration::from_millis(1)..Duration::from_millis(5)),
            (TaskType::Groth16Wrap, Duration::from_millis(1)..Duration::from_millis(5)),
            (TaskType::ExecuteOnly, Duration::from_millis(1)..Duration::from_millis(5)),
            (TaskType::CoreExecute, Duration::from_millis(1)..Duration::from_millis(5)),
        ]);

        for num_chunks in [1u32, 2, 3, 5, 8] {
            let worker_client = mock_worker_client(random_intervals.clone());
            let artifact_client = InMemoryArtifactClient::new();
            let mut tree = CompressTree::new(ACROSS_CHUNK_ARITY);

            let context = TaskContext {
                proof_id: ProofId::new("test_across_chunk_tree"),
                parent_id: None,
                parent_context: None,
                requester_id: RequesterId::new("test_across_chunk_tree"),
            };

            let (core_proofs_tx, core_proofs_rx) = mpsc::unbounded_channel::<ProofData>();

            // Send every chunk proof ready (no task_id), evens then odds, so chunks land out of
            // order and the later (odd) arrivals bridge the gaps the evens left.
            tokio::task::spawn({
                let artifact_client = artifact_client.clone();
                async move {
                    let order = (0..num_chunks)
                        .filter(|i| i % 2 == 0)
                        .chain((0..num_chunks).filter(|i| i % 2 == 1));
                    for idx in order {
                        let proof = artifact_client.create_artifact().unwrap();
                        core_proofs_tx
                            .send(ProofData::ChunkProof {
                                chunk_range: ChunkRange::single(idx),
                                proof,
                            })
                            .unwrap();
                    }
                    // Dropping the sender closes the stream, signalling the chunk count is final.
                }
            });

            let output = artifact_client.create_artifact().unwrap();

            tokio::time::timeout(
                Duration::from_secs(30),
                tree.reduce_proofs(
                    context,
                    output,
                    0,
                    core_proofs_rx,
                    &artifact_client,
                    &worker_client,
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("across-chunk tree hung for {num_chunks} chunks"))
            .unwrap_or_else(|e| panic!("across-chunk tree failed for {num_chunks} chunks: {e:?}"));
        }
    }

    /// Task-duration ranges for `mock_worker_client`, which needs an entry for every task type it
    /// dispatches.
    fn random_intervals() -> HashMap<TaskType, std::ops::Range<Duration>> {
        HashMap::from([
            (TaskType::Controller, Duration::from_millis(1)..Duration::from_millis(5)),
            (TaskType::SetupVkey, Duration::from_millis(1)..Duration::from_millis(5)),
            (TaskType::RecursionReduce, Duration::from_millis(5)..Duration::from_millis(20)),
            (TaskType::RecursionDeferred, Duration::from_millis(5)..Duration::from_millis(20)),
            (TaskType::ShrinkWrap, Duration::from_millis(1)..Duration::from_millis(5)),
            (TaskType::PlonkWrap, Duration::from_millis(1)..Duration::from_millis(5)),
            (TaskType::Groth16Wrap, Duration::from_millis(1)..Duration::from_millis(5)),
            (TaskType::ExecuteOnly, Duration::from_millis(1)..Duration::from_millis(5)),
            (TaskType::CoreExecute, Duration::from_millis(1)..Duration::from_millis(5)),
        ])
    }

    /// A re-delivered `CoreExecute` re-proves every chunk and streams a second set of chunk proofs.
    /// The tree keys by chunk index, so an accepted duplicate would overwrite the original and
    /// inflate the chunk count, leaving the full range unreachable. It must reduce to one root.
    #[tokio::test]
    async fn test_across_chunk_tree_drops_redelivered_chunk_proofs() {
        setup_logger();

        for num_chunks in [1u32, 2, 5] {
            let worker_client = mock_worker_client(random_intervals());
            let artifact_client = InMemoryArtifactClient::new();
            let mut tree = CompressTree::new(ACROSS_CHUNK_ARITY);

            let context = TaskContext {
                proof_id: ProofId::new("test_across_chunk_tree_redelivery"),
                parent_id: None,
                parent_context: None,
                requester_id: RequesterId::new("test_across_chunk_tree_redelivery"),
            };

            let (core_proofs_tx, core_proofs_rx) = mpsc::unbounded_channel::<ProofData>();

            tokio::task::spawn({
                let artifact_client = artifact_client.clone();
                async move {
                    // Two full passes over the same chunk indices. The second pass uploads fresh
                    // artifacts, exactly as a re-execution would.
                    for _ in 0..2 {
                        for idx in 0..num_chunks {
                            let proof = artifact_client.create_artifact().unwrap();
                            core_proofs_tx
                                .send(ProofData::ChunkProof {
                                    chunk_range: ChunkRange::single(idx),
                                    proof,
                                })
                                .unwrap();
                        }
                    }
                }
            });

            let output = artifact_client.create_artifact().unwrap();

            tokio::time::timeout(
                Duration::from_secs(30),
                tree.reduce_proofs(
                    context,
                    output,
                    0,
                    core_proofs_rx,
                    &artifact_client,
                    &worker_client,
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("across-chunk tree hung on {num_chunks} redelivered chunks"))
            .unwrap_or_else(|e| panic!("across-chunk tree failed for {num_chunks} chunks: {e:?}"));
        }
    }

    /// A chunk proof lost in transit leaves a gap the tree can never bridge, while the chunk count
    /// still advances the full range past it. Nothing can arrive to fix that, so the tree must fail
    /// immediately instead of waiting out the proof deadline.
    #[tokio::test]
    async fn test_across_chunk_tree_fails_fast_on_a_missing_chunk() {
        setup_logger();

        let worker_client = mock_worker_client(random_intervals());
        let artifact_client = InMemoryArtifactClient::new();
        let mut tree = CompressTree::new(ACROSS_CHUNK_ARITY);

        let context = TaskContext {
            proof_id: ProofId::new("test_across_chunk_tree_fail_fast"),
            parent_id: None,
            parent_context: None,
            requester_id: RequesterId::new("test_across_chunk_tree_fail_fast"),
        };

        let (core_proofs_tx, core_proofs_rx) = mpsc::unbounded_channel::<ProofData>();
        for idx in [0, 2] {
            let proof = artifact_client.create_artifact().unwrap();
            core_proofs_tx
                .send(ProofData::ChunkProof { chunk_range: ChunkRange::single(idx), proof })
                .unwrap();
        }
        drop(core_proofs_tx);

        let output = artifact_client.create_artifact().unwrap();

        let result = tokio::time::timeout(
            Duration::from_secs(30),
            tree.reduce_proofs(
                context,
                output,
                0,
                core_proofs_rx,
                &artifact_client,
                &worker_client,
            ),
        )
        .await
        .expect("across-chunk tree hung — the fail-fast did not fire");

        let err = result.expect_err("a gap in the chunk indices must fail, not complete");
        assert!(err.to_string().contains("across-chunk tree wedged"), "unexpected error: {err}");
    }

    /// The across-chunk tree ingests deferred (`ProofData::Artifact`) leaves and orders them ahead
    /// of chunk 0. Feeds `k` deferred leaves + `m` chunk proofs and asserts the tree folds them into
    /// one root covering `[0, k + m)`, with deferred leaves keyed at `[0, k)` (deferred-first) and
    /// chunks shifted to `[k, k + m)` — checked by both range and proof-artifact identity. Deferred
    /// leaves are task-backed, so the test plays the `RecursionDeferred` worker (completing each
    /// task) and intercepts each `RecursionReduce` to record the batch it folds.
    #[tokio::test]
    async fn test_across_chunk_tree_orders_deferred_first() {
        use std::sync::{Arc, Mutex};

        use sp1_hypercube::air::ShardRange;

        use crate::worker::{LocalWorkerClient, RawTaskRequest, TaskMetadata};

        setup_logger();

        #[derive(Clone)]
        struct RecordedReduce {
            is_complete: bool,
            range: ChunkRange,
            children: Vec<(ChunkRange, String)>,
        }

        for (k, m) in [(1u32, 1u32), (2, 1), (1, 3), (3, 5), (2, 8)] {
            let (worker_client, mut channels) = LocalWorkerClient::init();
            let artifact_client = InMemoryArtifactClient::new();
            let mut tree = CompressTree::new(ACROSS_CHUNK_ARITY);

            let context = TaskContext {
                proof_id: ProofId::new("test_deferred_tree"),
                parent_id: None,
                parent_context: None,
                requester_id: RequesterId::new("test_deferred_tree"),
            };

            // Play the deferred worker: complete every `RecursionDeferred` task after a short delay.
            {
                let worker_client = worker_client.clone();
                let mut rx = channels.task_receivers.remove(&TaskType::RecursionDeferred).unwrap();
                tokio::spawn(async move {
                    while let Some((task_id, request)) = rx.recv().await {
                        let worker_client = worker_client.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(2)).await;
                            worker_client
                                .complete_task(
                                    request.context.proof_id,
                                    task_id,
                                    TaskMetadata { gpu_ms: None },
                                )
                                .await
                                .unwrap();
                        });
                    }
                });
            }

            // Intercept each across-chunk reduce: record the batch it folds, then complete the task.
            let recorded = Arc::new(Mutex::new(Vec::<RecordedReduce>::new()));
            {
                let worker_client = worker_client.clone();
                let recorded = recorded.clone();
                let mut rx = channels.task_receivers.remove(&TaskType::RecursionReduce).unwrap();
                tokio::spawn(async move {
                    while let Some((task_id, request)) = rx.recv().await {
                        let proof_id = request.context.proof_id.clone();
                        let req = ReduceTaskRequest::from_raw(request).unwrap();
                        let children = req
                            .range_proofs
                            .proofs
                            .iter()
                            .map(|p| (p.chunk_range, p.proof.id().to_string()))
                            .collect::<Vec<_>>();
                        recorded.lock().unwrap().push(RecordedReduce {
                            is_complete: req.is_complete,
                            range: req.range_proofs.chunk_range,
                            children,
                        });
                        let worker_client = worker_client.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(2)).await;
                            worker_client
                                .complete_task(proof_id, task_id, TaskMetadata { gpu_ms: None })
                                .await
                                .unwrap();
                        });
                    }
                });
            }

            let (core_proofs_tx, core_proofs_rx) = mpsc::unbounded_channel::<ProofData>();

            // Feed `k` deferred Artifacts (indices 0..k) then `m` chunk proofs (evens then odds, to
            // land out of order). Each deferred task is submitted before its Artifact so the tree
            // can subscribe to it. Proof artifacts are tagged so the leaves are identifiable.
            tokio::spawn({
                let worker_client = worker_client.clone();
                let context = context.clone();
                async move {
                    for i in 0..k {
                        let task_id = worker_client
                            .submit_task(
                                TaskType::RecursionDeferred,
                                RawTaskRequest {
                                    inputs: vec![],
                                    outputs: vec![],
                                    context: context.clone(),
                                },
                            )
                            .await
                            .unwrap();
                        core_proofs_tx
                            .send(ProofData::Artifact {
                                task_id,
                                range: ShardRange::deferred(u64::from(i), u64::from(i) + 1),
                                proof: Artifact::from(format!("deferred-{i}")),
                            })
                            .unwrap();
                    }
                    let order = (0..m).filter(|j| j % 2 == 0).chain((0..m).filter(|j| j % 2 == 1));
                    for j in order {
                        core_proofs_tx
                            .send(ProofData::ChunkProof {
                                chunk_range: ChunkRange::single(j),
                                proof: Artifact::from(format!("chunk-{j}")),
                            })
                            .unwrap();
                    }
                    // Dropping the sender closes the stream, fixing the chunk count.
                }
            });

            let output = artifact_client.create_artifact().unwrap();

            tokio::time::timeout(
                Duration::from_secs(30),
                tree.reduce_proofs(
                    context,
                    output,
                    k,
                    core_proofs_rx,
                    &artifact_client,
                    &worker_client,
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("deferred tree hung for k={k}, m={m}"))
            .unwrap_or_else(|e| panic!("deferred tree failed for k={k}, m={m}: {e:?}"));

            // Exactly one root, covering the whole [0, k + m) range.
            let recorded = recorded.lock().unwrap();
            let roots = recorded.iter().filter(|r| r.is_complete).collect::<Vec<_>>();
            assert_eq!(roots.len(), 1, "expected exactly one root for k={k}, m={m}");
            assert_eq!(
                roots[0].range,
                ChunkRange { start: 0, end: k + m },
                "root must cover [0, k + m) for k={k}, m={m}",
            );

            // Every original leaf appears once as a length-1 child; deferred leaves key at [0, k)
            // and chunks at [k, k + m), each carrying its tagged artifact — i.e. deferred-first.
            let mut leaves = std::collections::BTreeSet::new();
            for reduce in recorded.iter() {
                for (range, id) in &reduce.children {
                    if range.len() != 1 {
                        continue;
                    }
                    let start = range.start;
                    assert!(leaves.insert(start), "leaf {start} folded twice for k={k}, m={m}");
                    if start < k {
                        assert_eq!(*id, format!("deferred-{start}"), "deferred leaf id mismatch");
                    } else {
                        assert_eq!(*id, format!("chunk-{}", start - k), "chunk leaf id mismatch");
                    }
                }
            }
            assert_eq!(
                leaves,
                (0..k + m).collect::<std::collections::BTreeSet<_>>(),
                "leaves must tile [0, k + m) for k={k}, m={m}",
            );
        }
    }
}
