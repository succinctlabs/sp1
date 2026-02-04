use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

use futures::future::try_join_all;
use hashbrown::HashMap;
use sp1_hypercube::{
    air::{ShardBoundary, ShardRange},
    SP1PcsProofInner, SP1RecursionProof,
};
use sp1_primitives::SP1GlobalContext;
use sp1_prover_types::{Artifact, ArtifactClient, ArtifactId, ArtifactType, TaskStatus, TaskType};
use sp1_recursion_circuit::machine::SP1ShapedWitnessValues;
use tokio::{sync::mpsc, task::JoinSet};
use tracing::Instrument;

use crate::{
    worker::{
        ProofData, RecursionProverData, ReduceTaskRequest, TaskContext, TaskError, TaskId,
        WorkerClient,
    },
    SP1CircuitWitness, SP1CompressWitness, SP1ProverComponents,
};

pub struct CompressTask {
    pub witness: SP1CompressWitness,
}

/// A proof in the recursion tree.
///
/// A recursion proof consists of a proof artifact along with its representative shard range. The
/// range represents the portion of the execution trace that this proof attests to, and is used in
/// the compression process to combine multiple proofs into a single proof.
#[derive(Debug, Clone)]
pub struct RecursionProof {
    pub shard_range: ShardRange,
    pub proof: Artifact,
}

/// A collection of recursion proofs covering a contiguous shard range.
///
/// The `RangeProofs` struct encapsulates a series of recursion proofs that together cover a
/// specific shard range. It provides methods to manipulate and access these proofs, including
/// downloading their witnesses and converting them to and from artifacts.
#[derive(Clone, Debug)]
pub struct RangeProofs {
    pub shard_range: ShardRange,
    pub proofs: VecDeque<RecursionProof>,
}

impl RangeProofs {
    pub fn new(shard_range: ShardRange, proofs: VecDeque<RecursionProof>) -> Self {
        Self { shard_range, proofs }
    }

    pub fn as_artifacts(self) -> impl Iterator<Item = Artifact> + Send + Sync {
        let range_artifact = Artifact::from(
            serde_json::to_string(&self.shard_range).expect("Failed to serialize shard range"),
        );
        std::iter::once(range_artifact).chain(self.proofs.into_iter().flat_map(|proof| {
            let range_str =
                serde_json::to_string(&proof.shard_range).expect("Failed to serialize shard range");
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
        let shard_range =
            serde_json::from_str(artifacts[0].id()).map_err(|e| TaskError::Fatal(e.into()))?;
        let proofs = artifacts[1..]
            .chunks_exact(2)
            .map(|chunk| -> Result<RecursionProof, TaskError> {
                let shard_range =
                    serde_json::from_str(chunk[0].id()).map_err(|e| TaskError::Fatal(e.into()))?;
                let proof = chunk[1].clone();
                Ok(RecursionProof { shard_range, proof })
            })
            .collect::<Result<VecDeque<RecursionProof>, TaskError>>()?;
        Ok(RangeProofs { shard_range, proofs })
    }

    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    pub fn push_right(&mut self, proof: RecursionProof) {
        assert_eq!(proof.shard_range.end(), self.shard_range.start());
        self.shard_range = (proof.shard_range.start()..self.shard_range.end()).into();
        self.proofs.push_front(proof);
    }

    pub fn push_left(&mut self, proof: RecursionProof) {
        assert_eq!(proof.shard_range.start(), self.shard_range.end());
        self.shard_range = (self.shard_range.start()..proof.shard_range.end()).into();
        self.proofs.push_back(proof);
    }

    pub fn split_off(&mut self, at: usize) -> Option<Self> {
        if at >= self.proofs.len() {
            return None;
        }
        // Split the proofs off at the given index.
        let proofs = self.proofs.split_off(at);
        // Get the range of the proofs.
        let range = {
            let at_start_range = proofs.front().unwrap().shard_range.start();
            let at_end_range = proofs.iter().last().unwrap().shard_range.end();
            at_start_range..at_end_range
        }
        .into();
        // Get the new range of the self.
        let new_self_range = {
            let at_start_range = self.proofs.front().unwrap().shard_range.start();
            let at_end_range = self.proofs.iter().last().unwrap().shard_range.end();
            at_start_range..at_end_range
        };
        // Update the shard range of the self.
        self.shard_range = new_self_range.into();
        // Return the new proofs.
        Some(Self { shard_range: range, proofs })
    }

    pub fn push_both(&mut self, middle: RecursionProof, right: Self) {
        assert_eq!(middle.shard_range.start(), self.shard_range.end());
        assert_eq!(right.shard_range.start(), middle.shard_range.end());
        // Push the middle to the queue.
        self.proofs.push_back(middle);
        // Append the right proofs to the queue.
        for proof in right.proofs {
            self.proofs.push_back(proof);
        }
        // Update the shard range.
        self.shard_range = (self.shard_range.start()..right.shard_range.end()).into();
    }

    pub fn range(&self) -> ShardRange {
        self.shard_range
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

        let witness = SP1CircuitWitness::Compress(witness);
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

/// A tree structure to manage compress proof reduction.
///
/// The [CompressTree] struct is designed to efficiently manage and reduce recursion proofs using
/// the attested range.
///
/// # Reduction Process
///
///  The tree keeps track of [`RangeProofs`] indexed by their starting shard boundary. When a new
/// [`RecursionProof`] is inserted, the tree checks for neighboring proofs (siblings) that can be
/// combined with the new proof based on their shard ranges. If a sibling is found, the proofs are
/// combined into a single [`RangeProofs`]. If the combined proofs reach the specified batch size,
/// or we have reached the final batch representing the full range with no jobs left, they are
/// prepared for reduction; otherwise, they are reinserted into the tree for future combination.
///
/// ## Shard Ordering
///
/// In the first level of the tree, we have three different types of shards:
///     - Core shards: covering execution of the main `RISC-V` instructions over time ranges.
///     - Memory shards: covering memory initialization and finalization over address ranges.
///     - Precompile shards: covering proofs for precompile execution. They all have the same shard range.
///     - Deferred shards: covering verification of deferred proofs.
/// These shards are ordered in the tree as:
///   precompile shards | deferred shards | core shards | memory shards
/// This ordering allows us to combine proofs that are adjacent in terms of their shard ranges,
/// regardless of their type. In particular, it is important that precompile shards are in the
/// beginning, since they all share the same initial shard range and therefore can always find a
/// sibling to combine with.
pub(super) struct CompressTree {
    map: BTreeMap<ShardBoundary, RangeProofs>,
    batch_size: usize,
}

impl CompressTree {
    /// Create an empty tree with the given batch size.
    pub fn new(batch_size: usize) -> Self {
        Self { map: BTreeMap::new(), batch_size }
    }

    /// Insert a new range of proofs into the tree.
    fn insert(&mut self, proofs: RangeProofs) {
        self.map.insert(proofs.shard_range.start(), proofs);
    }

    /// Get the sibling of a proof.
    ///
    /// By definition, a sibling is defined according to the range. A left sibling is a range with
    /// the same end as the start of the proof's range. A right sibling is a range with the same
    /// start as the end of the proof's range.
    fn sibling(&mut self, proof: &RecursionProof) -> Option<Sibling> {
        // Check for a left sibling
        if let Some(previous) =
            self.map.range(ShardBoundary::initial()..=proof.shard_range.start()).next_back()
        {
            let (start, proofs) = previous;
            let start = *start;
            let proofs = proofs.clone();

            if proofs.shard_range.end() == proof.shard_range.start() {
                let left = self.map.remove(&start).unwrap();
                // Check for a right sibling.
                if let Some(right) = self.map.remove(&proof.shard_range.end()) {
                    return Some(Sibling::Both(left, right));
                } else {
                    return Some(Sibling::Left(left));
                }
            }
        }
        // If there is no left sibling, check for a right sibling.
        if let Some(right) = self.map.remove(&proof.shard_range.end()) {
            return Some(Sibling::Right(right));
        }

        // No sibling found.
        None
    }

    fn is_complete(
        &self,
        range: &ShardRange,
        pending_tasks: usize,
        full_range: &Option<ShardRange>,
    ) -> bool {
        let is_range_equal = full_range.as_ref().is_some_and(|full| range == full);
        tracing::debug!(
            "Checking if complete: Pending tasks: {:?}, map is empty: {:?}, full range is some: {:?}, is_range_equal: {:?}",
            pending_tasks,
            self.map.is_empty(),
            full_range.is_some(),
            is_range_equal,
        );
        (pending_tasks == 0) && self.map.is_empty() && is_range_equal
    }

    /// Reduce the proofs into the tree until the batch size is reached.
    ///
    /// ### Inputs
    ///
    /// - `full_range_rx`: A receiver for the full range of proofs.
    /// - `proofs_rx`: A receiver for the proofs to reduce.
    /// - `recursion_executors`: A queue of executors to use to execute the proofs.
    /// - `pending_tasks`: The number of pending tasks that are already running.
    ///
    /// **Remark**: it's important to keep track of the number of pending tasks because the shard
    /// ranges only cover timestamp ranges but do not cover how many precomputed proofs are in the
    /// tree.
    ///
    /// ### Outputs
    ///
    /// - A vector of proofs that have been reduced.
    ///
    /// ### Notes
    ///
    /// For information about the ordering used, see the documentation under [`CompressTree`].
    ///
    /// This function will terminate when the batch size is reached or when the full range is
    /// reached and proven.
    pub async fn reduce_proofs(
        &mut self,
        context: TaskContext,
        output: Artifact,
        mut core_proofs_rx: mpsc::UnboundedReceiver<ProofData>,
        artifact_client: &impl ArtifactClient,
        worker_client: &impl WorkerClient,
    ) -> Result<(), TaskError> {
        // Populate the recursion proofs into the tree until we reach the reduce batch size.

        // Create a subscriber for core proof tasks.
        let (core_proofs_subscriber, mut core_proofs_event_stream) =
            worker_client.subscriber(context.proof_id.clone()).await?.stream();
        let core_proof_map = Arc::new(Mutex::new(HashMap::<TaskId, RecursionProof>::new()));
        // Keep track of the full range of proofs.
        let mut full_range: Option<ShardRange> = None;
        // Keep track of the max range of proofs that have been processed.
        let mut max_range = ShardBoundary::initial()..ShardBoundary::initial();
        // Keep track of the number of pending tasks.
        let mut pending_tasks = 0;
        // Create a channel to send the proofs to the proof queue.
        let (proof_tx, mut proof_rx) = mpsc::unbounded_channel::<RecursionProof>();
        // Create a subscriber for the reduction tasks.
        let (subscriber, mut event_stream) =
            worker_client.subscriber(context.proof_id.clone()).await?.stream();
        let mut proof_map = HashMap::<TaskId, RecursionProof>::new();

        let mut join_set = JoinSet::<Result<(), TaskError>>::new();

        let (num_core_proofs_tx, mut num_core_proofs_rx) = mpsc::channel(1);
        // Spawn a task to process the incoming core proofs and subscribe to them.
        join_set.spawn({
            let core_proof_map = core_proof_map.clone();
            async move {
                let mut num_core_proofs = 0;
                while let Some(proof_data) = core_proofs_rx.recv().await {
                    core_proofs_subscriber
                        .subscribe(proof_data.task_id.clone())
                        .map_err(|e| TaskError::Fatal(e.into()))?;
                    let proof =
                        RecursionProof { shard_range: proof_data.range, proof: proof_data.proof };
                    core_proof_map.lock().unwrap().insert(proof_data.task_id, proof);
                    num_core_proofs += 1;
                }
                tracing::info!(
                    "All core proofs received: number of core proofs: {:?}",
                    num_core_proofs
                );
                num_core_proofs_tx.send(num_core_proofs).await.ok();
                Ok(())
            }
            .instrument(tracing::debug_span!("Core proof processing"))
        });

        let mut num_core_proofs_completed = 0;
        let mut num_core_proofs: Option<usize> = None;
        let mut last_core_proof = None;
        loop {
            tokio::select! {
                Some(num_proofs) = num_core_proofs_rx.recv() => {
                    tracing::info!("Number of core proofs completed: {:?}", num_proofs);
                    num_core_proofs = Some(num_proofs);
                    // If all core proofs have been completed, set the full range to the max range
                    // and send the last core proof to the proof queue.
                    if num_core_proofs_completed == num_proofs {
                        tracing::info!("All core proofs completed: {:?}", num_proofs);
                        full_range = Some(max_range.clone().into());
                        tracing::info!("Setting full range to: {:?}", full_range);
                        // Send the last core proof to the proof queue if it hasn't been sent yet
                        // by the core proof event stream receive task below.
                        if let Some(proof) = last_core_proof.take() {
                            proof_tx.send(proof).map_err(|_| TaskError::Fatal(anyhow::anyhow!("Compress tree panicked")))?;
                        }
                    }
                }
                Some(proof) = proof_rx.recv() => {
                    // Mark that this is a completed task.
                    pending_tasks -= 1;
                    if self.is_complete(&proof.shard_range, pending_tasks, &full_range) {
                        return Ok(());
                    }
                    // Check if there is a neighboring range.
                    if let Some(sibling) = self.sibling(&proof) {
                        tracing::debug!("Found sibling");
                        let mut proofs = match sibling {
                            Sibling::Left(mut proofs) => {
                                proofs.push_left(proof);
                                proofs
                            }
                            Sibling::Right(mut proofs) => {
                                proofs.push_right(proof);
                                proofs
                            }
                            Sibling::Both(mut proofs, right) => {
                                proofs.push_both(proof, right);
                                proofs
                            }
                        };

                        // Check for proofs to split and put back the remainder.
                        let split = proofs.split_off(self.batch_size);
                        if let Some(split) = split {
                            self.insert(split);
                        }

                        if proofs.len() > self.batch_size {
                            tracing::error!("Proofs are larger than the batch size: {:?}", proofs.len());
                            panic!("Proofs are larger than the batch size: {:?}", proofs.len());
                        }

                        let is_complete = self.is_complete(&proofs.shard_range, pending_tasks, &full_range);
                        if proofs.len() == self.batch_size || is_complete {
                            let shard_range = proofs.shard_range;
                            // Create an artifact for the output proof.
                            let output_artifact = if is_complete { output.clone() } else { artifact_client.create_artifact()? };
                            let task_request = ReduceTaskRequest {
                                range_proofs: proofs,
                                is_complete,
                                output: output_artifact.clone(),
                                context: context.clone(),
                            };
                            let raw_task_request = task_request.into_raw()?;
                            let task_id = worker_client.submit_task(TaskType::RecursionReduce, raw_task_request).await?;
                            // Update the proof map mapping the task id to the proof.
                            proof_map.insert(task_id.clone(), RecursionProof { shard_range, proof: output_artifact });
                            // Subscribe to the task.
                            subscriber.subscribe(task_id).map_err(|_| TaskError::Fatal(anyhow::anyhow!("Subscriver closed")))?;
                            // Update the number of pending tasks.
                            pending_tasks += 1;
                        } else {
                            self.insert(proofs);
                        }
                    } else {
                        tracing::info!("No neighboring range found, adding proof to tree");
                        // If there is no neighboring range, add the proof to the tree.
                        let mut queue = VecDeque::with_capacity(self.batch_size);
                        let range = proof.shard_range;
                        queue.push_back(proof);
                        let proofs = RangeProofs::new(range, queue);
                        self.insert(proofs);
                    }
                }
                Some((task_id, status)) = event_stream.recv() => {
                    if status != TaskStatus::Succeeded {
                        return Err(
                            TaskError::Fatal
                            (anyhow::anyhow!("Reduction task {} failed", task_id))
                        );
                    }
                    let proof = proof_map.remove(&task_id);
                    if let Some(proof) = proof {
                        // Send the proof to the proof queue.
                        proof_tx.send(proof).map_err(|_| TaskError::Fatal(anyhow::anyhow!("Compress tree panicked")))?;
                    }
                    else {
                        tracing::debug!("Proof not found for task id: {}", task_id);
                    }
                }

                Some((task_id, status)) = core_proofs_event_stream.recv() => {
                    if status != TaskStatus::Succeeded {
                        return Err(
                            TaskError::Fatal
                            (anyhow::anyhow!("Core proof task {} failed", task_id))
                        );
                    }
                    // Download the proof
                    let normalize_proof = core_proof_map.lock().unwrap().remove(&task_id);
                    if let Some(normalize_proof) = normalize_proof {
                        let shard_range = &normalize_proof.shard_range;
                        let (start, end) = (shard_range.start(), shard_range.end());
                        if start < max_range.start {
                            max_range.start = start;
                        }
                        if end > max_range.end {
                            max_range.end = end;
                        }
                        // Set it as the last core proof and take the previous one.
                        let previous_core_proof = last_core_proof.take();
                        last_core_proof = Some(normalize_proof);
                        // Send the previous core proof to the proof queue, this is safe to do since
                        // we know it's not the last one.
                        if let Some(proof) = previous_core_proof {
                            // Send the proof to the proof queue.
                            proof_tx.send(proof).map_err(|_| TaskError::Fatal(anyhow::anyhow!("Compress tree panicked")))?;
                        }

                        // Mark this as a pending task for the compress tree.
                        pending_tasks += 1;
                        // Increment the number of completed core proofs.
                        num_core_proofs_completed += 1;
                        // If all core proofs have been completed, set the full range to the max
                        // range and send the last core proof to the proof queue.
                        if let Some(num_core_proofs) = num_core_proofs {
                            if num_core_proofs_completed == num_core_proofs {
                                full_range = Some(max_range.clone().into());
                                tracing::info!("Setting full range to: {:?}", full_range);
                                // Send the last core proof to the proof queue.
                                tracing::info!("Sending last core proof to proof queue: {:?}", last_core_proof);
                                let last_core_proof = last_core_proof.take().unwrap();
                                proof_tx.send(last_core_proof).map_err(|_| TaskError::Fatal(anyhow::anyhow!("Compress tree panicked")))?;
                                // Close the core proofs event stream.
                                core_proofs_event_stream.close();
                            }
                        }
                    } else {
                        tracing::debug!("Core proof not found for task id: {}", task_id);
                    }
                }
                else => {
                    break;
                }
            }
        }

        Err(TaskError::Fatal(anyhow::anyhow!("todo explain this")))
    }
}

#[cfg(test)]
mod test_utils {
    use std::time::Duration;

    use sp1_core_machine::utils::setup_logger;
    use sp1_prover_types::InMemoryArtifactClient;

    use crate::{
        shapes::DEFAULT_ARITY,
        worker::{test_utils::mock_worker_client, ProofId, ProveShardTaskRequest, RequesterId},
    };

    use super::*;

    async fn create_dummy_prove_shard_task(
        range: ShardRange,
        elf_artifact: Artifact,
        common_input_artifact: Artifact,
        context: TaskContext,
        core_proofs_tx: &mpsc::UnboundedSender<ProofData>,
        worker_client: &impl WorkerClient,
        artifact_client: &impl ArtifactClient,
    ) {
        let record_artifact = artifact_client.create_artifact().unwrap();
        let proof_artifact = artifact_client.create_artifact().unwrap();

        let request = ProveShardTaskRequest {
            elf: elf_artifact.clone(),
            common_input: common_input_artifact.clone(),
            record: record_artifact,
            output: proof_artifact.clone(),
            deferred_marker_task: Artifact::from("dummy marker task".to_string()),
            deferred_output: Artifact::from("dummy output artifact".to_string()),
            context: context.clone(),
        };

        let task = request.into_raw().unwrap();

        // Send the task to the worker.
        let task_id = worker_client.submit_task(TaskType::ProveShard, task).await.unwrap();
        let proof_data = ProofData { task_id, range, proof: proof_artifact };
        core_proofs_tx.send(proof_data).unwrap();
    }

    #[tokio::test]
    async fn test_compress_tree() {
        setup_logger();
        let num_core_shards = 200;
        let core_start_delay = Duration::from_millis(10);
        let num_memory_shards = 40;
        let memory_start_delay = Duration::from_millis(500);
        let num_precompile_shards = 20;
        let precompile_start_delay = Duration::from_millis(500);
        let num_deferred_shards = 100;
        let deferred_start_delay = Duration::from_millis(1);
        let num_iterations = 1;
        let random_intervals = HashMap::from([
            (TaskType::Controller, Duration::from_millis(20)..Duration::from_millis(100)),
            (TaskType::SetupVkey, Duration::from_millis(20)..Duration::from_millis(100)),
            (TaskType::RecursionReduce, Duration::from_millis(100)..Duration::from_millis(200)),
            (TaskType::ProveShard, Duration::from_millis(200)..Duration::from_millis(500)),
            (TaskType::MarkerDeferredRecord, Duration::from_millis(20)..Duration::from_millis(100)),
            (TaskType::RecursionDeferred, Duration::from_millis(20)..Duration::from_millis(100)),
            (TaskType::ShrinkWrap, Duration::from_millis(20)..Duration::from_millis(100)),
            (TaskType::PlonkWrap, Duration::from_millis(20)..Duration::from_millis(100)),
            (TaskType::Groth16Wrap, Duration::from_millis(20)..Duration::from_millis(100)),
            (TaskType::ExecuteOnly, Duration::from_millis(20)..Duration::from_millis(100)),
        ]);

        for _ in 0..num_iterations {
            let worker_client = mock_worker_client(random_intervals.clone());

            let artifact_client = InMemoryArtifactClient::new();

            let mut compress_tree = CompressTree::new(DEFAULT_ARITY);

            let context = TaskContext {
                proof_id: ProofId::new("test_compress_tree"),
                parent_id: None,
                parent_context: None,
                requester_id: RequesterId::new("test_compress_tree"),
            };

            let (core_proofs_tx, core_proofs_rx) = mpsc::unbounded_channel::<ProofData>();

            let elf_artifact = artifact_client.create_artifact().unwrap();
            let common_input_artifact = artifact_client.create_artifact().unwrap();

            tokio::task::spawn({
                let worker_client = worker_client.clone();
                let artifact_client = artifact_client.clone();
                let elf_artifact = elf_artifact.clone();
                let common_input_artifact = common_input_artifact.clone();
                let context = context.clone();
                let core_proofs_tx = core_proofs_tx.clone();
                async move {
                    tokio::time::sleep(core_start_delay).await;
                    for i in 1..=num_core_shards {
                        let range = ShardRange {
                            timestamp_range: (i, i + 1),
                            initialized_address_range: (0, 0),
                            finalized_address_range: (0, 0),
                            initialized_page_index_range: (0, 0),
                            finalized_page_index_range: (0, 0),
                            deferred_proof_range: (num_deferred_shards, num_deferred_shards),
                        };
                        create_dummy_prove_shard_task(
                            range,
                            elf_artifact.clone(),
                            common_input_artifact.clone(),
                            context.clone(),
                            &core_proofs_tx,
                            &worker_client,
                            &artifact_client,
                        )
                        .await;
                    }
                }
            });

            tokio::task::spawn({
                let worker_client = worker_client.clone();
                let artifact_client = artifact_client.clone();
                let elf_artifact = elf_artifact.clone();
                let common_input_artifact = common_input_artifact.clone();
                let context = context.clone();
                let core_proofs_tx = core_proofs_tx.clone();
                async move {
                    tokio::time::sleep(memory_start_delay).await;
                    for i in 0..num_memory_shards {
                        let range = ShardRange {
                            timestamp_range: (num_core_shards + 1, num_core_shards + 1),
                            initialized_address_range: (i, i + 1),
                            finalized_address_range: (i, i + 1),
                            initialized_page_index_range: (0, 0),
                            finalized_page_index_range: (0, 0),
                            deferred_proof_range: (num_deferred_shards, num_deferred_shards),
                        };
                        create_dummy_prove_shard_task(
                            range,
                            elf_artifact.clone(),
                            common_input_artifact.clone(),
                            context.clone(),
                            &core_proofs_tx,
                            &worker_client,
                            &artifact_client,
                        )
                        .await;
                    }
                }
            });

            tokio::task::spawn({
                let worker_client = worker_client.clone();
                let artifact_client = artifact_client.clone();
                let elf_artifact = elf_artifact.clone();
                let common_input_artifact = common_input_artifact.clone();
                let context = context.clone();
                let core_proofs_tx = core_proofs_tx.clone();
                async move {
                    tokio::time::sleep(precompile_start_delay).await;
                    for _ in 1..=num_precompile_shards {
                        let range = ShardRange::precompile();
                        create_dummy_prove_shard_task(
                            range,
                            elf_artifact.clone(),
                            common_input_artifact.clone(),
                            context.clone(),
                            &core_proofs_tx,
                            &worker_client,
                            &artifact_client,
                        )
                        .await;
                    }
                }
            });

            tokio::task::spawn({
                let worker_client = worker_client.clone();
                let artifact_client = artifact_client.clone();
                let elf_artifact = elf_artifact.clone();
                let common_input_artifact = common_input_artifact.clone();
                let context = context.clone();
                async move {
                    tokio::time::sleep(deferred_start_delay).await;
                    for i in 0..num_deferred_shards {
                        let range = ShardRange::deferred(i, i + 1);
                        create_dummy_prove_shard_task(
                            range,
                            elf_artifact.clone(),
                            common_input_artifact.clone(),
                            context.clone(),
                            &core_proofs_tx,
                            &worker_client,
                            &artifact_client,
                        )
                        .await;
                    }
                }
            });

            let output = artifact_client.create_artifact().unwrap();

            let worker_client = worker_client.clone();

            compress_tree
                .reduce_proofs(context, output, core_proofs_rx, &artifact_client, &worker_client)
                .await
                .unwrap();
        }
    }
}
