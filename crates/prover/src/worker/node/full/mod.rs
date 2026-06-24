use std::sync::Arc;

mod init;

pub use init::SP1LocalNodeBuilder;

use either::Either;
use mti::prelude::{MagicTypeIdExt, V7};
use sp1_core_executor::{ExecutionReport, SP1Context};
use sp1_core_machine::io::SP1Stdin;
use sp1_hypercube::{SP1PcsProofOuter, SP1VerifyingKey, SP1WrapProof};
use sp1_primitives::{io::SP1PublicValues, SP1OuterGlobalContext};
use sp1_prover_types::{
    network_base_types::ProofMode, Artifact, ArtifactClient, ArtifactType, InMemoryArtifactClient,
    ProofRequestStatus, TaskStatus, TaskType,
};
pub use sp1_verifier::{ProofFromNetwork, SP1Proof};
use tokio::task::JoinSet;
use tracing::{instrument, Instrument};

use crate::{
    shapes::DEFAULT_ARITY,
    worker::{
        LocalWorkerClient, ProofId, RawTaskRequest, RequesterId, SP1NodeCore, TaskContext,
        VkeyMapControllerInput, VkeyMapControllerOutput, WorkerClient,
    },
};

pub(crate) struct SP1NodeInner {
    artifact_client: InMemoryArtifactClient,
    worker_client: LocalWorkerClient,
    core: SP1NodeCore,
    _tasks: JoinSet<()>,
}

pub struct SP1LocalNode {
    inner: Arc<SP1NodeInner>,
}

impl Clone for SP1LocalNode {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl SP1LocalNode {
    pub fn core(&self) -> &SP1NodeCore {
        &self.inner.core
    }

    #[instrument(name = "execute_program", skip_all)]
    pub async fn execute(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        context: SP1Context<'static>,
    ) -> anyhow::Result<(SP1PublicValues, [u8; 32], ExecutionReport)> {
        self.inner.core.execute(elf, stdin, context).await
    }

    pub async fn setup(&self, elf: &[u8]) -> anyhow::Result<SP1VerifyingKey> {
        let elf_artifact = self.inner.artifact_client.create_artifact()?;
        self.inner.artifact_client.upload_program(&elf_artifact, elf.to_vec()).await?;

        // Create a setup task and wait for the vk
        let vk_artifact = self.inner.artifact_client.create_artifact()?;
        let context = TaskContext {
            proof_id: ProofId::new("core_proof"),
            parent_id: None,
            parent_context: None,
            requester_id: RequesterId::new("local node"),
        };
        let setup_request = RawTaskRequest {
            inputs: vec![elf_artifact.clone()],
            outputs: vec![vk_artifact.clone()],
            context: context.clone(),
        };
        tracing::trace!("submitting setup task");
        let setup_id =
            self.inner.worker_client.submit_task(TaskType::SetupVkey, setup_request).await?;
        // Wait for the setup task to finish
        let subscriber =
            self.inner.worker_client.subscriber(context.proof_id.clone()).await?.per_task();
        let status =
            subscriber.wait_task(setup_id).instrument(tracing::debug_span!("setup task")).await?;
        if status != TaskStatus::Succeeded {
            return Err(anyhow::anyhow!("setup task failed"));
        }
        tracing::trace!("setup task succeeded");
        // Download the vk
        let vk = self.inner.artifact_client.download::<SP1VerifyingKey>(&vk_artifact).await?;

        // Clean up the artifacts
        self.inner.artifact_client.try_delete(&elf_artifact, ArtifactType::Program).await?;
        self.inner
            .artifact_client
            .try_delete(&vk_artifact, ArtifactType::UnspecifiedArtifactType)
            .await?;

        Ok(vk)
    }

    pub async fn prove(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        context: SP1Context<'static>,
    ) -> anyhow::Result<ProofFromNetwork> {
        self.prove_with_mode(elf, stdin, context, ProofMode::Compressed).await
    }

    pub async fn build_vks(
        &self,
        range_or_limit: Option<Either<Vec<usize>, usize>>,
        chunk_size: usize,
    ) -> anyhow::Result<VkeyMapControllerOutput> {
        let vk_controller_artifact = self.inner.artifact_client.create_artifact()?;
        let input =
            VkeyMapControllerInput { range_or_limit, chunk_size, reduce_batch_size: DEFAULT_ARITY };
        self.inner.artifact_client.upload(&vk_controller_artifact, input).await?;

        let output_artifact = self.inner.artifact_client.create_artifact()?;

        let proof_id = ProofId::new("proof".create_type_id::<V7>().to_string());

        let request = RawTaskRequest {
            inputs: vec![vk_controller_artifact.clone()],
            outputs: vec![output_artifact.clone()],
            context: TaskContext {
                proof_id: proof_id.clone(),
                parent_id: None,
                parent_context: None,
                requester_id: RequesterId::new(format!("local-node-{}", std::process::id())),
            },
        };

        let task_id =
            self.inner.worker_client.submit_task(TaskType::UtilVkeyMapController, request).await?;
        let subscriber = self.inner.worker_client.subscriber(proof_id).await?.per_task();
        let status = subscriber.wait_task(task_id).await?;
        if status != TaskStatus::Succeeded {
            return Err(anyhow::anyhow!("controller task failed"));
        }

        // Clean up the input artifacts
        self.inner
            .artifact_client
            .try_delete(&vk_controller_artifact, ArtifactType::Program)
            .await?;

        // Download the output proof and return it.
        let output = self
            .inner
            .artifact_client
            .download::<VkeyMapControllerOutput>(&output_artifact)
            .await?;

        // Clean up the output artifact
        self.inner
            .artifact_client
            .try_delete(&output_artifact, ArtifactType::UnspecifiedArtifactType)
            .await?;

        Ok(output)
    }

    #[instrument(name = "prove", skip_all, fields(mode = ?mode))]
    pub async fn prove_with_mode(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        context: SP1Context<'static>,
        mode: ProofMode,
    ) -> anyhow::Result<ProofFromNetwork> {
        // Allocate the per-proof artifacts and id up front so the cleanup below
        // can always reach them, regardless of how the proving body exits.
        let elf_artifact = self.inner.artifact_client.create_artifact()?;
        let proof_nonce_artifact = self.inner.artifact_client.create_artifact()?;
        let stdin_artifact = self.inner.artifact_client.create_artifact()?;
        let output_artifact = self.inner.artifact_client.create_artifact()?;
        let proof_id = ProofId::new("proof".create_type_id::<V7>().to_string());

        // Run the actual proving. `?` inside only short-circuits this block; the
        // cleanup afterwards always runs (on both success and failure).
        let result = async {
            self.inner.artifact_client.upload_program(&elf_artifact, elf.to_vec()).await?;
            self.inner
                .artifact_client
                .upload::<[u32; 4]>(&proof_nonce_artifact, context.proof_nonce)
                .await?;
            self.inner
                .artifact_client
                .upload_with_type(&stdin_artifact, ArtifactType::Stdin, stdin)
                .await?;

            let mode_artifact = Artifact((mode as i32).to_string());
            let request = RawTaskRequest {
                inputs: vec![
                    elf_artifact.clone(),
                    stdin_artifact.clone(),
                    mode_artifact,
                    proof_nonce_artifact.clone(),
                ],
                outputs: vec![output_artifact.clone()],
                context: TaskContext {
                    proof_id: proof_id.clone(),
                    parent_id: None,
                    parent_context: None,
                    requester_id: RequesterId::new(format!("local-node-{}", std::process::id())),
                },
            };

            let task_id =
                self.inner.worker_client.submit_task(TaskType::Controller, request).await?;
            let subscriber =
                self.inner.worker_client.subscriber(proof_id.clone()).await?.per_task();
            let status = subscriber.wait_task(task_id).await?;
            if status != TaskStatus::Succeeded {
                return Err(anyhow::anyhow!("controller task failed"));
            }

            // Download the output proof.
            self.inner.artifact_client.download::<ProofFromNetwork>(&output_artifact).await
        }
        .await;

        // Always release this proof's task bookkeeping. The node (and its
        // worker_client) is reused across proofs, and `submit_task` records every
        // task in the worker client's `db`/`proof_index`; `complete_proof` is the
        // only thing that prunes them, so it must run for every proof.
        let status =
            if result.is_ok() { ProofRequestStatus::Completed } else { ProofRequestStatus::Failed };
        if let Err(e) =
            self.inner.worker_client.complete_proof(proof_id.clone(), None, status, "").await
        {
            tracing::warn!("failed to release task bookkeeping for proof {proof_id}: {e}");
        }

        // Delete whatever artifacts this proof leaked - the index has already
        // been pruned of everything deleted inline during proving, so this only
        // hits the leftovers (e.g. on an error path). The backstop that bounds
        // growth across proofs.
        self.inner.worker_client.cleanup(&proof_id, &self.inner.artifact_client).await;

        result
    }

    pub fn verify(&self, vk: &SP1VerifyingKey, proof: &SP1Proof) -> anyhow::Result<()> {
        self.inner.core.verify(vk, proof)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn wrap_vk(&self) -> &sp1_hypercube::MachineVerifyingKey<SP1OuterGlobalContext> {
        self.inner.core.wrap_vk()
    }

    /// Convert the given compressed proof to a proof that can be verified by the groth16 circuit.
    pub async fn shrink_wrap(
        &self,
        compressed_proof: &SP1Proof,
    ) -> anyhow::Result<SP1WrapProof<SP1OuterGlobalContext, SP1PcsProofOuter>> {
        let compressed_proof = match compressed_proof {
            SP1Proof::Compressed(proof) => *proof.clone(),
            _ => return Err(anyhow::anyhow!("given proof is not a compressed proof")),
        };
        // Upload the compressed proof to the artifact client
        let compressed_proof_artifact = self.inner.artifact_client.create_artifact()?;
        self.inner.artifact_client.upload(&compressed_proof_artifact, compressed_proof).await?;

        // Create an artifact for the output
        let output_artifact = self.inner.artifact_client.create_artifact()?;

        // Create a task request for the shrink wrap task
        let proof_id = ProofId::new("shrink wrap".create_type_id::<V7>().to_string());
        let request = RawTaskRequest {
            inputs: vec![compressed_proof_artifact.clone()],
            outputs: vec![output_artifact.clone()],
            context: TaskContext {
                proof_id: proof_id.clone(),
                parent_id: None,
                parent_context: None,
                requester_id: RequesterId::new(format!("local-node-{}", std::process::id())),
            },
        };

        let task_id = self.inner.worker_client.submit_task(TaskType::ShrinkWrap, request).await?;
        // Wait for the task to finish
        let subscriber = self.inner.worker_client.subscriber(proof_id).await?.per_task();
        let status = subscriber.wait_task(task_id).await?;
        if status != TaskStatus::Succeeded {
            return Err(anyhow::anyhow!("shrink wrap task failed"));
        }

        // Download the output proof and return it.
        let proof = self
            .inner
            .artifact_client
            .download::<SP1WrapProof<SP1OuterGlobalContext, SP1PcsProofOuter>>(&output_artifact)
            .await?;
        // Clean up the input and output artifacts
        tokio::try_join!(
            self.inner
                .artifact_client
                .try_delete(&compressed_proof_artifact, ArtifactType::UnspecifiedArtifactType),
            self.inner
                .artifact_client
                .try_delete(&output_artifact, ArtifactType::UnspecifiedArtifactType)
        )?;

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;
    use sp1_core_machine::{riscv::RiscvAir, utils::setup_logger};

    use crate::{components::SP1ProverComponents, CpuSP1ProverComponents};
    use sp1_hypercube::HashableKey;

    use crate::worker::{
        cpu_worker_builder, cpu_worker_builder_with_machine, SP1LocalNodeBuilder, SP1WorkerBuilder,
    };

    use super::*;

    async fn run_e2e_node_test(
        builder: SP1WorkerBuilder<CpuSP1ProverComponents>,
    ) -> anyhow::Result<()> {
        let elf = test_artifacts::FIBONACCI_ELF;
        let stdin = SP1Stdin::default();
        let mode = ProofMode::Compressed;

        let client =
            SP1LocalNodeBuilder::from_worker_client_builder(builder).build().await.unwrap();

        let proof_nonce = [0x6284, 0xC0DE, 0x4242, 0xCAFE];

        let time = tokio::time::Instant::now();
        let context = SP1Context { proof_nonce, ..Default::default() };

        let (_, _, report) = client.execute(&elf, stdin.clone(), context.clone()).await.unwrap();

        let execute_time = time.elapsed();
        let cycles = report.total_instruction_count() as usize;
        tracing::info!(
            "execute time: {:?}, cycles: {}, gas: {:?}",
            execute_time,
            cycles,
            report.gas()
        );

        let time = tokio::time::Instant::now();
        let vk = client.setup(&elf).await.unwrap();
        let setup_time = time.elapsed();
        tracing::info!("setup time: {:?}", setup_time);

        let time = tokio::time::Instant::now();

        tracing::info!("proving with mode: {mode:?}");
        let proof = client
            .prove_with_mode(&elf, stdin.clone(), context.clone(), mode)
            .await
            .expect("proof failed");
        let proof_time = time.elapsed();
        tracing::info!("proof time: {:?}", proof_time);

        // Verify the proof
        tokio::task::spawn_blocking(move || client.verify(&vk, &proof.proof).unwrap())
            .await
            .unwrap();

        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore = "placeholder recursion programs can't verify shared-FS core proofs; the vk-verifying variant also needs vk_map regen"]
    async fn test_e2e_node() -> anyhow::Result<()> {
        setup_logger();
        run_e2e_node_test(cpu_worker_builder()).await
    }

    /// Drive the real `SpliceChunkWorker` pipeline in Core mode and verify the resulting shard
    /// proofs. Verification is `verify_core_shards` (per-chunk seam + `Σ` cancellation).
    #[tokio::test]
    #[serial]
    async fn worker_core_pipeline_proof_verifies() -> anyhow::Result<()> {
        setup_logger();

        let machine = RiscvAir::machine();
        let client = SP1LocalNodeBuilder::from_worker_client_builder(
            cpu_worker_builder_with_machine(machine.clone()),
        )
        .build()
        .await
        .unwrap();

        let elf = test_artifacts::FIBONACCI_ELF;
        let stdin = SP1Stdin::default();
        let context =
            SP1Context { proof_nonce: [0x6284, 0xC0DE, 0x4242, 0xCAFE], ..Default::default() };

        let vk = client.setup(&elf).await.unwrap();
        let proof = client
            .prove_with_mode(&elf, stdin, context, ProofMode::Core)
            .await
            .expect("core proof failed");

        let shard_proofs = match proof.proof {
            SP1Proof::Core(shards) => shards,
            _ => panic!("expected a core proof"),
        };
        assert!(!shard_proofs.is_empty(), "core proof has no shards");

        let core_verifier = CpuSP1ProverComponents::core_verifier(machine);
        let proof_data = crate::SP1CoreProofData(shard_proofs);
        crate::verify::verify_core_shards(&core_verifier, &vk.vk, &proof_data)
            .expect("worker-produced core proof must verify under the per-chunk seam");

        Ok(())
    }

    /// Drive the real `SpliceChunkWorker` pipeline in *compress* mode and assert the node folds each
    /// `TraceChunk`'s shards into exactly one `ChunkProof`.
    #[tokio::test]
    #[serial]
    async fn worker_compress_pipeline_emits_one_chunk_proof_per_chunk() -> anyhow::Result<()> {
        use std::{collections::BTreeSet, sync::Arc};

        use sp1_hypercube::{SP1PcsProofInner, SP1RecursionProof, SP1VerifyingKey, DIGEST_SIZE};
        use sp1_primitives::SP1GlobalContext;
        use sp1_recursion_circuit::dummy::dummy_vk;
        use tokio::sync::mpsc;

        use crate::worker::{
            drive_chunk_consumer, CommonProverInput, CoreExecuteTaskRequest, MockRecursionStages,
            ProofData, RecursionStages, TaskId,
        };

        setup_logger();

        let machine = RiscvAir::machine();
        let worker = cpu_worker_builder_with_machine(machine.clone()).build().await.unwrap();
        let artifact_client = worker.artifact_client().clone();
        let worker_client = worker.worker_client().clone();

        // Stage the `CoreExecute` inputs. The vk is a dummy: the node's core proving derives its pk
        // from the program, and the mock `normalize` ignores the vk.
        let elf_art = artifact_client.create_artifact()?;
        artifact_client.upload_program(&elf_art, test_artifacts::FIBONACCI_ELF.to_vec()).await?;
        let stdin_art = artifact_client.create_artifact()?;
        artifact_client.upload(&stdin_art, SP1Stdin::default()).await?;
        let common_art = artifact_client.create_artifact()?;
        artifact_client
            .upload(
                &common_art,
                CommonProverInput {
                    vk: SP1VerifyingKey { vk: dummy_vk() },
                    mode: ProofMode::Compressed,
                    deferred_digest: [0u32; DIGEST_SIZE],
                    num_deferred_proofs: 0,
                    nonce: [0x6284, 0xC0DE, 0x4242, 0xCAFE],
                },
            )
            .await?;
        let output_art = artifact_client.create_artifact()?;

        let context = TaskContext {
            proof_id: ProofId::new("compress-node-test"),
            parent_id: None,
            parent_context: None,
            requester_id: RequesterId::new("compress-node-test"),
        };
        let request = CoreExecuteTaskRequest {
            elf: elf_art,
            stdin: stdin_art,
            common_input: common_art,
            execution_output: output_art,
            num_deferred_proofs: 0,
            cycle_limit: None,
            context,
            machine: machine.clone(),
            stdin_private: false,
        };

        // Subscribe to the executor task's `ProofData` stream before driving it.
        let task_id = TaskId::new("compress-node-core-execute");
        let mut msg_rx = worker_client.subscribe_task_messages(&task_id).await?;

        // Mock the recursion seam.
        let recursion: Arc<dyn RecursionStages> =
            Arc::new(MockRecursionStages::new(artifact_client.clone()));
        let core_prover = worker.prover_engine().core_prover.air_prover();
        let permits = worker.prover_engine().core_prover.permits();
        let controller = worker.controller();
        let engine = controller.initialize_splice_chunk_engine::<CpuSP1ProverComponents>(
            core_prover,
            permits,
            recursion,
        );

        let (chunk_tx, chunk_rx) = mpsc::channel(controller.splicing_buffer_size());
        let (exec_res, consumer_res) = tokio::join!(
            controller.execute(task_id.clone(), request, chunk_tx),
            drive_chunk_consumer(engine, chunk_rx),
        );
        exec_res.expect("executor completed");
        consumer_res.expect("chunk consumer drained every in-flight chunk");

        // Every `ProofData` was sent before the node tasks returned, so the buffered messages are
        // all present now.
        let mut chunk_starts = BTreeSet::new();
        let mut count = 0usize;
        while let Ok(bytes) = msg_rx.try_recv() {
            match bincode::deserialize::<ProofData>(&bytes)? {
                ProofData::ChunkProof { chunk_range, proof } => {
                    artifact_client
                        .download::<SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>>(&proof)
                        .await
                        .expect("chunk proof artifact must be uploaded and downloadable");
                    assert_eq!(
                        chunk_range.len(),
                        1,
                        "node emits single-chunk ranges, got {chunk_range:?}"
                    );
                    assert!(
                        chunk_starts.insert(chunk_range.start),
                        "duplicate chunk proof for trace_chunk_idx {}",
                        chunk_range.start
                    );
                    count += 1;
                }
                _ => panic!("compress mode must emit only ChunkProof variants"),
            }
        }

        assert!(count > 0, "compress run emitted no chunk proofs");
        assert_eq!(count, chunk_starts.len(), "exactly one chunk proof per trace_chunk_idx");

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "experimental")]
    #[serial]
    async fn test_e2e_node_experimental() -> anyhow::Result<()> {
        setup_logger();
        run_e2e_node_test(cpu_worker_builder().without_vk_verification()).await
    }

    #[tokio::test]
    #[cfg(feature = "mprotect")]
    #[serial]
    async fn test_e2e_node_trap() -> anyhow::Result<()> {
        setup_logger();
        let elf = test_artifacts::TRAP_LOAD_STORE_ELF;
        let stdin = SP1Stdin::default();
        let mode = ProofMode::Compressed;
        let client = SP1LocalNodeBuilder::from_worker_client_builder(
            cpu_worker_builder().without_vk_verification(),
        )
        .build()
        .await
        .unwrap();
        let proof_nonce = [0x6284, 0xC0DE, 0x4242, 0xCAFE];
        let context = SP1Context { proof_nonce, ..Default::default() };
        let (_, _, report) = client.execute(&elf, stdin.clone(), context.clone()).await.unwrap();
        let cycles = report.total_instruction_count() as usize;
        tracing::info!("cycles: {}", cycles);
        let vk = client.setup(&elf).await.unwrap();
        let time = tokio::time::Instant::now();
        let proof = client.prove_with_mode(&elf, stdin, context, mode).await.unwrap();
        tracing::info!("prove time: {:?}", time.elapsed());
        tokio::task::spawn_blocking(move || client.verify(&vk, &proof.proof).unwrap())
            .await
            .unwrap();
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore = "only run to write the vk root and num keys to a file"]
    async fn make_verifier_vks() -> anyhow::Result<()> {
        setup_logger();

        let client = SP1LocalNodeBuilder::from_worker_client_builder(cpu_worker_builder())
            .build()
            .await
            .unwrap();

        let recursion_vks = client.core().recursion_vks();

        let mut file = std::fs::File::create("../verifier/vk-artifacts/verifier_vks.bin")?;

        bincode::serialize_into(&mut file, &recursion_vks)?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore]
    async fn test_e2e_groth16_node() -> anyhow::Result<()> {
        setup_logger();

        let elf = test_artifacts::FIBONACCI_ELF;
        let stdin = SP1Stdin::default();
        let mode = ProofMode::Groth16;

        let machine = RiscvAir::machine();
        let client = SP1LocalNodeBuilder::from_worker_client_builder(
            cpu_worker_builder_with_machine(machine),
        )
        .build()
        .await
        .unwrap();

        let time = tokio::time::Instant::now();
        let context = SP1Context::default();
        let (_, _, report) = client.execute(&elf, stdin.clone(), context.clone()).await.unwrap();
        let execute_time = time.elapsed();
        let cycles = report.total_instruction_count() as usize;
        tracing::info!(
            "execute time: {:?}, cycles: {}, gas: {:?}",
            execute_time,
            cycles,
            report.gas()
        );

        let time = tokio::time::Instant::now();
        let vk = client.setup(&elf).await.unwrap();
        let setup_time = time.elapsed();
        tracing::info!("setup time: {:?}", setup_time);

        let time = tokio::time::Instant::now();

        tracing::info!("proving with mode: {mode:?}");
        let proof = client.prove_with_mode(&elf, stdin, context, mode).await.unwrap();
        let proof_time = time.elapsed();
        tracing::info!("proof time: {:?}", proof_time);

        // Verify the proof
        tokio::task::spawn_blocking(move || client.verify(&vk, &proof.proof).unwrap())
            .await
            .unwrap();

        Ok(())
    }

    /// Test that changing the vk_root (by modifying a vk_map entry) does NOT change the wrap VK
    /// or the Groth16 circuit. This confirms that vk_root is purely a witness variable.
    ///
    /// Note: Before running this test with `SP1_CIRCUIT_MODE=dev`, ensure that there are circuit
    /// artifacts for the current wrap VK (either on S3 or locally cached). Otherwise, the test
    /// will rebuild circuit artifacts locally, which may cause the test to pass incorrectly.
    #[tokio::test]
    #[serial]
    #[cfg(feature = "experimental")]
    #[ignore = "sanity check test; see doc-comment for proper usage"]
    async fn test_e2e_groth16_node_modified_vk_root() -> anyhow::Result<()> {
        use slop_algebra::AbstractField;
        use sp1_primitives::SP1Field;
        use sp1_recursion_executor::DIGEST_SIZE;
        use std::collections::BTreeMap;
        use std::io::Write;

        setup_logger();

        // Step 1: Load the original vk_map and modify the first entry.
        let original_map: BTreeMap<[SP1Field; DIGEST_SIZE], usize> =
            bincode::deserialize(include_bytes!("../../../vk_map.bin"))
                .expect("failed to deserialize vk_map.bin");
        tracing::info!("original vk_map has {} entries", original_map.len());

        let mut modified_map = original_map.clone();
        let first_key = *modified_map.keys().next().unwrap();
        let first_val = modified_map.remove(&first_key).unwrap();
        let mut new_key = first_key;
        new_key[0] += SP1Field::one();
        modified_map.insert(new_key, first_val);
        assert_eq!(modified_map.len(), original_map.len(), "map size should not change");

        // Step 2: Write modified vk_map to a temp file.
        let temp_dir = tempfile::tempdir()?;
        let vk_map_path = temp_dir.path().join("modified_vk_map.bin");
        {
            let mut file = std::fs::File::create(&vk_map_path)?;
            bincode::serialize_into(&mut file, &modified_map)?;
            file.flush()?;
        }
        tracing::info!("wrote modified vk_map to {:?}", vk_map_path);

        // Step 3: Build the prover with the modified vk_map (vk_verification stays ON).
        let builder =
            cpu_worker_builder().with_vk_map_path(vk_map_path.to_str().unwrap().to_string());

        let elf = test_artifacts::FIBONACCI_ELF;
        let stdin = SP1Stdin::default();
        let mode = ProofMode::Groth16;

        let client =
            SP1LocalNodeBuilder::from_worker_client_builder(builder).build().await.unwrap();

        // Step 4: Verify that the wrap VK hasn't changed by checking the Groth16 artifacts
        // cache directory. If the wrap VK is the same, the same cache dir
        // (based on wrap VK hash) will be used and the existing artifacts reused.
        let time = tokio::time::Instant::now();
        let vk = client.setup(&elf).await.unwrap();
        tracing::info!("setup time: {:?}", time.elapsed());

        let time = tokio::time::Instant::now();
        let context = SP1Context::default();
        tracing::info!("proving with mode: {mode:?} (modified vk_root)");
        let proof = client.prove_with_mode(&elf, stdin, context, mode).await.unwrap();
        tracing::info!("proof time: {:?}", time.elapsed());

        // Step 5: Verify the proof. This uses the cached Groth16 artifacts
        // (from the previous test_e2e_groth16_node run) since the wrap VK is unchanged.
        // If the Groth16 circuit had changed, verification would fail.
        tokio::task::spawn_blocking(move || {
            client.verify(&vk, &proof.proof).unwrap();
            tracing::info!("verification with modified vk_root PASSED");
        })
        .await
        .unwrap();

        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore = "placeholder recursion programs can't verify shared-FS core proofs; the vk-verifying variant also needs vk_map regen"]
    async fn test_node_deferred_compress() -> anyhow::Result<()> {
        setup_logger();

        let client = SP1LocalNodeBuilder::from_worker_client_builder(cpu_worker_builder())
            .build()
            .await
            .unwrap();

        // Test program which proves the Keccak-256 hash of various inputs.
        let keccak_elf = test_artifacts::KECCAK256_ELF;

        // Test program which verifies proofs of a vkey and a list of committed inputs.
        let verify_elf = test_artifacts::VERIFY_PROOF_ELF;

        tracing::info!("setup keccak elf");
        let keccak_vk = client.setup(&keccak_elf).await?;

        tracing::info!("setup verify elf");
        let verify_vk = client.setup(&verify_elf).await?;

        tracing::info!("prove subproof 1");
        let mut stdin = SP1Stdin::new();
        stdin.write(&1usize);
        stdin.write(&vec![0u8, 0, 0]);
        let context = SP1Context::default();
        let deferred_proof_1 = client
            .prove_with_mode(&keccak_elf, stdin, context.clone(), ProofMode::Compressed)
            .await?;
        let pv_1 = deferred_proof_1.public_values.as_slice().to_vec().clone();

        // Generate a second proof of keccak of various inputs.
        tracing::info!("prove subproof 2");
        let mut stdin = SP1Stdin::new();
        stdin.write(&3usize);
        stdin.write(&vec![0u8, 1, 2]);
        stdin.write(&vec![2, 3, 4]);
        stdin.write(&vec![5, 6, 7]);
        let deferred_proof_2 = client
            .prove_with_mode(&keccak_elf, stdin, context.clone(), ProofMode::Compressed)
            .await?;
        let pv_2 = deferred_proof_2.public_values.as_slice().to_vec().clone();

        let deferred_reduce_1 = match deferred_proof_1.proof {
            SP1Proof::Compressed(proof) => *proof,
            _ => return Err(anyhow::anyhow!("deferred proof 1 is not a compressed proof")),
        };
        let deferred_reduce_2 = match deferred_proof_2.proof {
            SP1Proof::Compressed(proof) => *proof,
            _ => return Err(anyhow::anyhow!("deferred proof 2 is not a compressed proof")),
        };

        // Exercise deferred proof verification during execute.
        let mut invalid_proof = deferred_reduce_1.clone();
        invalid_proof.proof.public_values.clear();
        let mut execute_stdin = SP1Stdin::new();
        let vkey_digest = keccak_vk.hash_u32();
        execute_stdin.write(&vkey_digest);
        execute_stdin.write(&vec![pv_1.clone(), pv_2.clone(), pv_2.clone()]);
        execute_stdin.write_proof(invalid_proof, keccak_vk.vk.clone());
        execute_stdin.write_proof(deferred_reduce_2.clone(), keccak_vk.vk.clone());
        execute_stdin.write_proof(deferred_reduce_2.clone(), keccak_vk.vk.clone());

        let execute_result = client.execute(&verify_elf, execute_stdin, context.clone()).await;
        let err = execute_result.expect_err("expected deferred proof verification to fail");
        assert!(
            err.to_string().contains("deferred proof 0 failed verification"),
            "unexpected error: {err}"
        );

        // Execute verify program with deferred proof verification enabled and valid proofs.
        let mut execute_stdin = SP1Stdin::new();
        let vkey_digest = keccak_vk.hash_u32();
        execute_stdin.write(&vkey_digest);
        execute_stdin.write(&vec![pv_1.clone(), pv_2.clone(), pv_2.clone()]);
        execute_stdin.write_proof(deferred_reduce_1.clone(), keccak_vk.vk.clone());
        execute_stdin.write_proof(deferred_reduce_2.clone(), keccak_vk.vk.clone());
        execute_stdin.write_proof(deferred_reduce_2.clone(), keccak_vk.vk.clone());

        let (_execute_pv, _execute_digest, execute_report) =
            client.execute(&verify_elf, execute_stdin, context.clone()).await?;
        assert_eq!(execute_report.exit_code, 0);

        // Run verify program with keccak vkey, subproofs, and their committed values.
        let mut stdin = SP1Stdin::new();
        let vkey_digest = keccak_vk.hash_u32();
        stdin.write(&vkey_digest);
        stdin.write(&vec![pv_1.clone(), pv_2.clone(), pv_2.clone()]);
        stdin.write_proof(deferred_reduce_1.clone(), keccak_vk.vk.clone());
        stdin.write_proof(deferred_reduce_2.clone(), keccak_vk.vk.clone());
        stdin.write_proof(deferred_reduce_2.clone(), keccak_vk.vk.clone());

        tracing::info!("proving verify program (core)");
        let verify_proof =
            client.prove_with_mode(&verify_elf, stdin, context, ProofMode::Compressed).await?;

        tracing::info!("verifying verify proof");
        tokio::task::spawn_blocking(move || {
            client.verify(&verify_vk, &verify_proof.proof).unwrap()
        })
        .await
        .unwrap();

        Ok(())
    }
}
