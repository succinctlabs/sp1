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
    TaskStatus, TaskType,
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

    pub async fn prove_with_mode(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
        context: SP1Context<'static>,
        mode: ProofMode,
    ) -> anyhow::Result<ProofFromNetwork> {
        let elf_artifact = self.inner.artifact_client.create_artifact()?;
        self.inner.artifact_client.upload_program(&elf_artifact, elf.to_vec()).await?;

        let proof_nonce_artifact = self.inner.artifact_client.create_artifact()?;
        self.inner
            .artifact_client
            .upload::<[u32; 4]>(&proof_nonce_artifact, context.proof_nonce)
            .await?;

        let stdin_artifact = self.inner.artifact_client.create_artifact()?;
        self.inner
            .artifact_client
            .upload_with_type(&stdin_artifact, ArtifactType::Stdin, stdin)
            .await?;

        let mode_artifact = Artifact((mode as i32).to_string());

        // Create an artifact for the output
        let output_artifact = self.inner.artifact_client.create_artifact()?;

        let proof_id = ProofId::new("proof".create_type_id::<V7>().to_string());
        let request = RawTaskRequest {
            inputs: vec![
                elf_artifact.clone(),
                stdin_artifact.clone(),
                mode_artifact.clone(),
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

        let task_id = self.inner.worker_client.submit_task(TaskType::Controller, request).await?;
        let subscriber = self.inner.worker_client.subscriber(proof_id).await?.per_task();
        let status = subscriber.wait_task(task_id).await?;
        if status != TaskStatus::Succeeded {
            return Err(anyhow::anyhow!("controller task failed"));
        }

        // Clean up the input artifacts
        self.inner.artifact_client.try_delete(&elf_artifact, ArtifactType::Program).await?;
        self.inner.artifact_client.try_delete(&stdin_artifact, ArtifactType::Stdin).await?;

        // Download the output proof and return it.
        let proof =
            self.inner.artifact_client.download::<ProofFromNetwork>(&output_artifact).await?;
        // Clean up the output artifact
        self.inner
            .artifact_client
            .try_delete(&output_artifact, ArtifactType::UnspecifiedArtifactType)
            .await?;

        self.inner
            .artifact_client
            .try_delete(&proof_nonce_artifact, ArtifactType::UnspecifiedArtifactType)
            .await?;

        Ok(proof)
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
    use sp1_core_machine::utils::setup_logger;

    use crate::CpuSP1ProverComponents;
    use sp1_hypercube::HashableKey;

    use crate::worker::{cpu_worker_builder, SP1LocalNodeBuilder, SP1WorkerBuilder};

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
    async fn test_e2e_node() -> anyhow::Result<()> {
        setup_logger();
        run_e2e_node_test(cpu_worker_builder()).await
    }

    #[tokio::test]
    #[cfg(feature = "experimental")]
    #[serial]
    async fn test_e2e_node_experimental() -> anyhow::Result<()> {
        setup_logger();
        run_e2e_node_test(cpu_worker_builder().without_vk_verification()).await
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
    async fn test_e2e_groth16_node() -> anyhow::Result<()> {
        setup_logger();

        let elf = test_artifacts::FIBONACCI_ELF;
        let stdin = SP1Stdin::default();
        let mode = ProofMode::Groth16;

        let client = SP1LocalNodeBuilder::from_worker_client_builder(cpu_worker_builder())
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

    #[tokio::test]
    #[serial]
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
