use std::borrow::Borrow;

use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractField, PrimeField32};

use sp1_hypercube::{
    air::{ShardRange, POSEIDON_NUM_WORDS},
    MerkleProof, SP1PcsProofInner, SP1RecursionProof,
};
use sp1_primitives::{hash_deferred_proof, SP1Field, SP1GlobalContext};
use sp1_prover_types::{Artifact, ArtifactClient, TaskType};
use sp1_recursion_circuit::machine::SP1ShapedWitnessValues;
use sp1_recursion_executor::{RecursionPublicValues, DIGEST_SIZE};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    utils::words_to_bytes,
    worker::{ProofData, RecursionDeferredTaskRequest, TaskContext, TaskError, WorkerClient},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct SP1DeferredData {
    pub input: SP1ShapedWitnessValues<SP1GlobalContext, SP1PcsProofInner>,
    pub vk_merkle_proofs: Vec<MerkleProof<SP1GlobalContext>>,
    pub start_reconstruct_deferred_digest: [SP1Field; POSEIDON_NUM_WORDS],
    pub deferred_proof_index: SP1Field,
}

pub struct DeferredInputs {
    inputs: Vec<SP1DeferredData>,
    deferred_digest: [SP1Field; DIGEST_SIZE],
}

impl DeferredInputs {
    pub fn new(
        deferred_proofs: impl IntoIterator<Item = SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>>,
        initial_deferred_digest: [SP1Field; DIGEST_SIZE],
    ) -> Self {
        // Prepare the inputs for the deferred proofs recursive verification.
        let mut deferred_digest = initial_deferred_digest;
        let mut deferred_inputs = Vec::new();

        for (index, proof) in deferred_proofs.into_iter().enumerate() {
            let vks_and_proofs = vec![(proof.vk.clone(), proof.proof.clone())];
            let merkle_proofs = vec![proof.vk_merkle_proof.clone()];

            let input = SP1ShapedWitnessValues { vks_and_proofs, is_complete: true };

            deferred_inputs.push(SP1DeferredData {
                input,
                start_reconstruct_deferred_digest: deferred_digest,
                vk_merkle_proofs: merkle_proofs,
                deferred_proof_index: SP1Field::from_canonical_usize(index),
            });

            deferred_digest = hash_deferred_proofs(deferred_digest, &[proof]);
        }
        DeferredInputs { inputs: deferred_inputs, deferred_digest }
    }

    pub fn num_deferred_proofs(&self) -> usize {
        self.inputs.len()
    }

    pub fn deferred_digest(&self) -> [SP1Field; DIGEST_SIZE] {
        self.deferred_digest
    }

    pub async fn emit_deferred_tasks(
        self,
        common_input: Artifact,
        context: TaskContext,
        core_proofs_tx: UnboundedSender<ProofData>,
        artifact_client: impl ArtifactClient,
        worker_client: impl WorkerClient,
    ) -> Result<(), TaskError> {
        for input in self.inputs {
            // Calculate the range of the deferred proof.
            let prev_deferred_proof = input.deferred_proof_index.as_canonical_u32() as u64;
            let deferred_proof = prev_deferred_proof + input.input.vks_and_proofs.len() as u64;
            let range = ShardRange::deferred(prev_deferred_proof, deferred_proof);
            // Upload the input
            let deferred_data = artifact_client.create_artifact()?;
            artifact_client.upload(&deferred_data, input).await?;
            // Create the output artifact
            let output = artifact_client.create_artifact()?;

            let task_request = RecursionDeferredTaskRequest {
                common_input: common_input.clone(),
                deferred_data,
                output: output.clone(),
                context: context.clone(),
            };
            let task_request = task_request.into_raw()?;
            let task_id =
                worker_client.submit_task(TaskType::RecursionDeferred, task_request).await?;
            // Send the id and output to the channel.
            let proof_data = ProofData { task_id, range, proof: output };
            core_proofs_tx
                .send(proof_data)
                .map_err(|_| TaskError::Fatal(anyhow::anyhow!("Controller panicked, failed to send deferred proof data to core proofs channel")))?;
        }
        Ok(())
    }
}

pub fn hash_deferred_proofs(
    prev_digest: [SP1Field; DIGEST_SIZE],
    deferred_proofs: &[SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>],
) -> [SP1Field; 8] {
    let mut digest = prev_digest;
    for proof in deferred_proofs.iter() {
        let pv: &RecursionPublicValues<SP1Field> = proof.proof.public_values.as_slice().borrow();
        let committed_values_digest = words_to_bytes(&pv.committed_value_digest);

        digest = hash_deferred_proof(
            &digest,
            &pv.sp1_vk_digest,
            &committed_values_digest.try_into().unwrap(),
        );
    }
    digest
}
