//! The wiring/crypto seam for two-stage recursion (compress mode).
//!
//! [`RecursionStages`] is the only surface the worker drives; the recursion circuit programs live
//! behind it. `SP1RecursionProver` implements it in production; `MockRecursionStages` stands in
//! for tests that exercise the plumbing without real crypto.

use futures::future::BoxFuture;
use slop_challenger::IopCtx;
use sp1_hypercube::{SP1PcsProofInner, SP1RecursionProof, ShardProof};
use sp1_primitives::SP1GlobalContext;
use sp1_prover_types::Artifact;

use crate::worker::{CommonProverInput, TaskError};

/// The inner recursion proof type produced by every stage.
type StageProof = SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>;

/// The per-chunk shared Fiat-Shamir context handed to every `normalize` call: the ordered chunk
/// commitments and merkle roots the shared global challenge is derived from, plus this shard's
/// position in the chunk. Built in-node from the chunk's broadcast prove data.
#[derive(Clone, Debug)]
pub struct ChunkChallengeCtx {
    /// The chunk's ordered global commitments; their hash binds the shared challenge.
    pub commitments: Vec<<SP1GlobalContext as IopCtx>::Digest>,
    /// The chunk's start merkle root.
    pub prev_root: [u32; 8],
    /// The chunk's end merkle root.
    pub cur_root: [u32; 8],
    /// This shard's index within the chunk.
    pub shard_index: u32,
    /// The number of shards in the chunk.
    pub num_shards: u32,
}

/// Isolates the recursion circuit programs from the worker plumbing.
pub trait RecursionStages: Send + Sync {
    /// Normalize the core proof.
    fn normalize<'a>(
        &'a self,
        common: &'a CommonProverInput,
        core_proof: ShardProof<SP1GlobalContext, SP1PcsProofInner>,
        chunk_ctx: &'a ChunkChallengeCtx,
        out: Artifact,
    ) -> BoxFuture<'a, Result<StageProof, TaskError>>;

    /// Reduce same-chunk proofs into one.
    fn within_chunk_reduce<'a>(
        &'a self,
        // 1 or 2 children; len 1 is the arity-1 carry (odd node / single-chunk or single-shard root)
        children: Vec<StageProof>,
        is_chunk_complete: bool,
        out: Artifact,
    ) -> BoxFuture<'a, Result<StageProof, TaskError>>;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use slop_algebra::AbstractField;
    use sp1_hypercube::{
        air::POSEIDON_NUM_WORDS, create_dummy_recursion_proof, MachineVerifyingKey,
        SP1VerifyingKey, UntrustedConfig, DIGEST_SIZE,
    };
    use sp1_primitives::SP1Field;
    use sp1_prover_types::{network_base_types::ProofMode, ArtifactClient, InMemoryArtifactClient};

    use super::*;
    use crate::worker::MockRecursionStages;

    fn dummy_vk() -> SP1VerifyingKey {
        SP1VerifyingKey {
            vk: MachineVerifyingKey {
                pc_start: [SP1Field::zero(); 3],
                initial_memory_root: [SP1Field::zero(); POSEIDON_NUM_WORDS],
                preprocessed_commit: [SP1Field::zero(); DIGEST_SIZE],
                untrusted_config: UntrustedConfig::zero(),
            },
        }
    }

    fn dummy_common(vk: SP1VerifyingKey) -> CommonProverInput {
        CommonProverInput {
            vk,
            mode: ProofMode::Compressed,
            deferred_digest: [0u32; DIGEST_SIZE],
            num_deferred_proofs: 0,
            nonce: [0u32; 4],
        }
    }

    /// Each stage of the mock emits a proof and uploads it; driving the seam through `dyn` also
    /// pins object-safety of the trait.
    #[tokio::test]
    async fn mock_recursion_stages_emit_and_upload() {
        let artifact_client = InMemoryArtifactClient::new();
        let stages = MockRecursionStages::new(artifact_client.clone());
        let vk = dummy_vk();
        let common = dummy_common(vk.clone());
        let ctx = ChunkChallengeCtx {
            commitments: vec![],
            prev_root: [0; 8],
            cur_root: [0; 8],
            shard_index: 0,
            num_shards: 1,
        };

        let core_proof = create_dummy_recursion_proof(&vk).proof;
        let out0 = artifact_client.create_artifact().unwrap();
        let leaf = stages.normalize(&common, core_proof, &ctx, out0.clone()).await.unwrap();
        artifact_client
            .download::<StageProof>(&out0)
            .await
            .expect("normalize should have uploaded a leaf proof");

        let dyn_stages: Arc<dyn RecursionStages> = Arc::new(stages);

        // Arity-2 reduces.
        let out1 = artifact_client.create_artifact().unwrap();
        dyn_stages
            .within_chunk_reduce(vec![leaf.clone(), leaf.clone()], true, out1.clone())
            .await
            .unwrap();
        artifact_client.download::<StageProof>(&out1).await.expect("within-chunk reduce uploads");

        // Arity-1 carry (single-chunk / single-shard root): one child is allowed.
        let out3 = artifact_client.create_artifact().unwrap();
        dyn_stages.within_chunk_reduce(vec![leaf.clone()], true, out3.clone()).await.unwrap();
        artifact_client
            .download::<StageProof>(&out3)
            .await
            .expect("arity-1 within-chunk reduce uploads");
    }
}
