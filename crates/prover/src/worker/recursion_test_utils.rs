//! Test doubles for the worker's recursion seam.

use futures::future::BoxFuture;
use sp1_hypercube::{
    create_dummy_recursion_proof, SP1PcsProofInner, SP1RecursionProof, ShardProof,
};
use sp1_primitives::SP1GlobalContext;
use sp1_prover_types::{Artifact, ArtifactClient};

use crate::worker::{ChunkChallengeCtx, CommonProverInput, RecursionStages, TaskError};

/// The inner recursion proof type produced by every stage.
type StageProof = SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>;

/// Test double for [`RecursionStages`]: emits and uploads a dummy proof for each stage without any
/// verification, so the node/controller plumbing can be driven end-to-end without real crypto.
pub struct MockRecursionStages<A> {
    artifact_client: A,
}

impl<A: ArtifactClient> MockRecursionStages<A> {
    pub fn new(artifact_client: A) -> Self {
        Self { artifact_client }
    }
}

impl<A: ArtifactClient> RecursionStages for MockRecursionStages<A> {
    fn normalize<'a>(
        &'a self,
        common: &'a CommonProverInput,
        _core_proof: ShardProof<SP1GlobalContext, SP1PcsProofInner>,
        _chunk_ctx: &'a ChunkChallengeCtx,
        out: Artifact,
    ) -> BoxFuture<'a, Result<StageProof, TaskError>> {
        Box::pin(async move {
            let proof = create_dummy_recursion_proof(&common.vk);
            self.artifact_client.upload(&out, proof.clone()).await?;
            Ok(proof)
        })
    }

    fn within_chunk_reduce<'a>(
        &'a self,
        children: Vec<StageProof>,
        _is_chunk_complete: bool,
        out: Artifact,
    ) -> BoxFuture<'a, Result<StageProof, TaskError>> {
        Box::pin(async move {
            let first = children.into_iter().next().expect("reduce needs >= 1 child");
            self.artifact_client.upload(&out, first.clone()).await?;
            Ok(first)
        })
    }
}
