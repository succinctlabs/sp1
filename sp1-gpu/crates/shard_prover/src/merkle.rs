//! GPU implementation of the core prover's merkle proving capability.

use std::{future::Future, sync::Arc};

use sp1_core_executor::{ExecutionRecord, MerkleProofRecord, Program};
use sp1_core_machine::merkle_prover::{
    merkle_gpu_args, BatchMerkleProver, MerkleProvingInput, MERKLE_TREE_HEIGHT,
};
use sp1_gpu_merkle_tree::gpu_batch_update;
use sp1_hypercube::{air::PROOF_NONCE_NUM_WORDS, prover::ProverSemaphore};
use sp1_primitives::SP1GlobalContext;

use crate::{CudaShardProver, CudaShardProverComponents};

impl<PC> BatchMerkleProver for CudaShardProver<SP1GlobalContext, PC>
where
    PC: CudaShardProverComponents<SP1GlobalContext>,
{
    fn prepare_merkle_proof(
        &self,
        input: MerkleProvingInput,
        program: Arc<Program>,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        global_dependencies_opt: bool,
        permits: ProverSemaphore,
    ) -> impl Future<Output = ExecutionRecord> + Send {
        let scope = self.scope().clone();
        async move {
            let _permit = permits.acquire().await;
            let record = tokio::task::spawn_blocking(move || {
                let (default_leaf, leaf_idx, leaf_val, updates) = merkle_gpu_args(&input);
                let (proof, _timings) = gpu_batch_update(
                    &scope,
                    default_leaf,
                    &leaf_idx,
                    &leaf_val,
                    &updates,
                    MERKLE_TREE_HEIGHT,
                );
                MerkleProofRecord { payload: input.payload, proof }
            })
            .await
            .expect("gpu merkle proof preparation panicked");
            ExecutionRecord::from_merkle_proof_record(
                program,
                proof_nonce,
                global_dependencies_opt,
                record,
            )
        }
    }
}
