//! The merkle proving capability of a core prover.

use std::{future::Future, sync::Arc};

use serde::{Deserialize, Serialize};
use slop_algebra::AbstractField;
use slop_merkle_tree::batch_update::{batch_update, Digest, Update};
use slop_symmetric::CryptographicHasher;
use sp1_core_executor::{ExecutionRecord, MerkleProofRecord, MerkleProvingPayload, Program};
use sp1_hypercube::{
    air::PROOF_NONCE_NUM_WORDS,
    prover::{CpuShardProver, ProverSemaphore, SP1InnerPcsProver},
    SP1Pcs,
};
use sp1_jit::MERKLE_PAGE_WORDS;
use sp1_primitives::{SP1Field, SP1GlobalContext, POSEIDON2_HASHER};

use crate::riscv::RiscvAir;

/// Width of a Poseidon2 leaf digest, in KoalaBear field elements.
pub const DIGEST_WIDTH: usize = 8;

/// Number of KoalaBear field elements one page expands into (3 `u64` to 8 elements).
pub const PAGE_ELEMENTS: usize = 688;
const _: () = assert!(PAGE_ELEMENTS == MERKLE_PAGE_WORDS.div_ceil(3) * 8);

/// A merkle leaf hash: an 8-element KoalaBear Poseidon2 digest.
pub type LeafDigest = [SP1Field; DIGEST_WIDTH];

/// Height of the sparse memory Merkle tree: `2^29` leaf slots (40-bit address space ÷ 2 KB pages).
pub const MERKLE_TREE_HEIGHT: usize = 29;

/// Leaf hash for a page that has never been touched.
#[inline]
pub fn zero_leaf() -> LeafDigest {
    *ZERO_LEAF
}

static ZERO_LEAF: std::sync::LazyLock<LeafDigest> =
    std::sync::LazyLock::new(|| hash_page(&[0u64; MERKLE_PAGE_WORDS]));

/// Hash a single page into a Poseidon2 leaf digest, bit-packing 3 `u64` into 8 KoalaBear
/// elements (`(u16 lane of e1 / e2) << 8 | byte of e3`).
#[inline]
pub fn hash_page(page: &[u64; MERKLE_PAGE_WORDS]) -> LeafDigest {
    let elements = page.chunks(3).flat_map(|chunk| {
        let e1 = chunk[0];
        let e2 = chunk.get(1).copied().unwrap_or(0);
        let e3 = chunk.get(2).copied().unwrap_or(0);
        let e3_bytes = e3.to_le_bytes();
        (0..8).map(move |j| {
            let lane =
                if j < 4 { (e1 >> (16 * j)) & 0xFFFF } else { (e2 >> (16 * (j - 4))) & 0xFFFF };
            SP1Field::from_canonical_u32(((lane as u32) << 8) | e3_bytes[j] as u32)
        })
    });
    POSEIDON2_HASHER.hash_iter(elements)
}

/// Input to `prepare_merkle_proof` for one chunk's merkle-proving body.
#[derive(Serialize, Deserialize)]
pub struct MerkleProvingInput {
    pub chunk_idx: u64,
    /// The prev tree's non-default leaves (sorted by index) going into this chunk.
    pub pre_chunk_snapshot: Arc<Vec<(u32, LeafDigest)>>,
    /// Leaf hashes for the chunk's dirty pages before this chunk (parallel to `payload.page_ids`).
    pub prev_leaves: Arc<Vec<LeafDigest>>,
    /// Leaf hashes for the chunk's dirty pages after this chunk (parallel to `payload.page_ids`).
    pub new_leaves: Arc<Vec<LeafDigest>>,
    /// The per-chunk touched-page reconstruction payload.
    pub payload: MerkleProvingPayload,
}

/// Compute the batch Merkle proof for one chunk on the CPU and bundle it with the payload
/// into a [`MerkleProofRecord`]. This is the CPU prover's `prepare_merkle_proof` body.
pub fn build_merkle_proof_record(input: MerkleProvingInput) -> MerkleProofRecord {
    let default_leaf: Digest = zero_leaf();
    let leaves: Vec<(u64, Digest)> =
        input.pre_chunk_snapshot.iter().map(|&(idx, leaf)| (idx as u64, leaf)).collect();
    let mut updates: Vec<Update> = input
        .payload
        .page_ids
        .iter()
        .enumerate()
        .map(|(i, &page_id)| Update {
            idx: page_id as u64,
            prev_leaf: input.prev_leaves[i],
            new_leaf: input.new_leaves[i],
        })
        .collect();
    // `page_ids` are in dirty-page emission order; the batch update needs them sorted.
    updates.sort_unstable_by_key(|u| u.idx);

    let proof = batch_update(default_leaf, &leaves, &updates, MERKLE_TREE_HEIGHT).to_merkle_proof();
    let prev_leaves = input.prev_leaves.to_vec();
    let new_leaves = input.new_leaves.to_vec();
    MerkleProofRecord { payload: input.payload, proof, prev_leaves, new_leaves }
}

/// GPU-friendly batch args derived from a chunk's input.
pub fn merkle_gpu_args(
    input: &MerkleProvingInput,
) -> (Digest, Vec<u32>, Vec<SP1Field>, Vec<Update>) {
    let default_leaf: Digest = zero_leaf();
    let leaf_idx: Vec<u32> = input.pre_chunk_snapshot.iter().map(|&(i, _)| i).collect();
    let leaf_val: Vec<SP1Field> = input.pre_chunk_snapshot.iter().flat_map(|&(_, l)| l).collect();
    let mut updates: Vec<Update> = input
        .payload
        .page_ids
        .iter()
        .enumerate()
        .map(|(i, &page_id)| Update {
            idx: page_id as u64,
            prev_leaf: input.prev_leaves[i],
            new_leaf: input.new_leaves[i],
        })
        .collect();
    updates.sort_unstable_by_key(|u| u.idx);
    (default_leaf, leaf_idx, leaf_val, updates)
}

/// The merkle proving capability of a core prover.
pub trait BatchMerkleProver: 'static + Send + Sync {
    /// Prepare the batch Merkle proof for a chunk's memory updates, returning an
    /// [`ExecutionRecord`] carrying the [`MerkleProofRecord`].
    fn prepare_merkle_proof(
        &self,
        input: MerkleProvingInput,
        program: Arc<Program>,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
        global_dependencies_opt: bool,
        permits: ProverSemaphore,
    ) -> impl Future<Output = ExecutionRecord> + Send {
        async move {
            let _permit = permits.acquire().await;
            let record = tokio::task::spawn_blocking(move || build_merkle_proof_record(input))
                .await
                .expect("merkle proof preparation panicked");
            ExecutionRecord::from_merkle_proof_record(
                program,
                proof_nonce,
                global_dependencies_opt,
                record,
            )
        }
    }
}

/// The CPU core prover uses the default `prepare_merkle_proof`.
impl BatchMerkleProver
    for CpuShardProver<
        SP1GlobalContext,
        SP1Pcs<SP1GlobalContext>,
        SP1InnerPcsProver,
        RiscvAir<SP1Field>,
    >
{
}
