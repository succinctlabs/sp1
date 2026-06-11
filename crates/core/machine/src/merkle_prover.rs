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

/// Running merkle leaf state across a program's trace chunks.
pub struct LeafState {
    leaves: std::collections::HashMap<u32, LeafDigest>,
}

impl Default for LeafState {
    fn default() -> Self {
        Self::new()
    }
}

impl LeafState {
    #[must_use]
    pub fn new() -> Self {
        Self { leaves: std::collections::HashMap::new() }
    }

    /// Seed the leaf state from a program's initial `memory_image`.
    #[must_use]
    pub fn from_memory_image(memory_image: &hashbrown::HashMap<u64, u64>) -> Self {
        use rayon::prelude::*;
        const PAGE_BYTES: u64 = (MERKLE_PAGE_WORDS * 8) as u64;
        let mut pages: std::collections::HashMap<u32, Box<[u64; MERKLE_PAGE_WORDS]>> =
            std::collections::HashMap::new();
        for (&addr, &val) in memory_image.iter() {
            debug_assert_eq!(addr % 8, 0, "memory_image address {addr} must be 8-aligned");
            let page_id = (addr / PAGE_BYTES) as u32;
            let word = ((addr % PAGE_BYTES) / 8) as usize;
            pages.entry(page_id).or_insert_with(|| Box::new([0u64; MERKLE_PAGE_WORDS]))[word] = val;
        }
        let leaves: std::collections::HashMap<u32, LeafDigest> =
            pages.into_par_iter().map(|(page_id, page)| (page_id, hash_page(&page))).collect();
        Self { leaves }
    }

    /// Current leaf for a page, or the zero leaf if untouched.
    #[must_use]
    pub fn get_leaf(&self, page_id: u32) -> LeafDigest {
        self.leaves.get(&page_id).copied().unwrap_or_else(zero_leaf)
    }

    /// Number of distinct pages touched at least once across all ingested chunks.
    #[must_use]
    pub fn touched_pages(&self) -> usize {
        self.leaves.len()
    }

    /// Snapshot the current non-trivial leaves as an `Arc<Vec<(page_id, leaf)>>`.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Vec<(u32, LeafDigest)>> {
        let mut out: Vec<(u32, LeafDigest)> = self.leaves.iter().map(|(&k, &v)| (k, v)).collect();
        out.sort_unstable_by_key(|&(k, _)| k);
        Arc::new(out)
    }

    /// Hash this chunk's dirty pages in parallel and update the leaf state.
    pub fn ingest_chunk(
        &mut self,
        dirty_pages: &[sp1_jit::DirtyPage],
    ) -> (Vec<LeafDigest>, Vec<LeafDigest>) {
        use rayon::prelude::*;
        let new_leaves: Vec<LeafDigest> =
            dirty_pages.par_iter().map(|p| hash_page(&p.final_contents)).collect();

        let mut prev_leaves = Vec::with_capacity(dirty_pages.len());
        for (i, page) in dirty_pages.iter().enumerate() {
            debug_assert!(page.page_id < (1u32 << 29));
            let prev = self.leaves.get(&page.page_id).copied().unwrap_or_else(zero_leaf);
            prev_leaves.push(prev);
            self.leaves.insert(page.page_id, new_leaves[i]);
        }

        (prev_leaves, new_leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_jit::DirtyPage;
    use std::collections::HashMap;

    /// Build a deterministic-but-seeded page for tests.
    fn make_page(seed: u64) -> [u64; MERKLE_PAGE_WORDS] {
        let mut page = [0u64; MERKLE_PAGE_WORDS];
        for (i, slot) in page.iter_mut().enumerate() {
            *slot = seed.wrapping_mul(2_654_435_761).wrapping_add(i as u64 * 7919);
        }
        page
    }

    /// Bundle a (page_id, contents) pair into a `DirtyPage` for tests.
    fn dp(page_id: u32, final_contents: [u64; MERKLE_PAGE_WORDS]) -> DirtyPage {
        DirtyPage { page_id, final_contents }
    }

    #[test]
    fn hash_page_is_deterministic() {
        let page = make_page(42);
        assert_eq!(hash_page(&page), hash_page(&page));
    }

    #[test]
    fn hash_page_differs_with_different_inputs() {
        assert_ne!(hash_page(&make_page(1)), hash_page(&make_page(2)));
    }

    #[test]
    fn hash_page_packs_every_bit() {
        let mut a = [0u64; MERKLE_PAGE_WORDS];
        let mut b = [0u64; MERKLE_PAGE_WORDS];
        a[0] = 1;
        b[0] = 1 << 63;
        assert_ne!(hash_page(&a), hash_page(&b));
    }

    #[test]
    fn empty_state_returns_zero_prev_for_fresh_pages() {
        let mut state = LeafState::new();
        let page = make_page(7);
        let (prev, new) = state.ingest_chunk(&[dp(42, page)]);
        assert_eq!(prev, vec![zero_leaf()]);
        assert_eq!(new, vec![hash_page(&page)]);
        assert_eq!(state.get_leaf(42), hash_page(&page));
        assert_eq!(state.get_leaf(43), zero_leaf());
    }

    #[test]
    fn second_chunk_sees_first_chunks_leaves() {
        let mut state = LeafState::new();
        let p7_v1 = make_page(7);
        let p9 = make_page(9);
        let p7_v2 = make_page(70);
        let p11 = make_page(11);

        // Chunk 1: writes pages 7 and 9.
        let (prev1, new1) = state.ingest_chunk(&[dp(7, p7_v1), dp(9, p9)]);
        assert_eq!(prev1, vec![zero_leaf(); 2]);
        assert_eq!(new1, vec![hash_page(&p7_v1), hash_page(&p9)]);

        // Chunk 2: re-writes page 7 with new contents, writes page 11 fresh.
        let (prev2, new2) = state.ingest_chunk(&[dp(7, p7_v2), dp(11, p11)]);
        assert_eq!(prev2[0], hash_page(&p7_v1), "page 7 prev should be chunk 1's new");
        assert_eq!(prev2[1], zero_leaf(), "page 11 prev should be zero (untouched)");
        assert_eq!(new2, vec![hash_page(&p7_v2), hash_page(&p11)]);

        assert_eq!(state.get_leaf(7), hash_page(&p7_v2));
        assert_eq!(state.get_leaf(9), hash_page(&p9));
        assert_eq!(state.get_leaf(11), hash_page(&p11));
        assert_eq!(state.touched_pages(), 3);
    }

    #[test]
    fn final_state_matches_independent_recompute() {
        let chunks: Vec<Vec<DirtyPage>> = vec![
            vec![dp(0, make_page(0)), dp(1, make_page(1)), dp(2, make_page(2))],
            vec![dp(1, make_page(10)), dp(3, make_page(3))],
            vec![dp(0, make_page(20)), dp(2, make_page(22)), dp(4, make_page(4))],
            vec![dp(1, make_page(100))],
            vec![dp(5, make_page(5)), dp(0, make_page(200))],
        ];

        let mut state = LeafState::new();
        for chunk in &chunks {
            state.ingest_chunk(chunk);
        }

        let mut last_contents: HashMap<u32, [u64; MERKLE_PAGE_WORDS]> = HashMap::new();
        for chunk in &chunks {
            for page in chunk {
                last_contents.insert(page.page_id, page.final_contents);
            }
        }

        assert_eq!(state.touched_pages(), last_contents.len());
        for (pid, contents) in &last_contents {
            assert_eq!(
                state.get_leaf(*pid),
                hash_page(contents),
                "leaf for page {pid} mismatches recompute",
            );
        }
    }

    /// Perf microbench, ignored by default. Run with:
    ///   cargo test --release -p sp1-core-machine --lib merkle_prover -- \
    ///       --ignored --nocapture bench_ingest_chunk
    #[test]
    #[ignore]
    #[allow(clippy::print_stdout)]
    fn bench_ingest_chunk() {
        let sizes = [1_000usize, 5_000, 7_000, 11_000, 22_000];
        println!();
        println!("{:>10}  {:>10}  {:>10}", "pages", "elapsed", "ns/page");
        for &n in &sizes {
            // Run a few warm-up iterations first so the rayon pool is hot.
            for warm in 0..2 {
                let mut state = LeafState::new();
                let pages: Vec<DirtyPage> =
                    (0..n).map(|i| dp(i as u32, make_page((warm * n + i) as u64))).collect();
                let _ = state.ingest_chunk(&pages);
            }

            let mut state = LeafState::new();
            let pages: Vec<DirtyPage> = (0..n).map(|i| dp(i as u32, make_page(i as u64))).collect();
            let start = std::time::Instant::now();
            let _ = state.ingest_chunk(&pages);
            let elapsed = start.elapsed();
            let ns_per_page = elapsed.as_nanos() as f64 / n as f64;
            println!("{:>10}  {:>10.2?}  {:>10.0}", n, elapsed, ns_per_page);
        }
        println!();
    }

    #[test]
    fn intra_chunk_same_page_id_takes_last() {
        let mut state = LeafState::new();
        let p_v1 = make_page(1);
        let p_v2 = make_page(2);
        let (prev, new) = state.ingest_chunk(&[dp(5, p_v1), dp(5, p_v2)]);

        assert_eq!(prev[0], zero_leaf());
        assert_eq!(prev[1], hash_page(&p_v1));
        assert_eq!(new, vec![hash_page(&p_v1), hash_page(&p_v2)]);
        assert_eq!(state.get_leaf(5), hash_page(&p_v2));
    }

    #[test]
    fn from_empty_memory_image_is_all_zero() {
        let state = LeafState::from_memory_image(&hashbrown::HashMap::new());
        assert_eq!(state.touched_pages(), 0);
        assert_eq!(state.get_leaf(0), zero_leaf());
        assert_eq!(state.get_leaf(12345), zero_leaf());
    }

    #[test]
    fn from_memory_image_matches_executor_page_layout() {
        const PAGE_BYTES: u64 = (MERKLE_PAGE_WORDS * 8) as u64;
        let entries: Vec<(u64, u64)> = vec![
            (0, 0xdead_beef),
            (8, 0x0102_0304),
            (PAGE_BYTES - 8, 0x1111_2222),       // page 0, last word
            (PAGE_BYTES, 0x3333_4444),           // page 1, word 0
            (PAGE_BYTES + 8 * 100, 0x5555_6666), // page 1, word 100
            (PAGE_BYTES * 5 + 8 * 7, 0x7777),    // page 5, word 7
        ];
        let image: hashbrown::HashMap<u64, u64> = entries.iter().copied().collect();

        let state = LeafState::from_memory_image(&image);

        let mut pages: HashMap<u32, [u64; MERKLE_PAGE_WORDS]> = HashMap::new();
        for &(addr, val) in &entries {
            assert_eq!(addr % 8, 0);
            let widx = addr / 8;
            let pid = (widx / MERKLE_PAGE_WORDS as u64) as u32;
            let w = (widx % MERKLE_PAGE_WORDS as u64) as usize;
            pages.entry(pid).or_insert([0u64; MERKLE_PAGE_WORDS])[w] = val;
        }

        assert_eq!(state.touched_pages(), pages.len());
        for (&pid, page) in &pages {
            assert_eq!(state.get_leaf(pid), hash_page(page), "leaf mismatch on page {pid}");
        }
        // Untouched pages stay zero.
        assert_eq!(state.get_leaf(2), zero_leaf());
        assert_eq!(state.get_leaf(42), zero_leaf());
    }

    #[test]
    fn from_memory_image_all_zero_words_equal_zero_leaf() {
        let image: hashbrown::HashMap<u64, u64> = [(0u64, 0u64), (8, 0)].into_iter().collect();
        let state = LeafState::from_memory_image(&image);
        assert_eq!(state.get_leaf(0), zero_leaf());
    }
}
