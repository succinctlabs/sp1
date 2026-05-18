use std::collections::HashMap;
use std::sync::Arc;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use slop_algebra::AbstractField;
use slop_symmetric::CryptographicHasher;
use sp1_core_executor::MerkleProvingPayload;
use sp1_jit::{DirtyPage, MERKLE_PAGE_WORDS};
use sp1_primitives::{SP1Field, POSEIDON2_HASHER};

/// Width of a Poseidon2 leaf digest, in KoalaBear field elements.
pub const DIGEST_WIDTH: usize = 8;

/// Number of KoalaBear field elements one 2 KB page expands into.
pub const PAGE_ELEMENTS: usize = MERKLE_PAGE_WORDS * 3;

/// A merkle leaf hash: an 8-element KoalaBear Poseidon2 digest.
pub type LeafDigest = [SP1Field; DIGEST_WIDTH];

/// Leaf hash for a page that has never been touched.
#[inline]
pub fn zero_leaf() -> LeafDigest {
    *ZERO_LEAF
}

static ZERO_LEAF: std::sync::LazyLock<LeafDigest> =
    std::sync::LazyLock::new(|| hash_page(&[0u64; MERKLE_PAGE_WORDS]));

/// Controller-side running merkle leaf state.
pub struct LeafState {
    leaves: HashMap<u32, LeafDigest>,
}

impl Default for LeafState {
    fn default() -> Self {
        Self::new()
    }
}

impl LeafState {
    pub fn new() -> Self {
        Self { leaves: HashMap::new() }
    }

    /// Current leaf for a page, or the zero leaf if untouched.
    pub fn get_leaf(&self, page_id: u32) -> LeafDigest {
        self.leaves.get(&page_id).copied().unwrap_or_else(zero_leaf)
    }

    /// Number of distinct pages touched at least once across all ingested chunks.
    pub fn touched_pages(&self) -> usize {
        self.leaves.len()
    }

    /// Snapshot the current non-trivial leaves as an `Arc<Vec<(page_id, leaf)>>`.
    pub fn snapshot(&self) -> Arc<Vec<(u32, LeafDigest)>> {
        let mut out: Vec<(u32, LeafDigest)> = self.leaves.iter().map(|(&k, &v)| (k, v)).collect();
        out.sort_unstable_by_key(|&(k, _)| k);
        Arc::new(out)
    }

    /// Hash this chunk's dirty pages in parallel and update the leaf state.
    pub fn ingest_chunk(
        &mut self,
        dirty_pages: &[DirtyPage],
    ) -> (Vec<LeafDigest>, Vec<LeafDigest>) {
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

/// Hash a single page (`[u64; 256]`) into a Poseidon2 leaf digest.
#[inline]
fn hash_page(page: &[u64; MERKLE_PAGE_WORDS]) -> LeafDigest {
    let elements: Vec<SP1Field> = page
        .iter()
        .flat_map(|&word| {
            let lo = (word & 0x00FF_FFFF) as u32;
            let mid = ((word >> 24) & 0x00FF_FFFF) as u32;
            let hi = ((word >> 48) & 0x0000_FFFF) as u32;
            [
                SP1Field::from_canonical_u32(lo),
                SP1Field::from_canonical_u32(mid),
                SP1Field::from_canonical_u32(hi),
            ]
        })
        .collect();
    debug_assert_eq!(elements.len(), PAGE_ELEMENTS);
    POSEIDON2_HASHER.hash_iter(elements)
}

/// Input to `prepare_merkle_proof` for one chunk's merkle-proving body.
#[derive(Serialize, Deserialize)]
pub struct MerkleProvingInput {
    pub chunk_idx: u64,
    pub pre_chunk_snapshot: Arc<Vec<(u32, LeafDigest)>>,
    pub prev_leaves: Arc<Vec<LeafDigest>>,
    pub new_leaves: Arc<Vec<LeafDigest>>,
    pub payload: MerkleProvingPayload,
}

#[cfg(test)]
mod tests {
    use super::*;

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
    ///   cargo test --release -p sp1-prover --lib worker::controller::leaves -- \
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
}
