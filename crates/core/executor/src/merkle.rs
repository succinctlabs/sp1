//! Leaf-hash and initial-memory-root primitives for the sparse memory Merkle tree.
//!
//! Here (not `sp1-core-machine`) so a `Program`'s `initial_memory_root` is computable directly;
//! `sp1-core-machine` re-exports them.

use hashbrown::HashMap;
use slop_algebra::AbstractField;
use slop_maybe_rayon::prelude::{IntoParallelIterator, ParallelIterator};
use slop_merkle_tree::batch_update::{compute_root, Digest};
use slop_symmetric::CryptographicHasher;
use sp1_primitives::{SP1Field, POSEIDON2_HASHER};

use crate::MERKLE_PAGE_WORDS;

/// Width of a `Poseidon2` leaf digest, in `KoalaBear` field elements.
pub const DIGEST_WIDTH: usize = 8;

/// Number of `KoalaBear` field elements one page expands into (3 `u64` to 8 elements).
pub const PAGE_ELEMENTS: usize = 688;
const _: () = assert!(PAGE_ELEMENTS == MERKLE_PAGE_WORDS.div_ceil(3) * 8);

/// A merkle leaf hash: an 8-element `KoalaBear` `Poseidon2` digest.
pub type LeafDigest = [SP1Field; DIGEST_WIDTH];

/// Height of the sparse memory Merkle tree: `2^29` leaf slots (40-bit address space ÷ 2 KB pages).
pub const MERKLE_TREE_HEIGHT: usize = 29;

/// Leaf hash for a page that has never been touched.
#[inline]
#[must_use]
pub fn zero_leaf() -> LeafDigest {
    *ZERO_LEAF
}

static ZERO_LEAF: std::sync::LazyLock<LeafDigest> =
    std::sync::LazyLock::new(|| hash_page(&[0u64; MERKLE_PAGE_WORDS]));

/// Hash a single page into a `Poseidon2` leaf digest, bit-packing 3 `u64` into 8 `KoalaBear`
/// elements (`(u16 lane of e1 / e2) << 8 | byte of e3`).
#[inline]
#[must_use]
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

/// The sorted, distinct `(page_id, leaf_hash)` pairs of a memory image's non-default pages.
#[must_use]
pub fn memory_image_leaves(memory_image: &HashMap<u64, u64>) -> Vec<(u32, LeafDigest)> {
    const PAGE_BYTES: u64 = (MERKLE_PAGE_WORDS * 8) as u64;
    let mut pages: HashMap<u32, Box<[u64; MERKLE_PAGE_WORDS]>> = HashMap::new();
    for (&addr, &val) in memory_image.iter() {
        debug_assert_eq!(addr % 8, 0, "memory_image address {addr} must be 8-aligned");
        let page_id = (addr / PAGE_BYTES) as u32;
        let word = ((addr % PAGE_BYTES) / 8) as usize;
        pages.entry(page_id).or_insert_with(|| Box::new([0u64; MERKLE_PAGE_WORDS]))[word] = val;
    }
    let pages: Vec<(u32, Box<[u64; MERKLE_PAGE_WORDS]>)> = pages.into_iter().collect();
    let mut leaves: Vec<(u32, LeafDigest)> =
        pages.into_par_iter().map(|(page_id, page)| (page_id, hash_page(&page))).collect();
    leaves.sort_unstable_by_key(|&(page_id, _)| page_id);
    leaves
}

/// Merkle root of a program's initial memory image (the first chunk's `prev_merkle_root`).
#[must_use]
pub fn memory_image_root(memory_image: &HashMap<u64, u64>) -> LeafDigest {
    let leaves: Vec<(u64, Digest)> =
        memory_image_leaves(memory_image).into_iter().map(|(id, leaf)| (id as u64, leaf)).collect();
    compute_root(zero_leaf(), &leaves, MERKLE_TREE_HEIGHT)
}
