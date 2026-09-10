use slop_alloc::{Backend, Buffer, HasBackend};

/// A binary Merkle tree.
///
/// Large trees are stored truncated: only levels `0..=stored_height` are kept, and the bottom
/// `height - stored_height` levels are recomputed from the leaf data when opening paths.
#[derive(Debug, Clone)]
pub struct MerkleTree<T, A: Backend> {
    /// The digests of levels `0..=stored_height`.
    ///
    /// The digests are stored so that the root is an index `0`, and for each node `i`, its left
    /// child is at index `2i + 1` and the right child is at index `2i + 2`.
    pub digests: Buffer<T, A>,
    /// The total height of the tree.
    pub height: usize,
    /// The deepest stored level.
    pub stored_height: usize,
}

/// Number of bottom levels dropped from stored trees and recomputed per query.
pub const MERKLE_TRUNCATED_LEVELS: usize = 8;

/// Trees shorter than this are stored in full.
pub const MIN_TRUNCATED_HEIGHT: usize = 15;

impl<T, A: Backend> MerkleTree<T, A> {
    pub fn uninit(height: usize, allocator: A) -> Self {
        Self {
            digests: Buffer::with_capacity_in(Self::digests_len(height), allocator),
            height,
            stored_height: height,
        }
    }

    #[inline]
    const fn digests_len(height: usize) -> usize {
        (1 << (height + 1)) - 1
    }

    /// # Safety
    ///
    /// Todo
    pub unsafe fn assume_init(&mut self) {
        self.digests.set_len(Self::digests_len(self.stored_height));
    }

    #[inline]
    pub fn height(&self) -> usize {
        self.height
    }

    /// Number of bottom levels not stored.
    #[inline]
    pub fn truncated_levels(&self) -> usize {
        self.height - self.stored_height
    }

    #[inline]
    pub fn digests(&self) -> &Buffer<T, A> {
        &self.digests
    }
}

impl<T, A: Backend> HasBackend for MerkleTree<T, A> {
    type Backend = A;

    #[inline]
    fn backend(&self) -> &Self::Backend {
        self.digests.backend()
    }
}
