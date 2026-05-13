//! Per-chunk dirty page tracking for merkle-memory proving.
//!
//! For each trace chunk, the `MinimalExecutor` must emit:
//! - the list of touched pages (page_id),
//! - the contents of each touched page at the end of the chunk.
//!
//! The initial contents of the pages are reconstructed by the `SplicingVM`.
//!
//! The JIT emits an inline probe into every load/store that indexes a dense bitset by
//! `page_id`. On the first touch in a chunk, the probe sets the bit and inline-pushes `page_id` to
//! a fixed-capacity list. At chunk boundary, `emit_dirty_pages` walks the list, reads each page's
//! current contents from JIT memory, and returns the set and the contents.

/// Page size in 8-byte words. One merkle leaf hashes `MERKLE_PAGE_WORDS` memory values.
pub const MERKLE_PAGE_WORDS: usize = 256;

/// Right-shift to derive `page_id` from the memory address in bytes.
pub const MERKLE_PAGE_SHIFT: u32 = 3 + (MERKLE_PAGE_WORDS.trailing_zeros());

/// Number of 64-bit words in the dirty-page bitset.
pub const DIRTY_BITSET_WORDS: usize =
    1 << (sp1_primitives::consts::MAX_JIT_LOG_ADDR - MERKLE_PAGE_SHIFT as usize - 6);

/// Preallocated capacity of `DirtyPageTracker::list`.
///
/// Hard cap: the backing buffer size, never exceeded by construction.
pub const DIRTY_LIST_CAPACITY: usize = 1 << 17;

/// Soft cap on `dirty_page_list_len`: when reached, the JIT cold path ends
/// the current chunk. Must be `< DIRTY_LIST_CAPACITY` with enough margin.
pub const DIRTY_LIST_SOFT_CAP: usize = 100_000;

/// A touched page's state at the end of the chunk.
#[derive(Clone, Debug)]
pub struct DirtyPage {
    /// The index of the page.
    pub page_id: u32,
    /// The contents of the page at the end of the chunk.
    pub final_contents: [u64; MERKLE_PAGE_WORDS],
}

/// All pages dirtied during one chunk, produced by `JitFunction::emit_dirty_pages`.
#[derive(Clone, Debug, Default)]
pub struct DirtyPages {
    pub pages: Vec<DirtyPage>,
}

/// Size of one dirty-page entry on the wire (u32 page_id + 256 u64 words).
pub const DIRTY_PAGE_WIRE_BYTES: usize = 4 + MERKLE_PAGE_WORDS * 8;

/// Bytes needed for the wire payload of `n` dirty pages: the count header
/// plus n entries.
pub const fn dirty_pages_wire_bytes(n: usize) -> usize {
    4 + n * DIRTY_PAGE_WIRE_BYTES
}

impl DirtyPages {
    /// Serialize `self` into the wire format documented above. Returns the
    /// number of bytes written. Panics if `buf` is too small.
    pub fn write_to_wire(&self, buf: &mut [u8]) -> usize {
        let n = self.pages.len();
        let total = dirty_pages_wire_bytes(n);
        assert!(buf.len() >= total, "dirty-pages wire buffer too small");

        buf[0..4].copy_from_slice(&(n as u32).to_le_bytes());
        let mut off = 4;
        for page in &self.pages {
            buf[off..off + 4].copy_from_slice(&page.page_id.to_le_bytes());
            off += 4;
            for word in &page.final_contents {
                buf[off..off + 8].copy_from_slice(&word.to_le_bytes());
                off += 8;
            }
        }
        debug_assert_eq!(off, total);
        off
    }

    /// Deserialize from the wire format. Panics on truncated input.
    pub fn read_from_wire(buf: &[u8]) -> Self {
        assert!(buf.len() >= 4, "dirty-pages wire buffer too small for count header");
        let n = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let total = dirty_pages_wire_bytes(n);
        assert!(buf.len() >= total, "dirty-pages wire buffer truncated");

        let mut pages = Vec::with_capacity(n);
        let mut off = 4;
        for _ in 0..n {
            let page_id = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            off += 4;
            let mut final_contents = [0u64; MERKLE_PAGE_WORDS];
            for word in &mut final_contents {
                *word = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
                off += 8;
            }
            pages.push(DirtyPage { page_id, final_contents });
        }
        Self { pages }
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    #[test]
    fn wire_roundtrip_empty() {
        let pages = DirtyPages::default();
        let mut buf = vec![0u8; dirty_pages_wire_bytes(0)];
        let n = pages.write_to_wire(&mut buf);
        assert_eq!(n, 4);
        let back = DirtyPages::read_from_wire(&buf);
        assert!(back.pages.is_empty());
    }

    #[test]
    fn wire_roundtrip_small() {
        let mut p0 = [0u64; MERKLE_PAGE_WORDS];
        p0[0] = 0xdead_beef_cafe_babe;
        p0[255] = u64::MAX;
        let mut p1 = [0u64; MERKLE_PAGE_WORDS];
        for (i, w) in p1.iter_mut().enumerate() {
            *w = (i as u64).wrapping_mul(0xabcd_1234_5678_9abc);
        }
        let pages = DirtyPages {
            pages: vec![
                DirtyPage { page_id: 7, final_contents: p0 },
                DirtyPage { page_id: 42, final_contents: p1 },
            ],
        };

        let mut buf = vec![0u8; dirty_pages_wire_bytes(2)];
        let n = pages.write_to_wire(&mut buf);
        assert_eq!(n, dirty_pages_wire_bytes(2));

        let back = DirtyPages::read_from_wire(&buf);
        assert_eq!(back.pages.len(), 2);
        assert_eq!(back.pages[0].page_id, 7);
        assert_eq!(back.pages[0].final_contents, p0);
        assert_eq!(back.pages[1].page_id, 42);
        assert_eq!(back.pages[1].final_contents, p1);
    }

    #[test]
    fn wire_sizes() {
        assert_eq!(DIRTY_PAGE_WIRE_BYTES, 4 + 256 * 8);
        assert_eq!(dirty_pages_wire_bytes(0), 4);
        assert_eq!(dirty_pages_wire_bytes(1), 4 + 2052);
        assert_eq!(dirty_pages_wire_bytes(22_000), 4 + 22_000 * 2052);
    }
}

/// Per-chunk dirty-page tracking state, owned by `JitFunction`.
pub struct DirtyPageTracker {
    /// Dense bitset indexed by `page_id` on whether the page has been touched in this chunk.
    /// 2^29 bits (for 40-bit address space, 2 KB pages) = 64 MB.
    pub bitset: Box<[u64]>,
    /// Fixed-size, heap-allocated storage for the per-chunk touched-pages list.
    pub list: Box<[u32]>,
    /// Current length of `list` for this chunk.
    pub list_len: u32,
}

impl DirtyPageTracker {
    /// Create an empty tracker. Bitset zeroed, list length zero.
    pub fn new() -> Self {
        Self {
            bitset: vec![0u64; DIRTY_BITSET_WORDS].into_boxed_slice(),
            list: vec![0u32; DIRTY_LIST_CAPACITY].into_boxed_slice(),
            list_len: 0,
        }
    }

    /// The active portion of the fixed-capacity touched-pages list.
    #[inline]
    pub fn list_slice(&self) -> &[u32] {
        &self.list[..self.list_len as usize]
    }

    /// Clear all per-chunk state. Called after `emit_dirty_pages` at chunk boundary.
    pub fn reset(&mut self) {
        for i in 0..self.list_len as usize {
            let page_id = self.list[i] as usize;
            let qword = page_id / 64;
            self.bitset[qword] = 0;
        }
        self.list_len = 0;
    }
}

impl Default for DirtyPageTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_shift_matches_page_size() {
        assert_eq!(MERKLE_PAGE_SHIFT, (8 * MERKLE_PAGE_WORDS).trailing_zeros());
    }

    #[test]
    fn new_tracker_is_empty() {
        let t = DirtyPageTracker::new();
        assert_eq!(t.list_len, 0);
        assert_eq!(t.list_slice().len(), 0);
        assert!(t.bitset.iter().all(|&w| w == 0));
    }

    #[test]
    fn reset_clears_state() {
        let mut t = DirtyPageTracker::new();
        t.list[0] = 7;
        t.list[1] = 42;
        t.list[2] = 1_000;
        t.list_len = 3;
        t.bitset[7 / 64] |= 1u64 << 7;
        t.bitset[42 / 64] |= 1u64 << 42;
        t.bitset[1_000 / 64] |= 1u64 << (1_000 % 64);

        t.reset();

        assert_eq!(t.list_len, 0);
        assert!(t.bitset.iter().all(|&w| w == 0));
    }

    #[test]
    fn bitset_word_count_matches_40bit_space() {
        assert_eq!(DIRTY_BITSET_WORDS, 1 << 23);
        assert_eq!(DIRTY_BITSET_WORDS * std::mem::size_of::<u64>(), 64 * 1024 * 1024);
        assert_eq!(DIRTY_BITSET_WORDS * std::mem::size_of::<u64>() * 8, 1 << 29);
    }
}
