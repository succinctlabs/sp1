/// A structure that stores a single bit for each address.
///
/// In practice, this helps us track touched addresses and external status.
///
/// Note that the default value is falsy.
pub struct CompressedMemory {
    index: Vec<u32>,
    bits: Vec<Page>,
}

#[allow(clippy::new_without_default)]
impl CompressedMemory {
    /// The address space is 40 bits, and we store a single bit for each 8 bye aligned address.
    const LOG_MAX_ADDR: usize = 40;
    /// The alignment of the address space.
    const ALIGNMENT: usize = 8;
    /// The number of pages in the address space.
    const MAX_NUM_PAGES: usize = (1 << Self::LOG_MAX_ADDR) / Self::ALIGNMENT / Self::PAGE_SIZE;
    /// The size size of a page in terms of address representatives.
    const PAGE_SIZE: usize = 1 << 18;

    /// Create a new compressed memory, preallocating all the index slots.
    #[must_use]
    pub fn new() -> Self {
        Self { index: vec![u32::MAX; Self::MAX_NUM_PAGES], bits: Vec::new() }
    }

    /// Set/clear the bit at `addr`. Returns the previous bit value.
    #[inline]
    pub fn insert(&mut self, addr: u64, value: bool) -> bool {
        let (upper, lower) = Self::indices(addr);
        debug_assert!(upper < Self::MAX_NUM_PAGES, "address exceeds 40-bit range");

        let page_id = match self.index[upper] {
            u32::MAX => {
                let id = self.bits.len() as u32;
                self.bits.push(Page::new());
                self.index[upper] = id;
                id
            }
            id => id,
        };

        self.bits[page_id as usize].set(lower, value)
    }

    /// Read the bit at `addr`.
    #[inline]
    #[must_use]
    pub fn get(&self, addr: u64) -> bool {
        let (upper, lower) = Self::indices(addr);
        if upper >= self.index.len() {
            return false;
        }
        match self.index[upper] {
            u32::MAX => false,
            id => self.bits[id as usize].get(lower),
        }
    }

    #[inline]
    fn indices(addr: u64) -> (usize, usize) {
        // Compress by ALIGNMENT (8 bytes): one bit per aligned address.
        let compressed = (addr / Self::ALIGNMENT as u64) as usize;
        let upper = compressed / Self::PAGE_SIZE; // page number
        let lower = compressed % Self::PAGE_SIZE; // offset within page
        (upper, lower)
    }

    /// Return all concrete byte addresses whose bit is set (ascending).
    #[must_use]
    pub fn is_set(&self) -> Vec<u64> {
        let mut out = Vec::new();
        for (upper, &pid) in self.index.iter().enumerate() {
            if pid == u32::MAX {
                continue;
            }
            let base = upper * Self::PAGE_SIZE; // base compressed index for this page
            for lower in self.bits[pid as usize].iter_set_indices() {
                let compressed = base + lower;
                out.push((compressed as u64) * Self::ALIGNMENT as u64);
            }
        }
        out
    }
}

/// A structure that stores a single bit for each page index.
///
/// Similar to `CompressedMemory`, but for tracking touched page indices (2^12 byte pages).
///
/// Note that the default value is falsy.
pub struct CompressedPages {
    index: Vec<u32>,
    bits: Vec<PageBits>,
}

#[allow(clippy::new_without_default)]
impl CompressedPages {
    /// The address space is 40 bits, and pages are 2^12 bytes.
    const LOG_MAX_ADDR: usize = 40;
    /// Each page is 2^12 = 4096 bytes.
    const LOG_PAGE_SIZE: usize = 12;
    /// The number of bitset pages in the index.
    const MAX_NUM_BITSET_PAGES: usize =
        (1 << (Self::LOG_MAX_ADDR - Self::LOG_PAGE_SIZE)) / Self::BITSET_PAGE_SIZE;
    /// The size of a bitset page in terms of page index representatives.
    const BITSET_PAGE_SIZE: usize = 1 << 14;

    /// Create a new compressed pages tracker, preallocating all the index slots.
    #[must_use]
    pub fn new() -> Self {
        Self { index: vec![u32::MAX; Self::MAX_NUM_BITSET_PAGES], bits: Vec::new() }
    }

    /// Set/clear the bit at `page_idx`. Returns the previous bit value.
    #[inline]
    pub fn insert(&mut self, page_idx: u64, value: bool) -> bool {
        let (upper, lower) = Self::indices(page_idx);
        debug_assert!(upper < Self::MAX_NUM_BITSET_PAGES, "page index exceeds 28-bit range");

        let bitset_page_id = match self.index[upper] {
            u32::MAX => {
                let id = self.bits.len() as u32;
                self.bits.push(PageBits::new());
                self.index[upper] = id;
                id
            }
            id => id,
        };

        self.bits[bitset_page_id as usize].set(lower, value)
    }

    /// Read the bit at `page_idx`.
    #[inline]
    #[must_use]
    pub fn get(&self, page_idx: u64) -> bool {
        let (upper, lower) = Self::indices(page_idx);
        if upper >= self.index.len() {
            return false;
        }
        match self.index[upper] {
            u32::MAX => false,
            id => self.bits[id as usize].get(lower),
        }
    }

    #[inline]
    fn indices(page_idx: u64) -> (usize, usize) {
        let idx = page_idx as usize;
        let upper = idx / Self::BITSET_PAGE_SIZE; // bitset page number
        let lower = idx % Self::BITSET_PAGE_SIZE; // offset within bitset page
        (upper, lower)
    }

    /// Return all page indices whose bit is set (ascending).
    #[must_use]
    pub fn is_set(&self) -> Vec<u64> {
        let mut out = Vec::new();
        for (upper, &pid) in self.index.iter().enumerate() {
            if pid == u32::MAX {
                continue;
            }
            let base = upper * Self::BITSET_PAGE_SIZE;
            for lower in self.bits[pid as usize].iter_set_indices() {
                out.push((base + lower) as u64);
            }
        }
        out
    }
}

/// A bitset page for `CompressedPages`.
struct PageBits {
    bits: Vec<u64>,
}

impl PageBits {
    fn new() -> Self {
        Self { bits: vec![0; CompressedPages::BITSET_PAGE_SIZE / 64] }
    }

    #[inline]
    fn word_mask(idx: usize) -> (usize, u64) {
        let w = idx >> 6;
        let m = 1u64 << (idx & 63);
        (w, m)
    }

    #[inline]
    fn set(&mut self, idx: usize, value: bool) -> bool {
        let (w, m) = Self::word_mask(idx);
        let prev = (self.bits[w] & m) != 0;
        if value {
            self.bits[w] |= m;
        } else {
            self.bits[w] &= !m;
        }
        prev
    }

    #[inline]
    fn get(&self, idx: usize) -> bool {
        let (w, m) = Self::word_mask(idx);
        (self.bits[w] & m) != 0
    }

    #[inline]
    fn iter_set_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.bits.iter().enumerate().flat_map(|(w_i, &word0)| {
            let mut word = word0;
            std::iter::from_fn(move || {
                if word == 0 {
                    return None;
                }
                let tz = word.trailing_zeros() as usize;
                let idx = (w_i << 6) | tz;
                word &= word - 1;
                Some(idx)
            })
        })
    }
}

/// A page of memory.
pub struct Page {
    bits: Vec<u64>,
}

impl Page {
    pub fn new() -> Self {
        Self { bits: vec![0; CompressedMemory::PAGE_SIZE / 64] }
    }

    #[inline]
    fn word_mask(idx: usize) -> (usize, u64) {
        let w = idx >> 6;
        let m = 1u64 << (idx & 63);
        (w, m)
    }

    /// Set/clear and return previous bit.
    #[inline]
    fn set(&mut self, idx: usize, value: bool) -> bool {
        let (w, m) = Self::word_mask(idx);
        let prev = (self.bits[w] & m) != 0;
        if value {
            self.bits[w] |= m;
        } else {
            self.bits[w] &= !m;
        }
        prev
    }

    #[inline]
    fn get(&self, idx: usize) -> bool {
        let (w, m) = Self::word_mask(idx);
        (self.bits[w] & m) != 0
    }

    /// Iterate local indices whose bit is set.
    #[inline]
    fn iter_set_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.bits.iter().enumerate().flat_map(|(w_i, &word0)| {
            let mut word = word0;
            std::iter::from_fn(move || {
                if word == 0 {
                    return None;
                }
                let tz = word.trailing_zeros() as usize;
                let idx = (w_i << 6) | tz;
                word &= word - 1; // clear lowest set bit
                Some(idx)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn align_down(x: u64) -> u64 {
        x & !((CompressedMemory::ALIGNMENT as u64) - 1)
    }

    #[test]
    fn new_is_empty_and_false() {
        let m = CompressedMemory::new();
        assert!(!m.get(0));
        assert!(!m.get(8));
        assert!(!m.get(123456));
    }

    #[test]
    fn basic_set_get_and_prev() {
        let mut m = CompressedMemory::new();

        // Initially false
        assert!(!m.get(0));

        // First set -> prev=false, now true
        assert!(!m.insert(0, true));
        assert!(m.get(0));

        // Setting true again -> prev=true
        assert!(m.insert(0, true));
        assert!(m.get(0));

        // Clearing -> prev=true, now false
        assert!(m.insert(0, false));
        assert!(!m.get(0));
    }

    #[test]
    fn unaligned_addresses_alias_same_bit() {
        let mut m = CompressedMemory::new();

        // Choose an unaligned address; it should alias the same 8-byte slot.
        let a = 9u64; // maps to compressed index 1
        let aligned = align_down(a);

        assert_eq!(aligned, 8);

        // Set via unaligned and confirm aliases read as true
        m.insert(a, true);
        assert!(m.get(aligned));
        assert!(m.get(a));
        assert!(m.get(aligned + (CompressedMemory::ALIGNMENT as u64) - 1));

        // Next aligned slot should remain false
        assert!(!m.get(aligned + CompressedMemory::ALIGNMENT as u64));
    }

    #[test]
    fn across_page_boundary() {
        let mut m = CompressedMemory::new();

        // First index of page 0 and first index of page 1.
        let a0 = 0u64;
        let a1 = (CompressedMemory::PAGE_SIZE as u64) * (CompressedMemory::ALIGNMENT as u64);

        m.insert(a0, true);
        m.insert(a1, true);

        assert!(m.get(a0));
        assert!(m.get(a1));
    }

    #[test]
    fn high_address_within_40_bits() {
        let mut m = CompressedMemory::new();

        // Max representable byte address in 40-bit space.
        let max_addr = ((1u128 << CompressedMemory::LOG_MAX_ADDR) - 1) as u64;
        let max_aligned = align_down(max_addr);

        // Sanity: compressed index should be last slot (upper = MAX_NUM_PAGES-1)
        let compressed = (max_aligned / CompressedMemory::ALIGNMENT as u64) as usize;
        let upper = compressed / CompressedMemory::PAGE_SIZE;
        let lower = compressed % CompressedMemory::PAGE_SIZE;

        assert_eq!(upper, CompressedMemory::MAX_NUM_PAGES - 1);
        assert_eq!(lower, CompressedMemory::PAGE_SIZE - 1);

        // Set and read back
        assert!(!m.insert(max_aligned, true));
        assert!(m.get(max_aligned));

        // Neighboring (next) address would overflow; previous aligned slot remains false.
        if max_aligned >= CompressedMemory::ALIGNMENT as u64 {
            assert!(!m.get(max_aligned - CompressedMemory::ALIGNMENT as u64));
        }

        // is_set contains exactly this address
        assert_eq!(m.is_set(), vec![max_aligned]);
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn many_out_of_order_is_set_is_sorted() {
        let mut m = CompressedMemory::new();

        // Choose a spread of addresses across pages and within a page.
        let a = 0u64;
        let b = (CompressedMemory::PAGE_SIZE as u64 / 2) * (CompressedMemory::ALIGNMENT as u64);
        let c = (CompressedMemory::PAGE_SIZE as u64) * (CompressedMemory::ALIGNMENT as u64); // next page start
        let d = c + 24; // same page as c, unaligned (aliases c+16..c+23 group)

        // Insert in scrambled order
        m.insert(c, true);
        m.insert(a, true);
        m.insert(d, true); // same compressed slot as align_down(d, 8)
        m.insert(b, true);

        // Expected set of aligned addresses
        let expected = {
            let mut v = vec![align_down(a), align_down(b), align_down(c), align_down(d)];
            v.sort_unstable();
            v.dedup();
            v
        };

        let mut got = m.is_set();
        // is_set should already be ascending; sort to be safe in case impl changes
        got.sort_unstable();
        assert_eq!(got, expected);
    }
}
