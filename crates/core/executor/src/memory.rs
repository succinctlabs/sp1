use std::mem::{replace, size_of};

use serde::{Deserialize, Serialize};
use vec_map::VecMap;

/// A page of memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<V>(VecMap<V>);

impl<V> Page<V> {
    /// Create a `Page` with capacity `PAGE_LEN`.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(VecMap::with_capacity(capacity))
    }
}

impl<V> Default for Page<V> {
    fn default() -> Self {
        Self(VecMap::default())
    }
}

/// Paged memory. Balances both memory locality and total memory usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagedMemory<V> {
    /// The internal page table.
    pub page_table: VecMap<Page<V>>,
}

impl<V> PagedMemory<V> {
    /// The base 2 logarithm of the (maximum) page size in bytes.
    const LOG_PAGE_SIZE: usize = 12;
    /// The base 2 logarithm of the length of each page, considered as an array of `Option<V>`.
    const LOG_PAGE_LEN: usize =
        Self::LOG_PAGE_SIZE - size_of::<Option<V>>().next_power_of_two().ilog2() as usize;
    /// The length of each page, considered as an array of `Option<V>`.
    const PAGE_LEN: usize = 1 << Self::LOG_PAGE_LEN;
    /// The mask for retrieving the lowest bits necessary to index within a page.
    const PAGE_MASK: usize = Self::PAGE_LEN - 1;
    /// The maximum number of pages. Used for the length of the page table.
    const MAX_PAGE_COUNT: usize =
        1 << (u32::BITS as usize - Self::LOG_PAGE_LEN - Self::NUM_IGNORED_LOWER_BITS);
    /// The number of lower bits to ignore, since addresses (except registers) are a multiple of 4.
    const NUM_IGNORED_LOWER_BITS: usize = 2;
    /// The number of registers in the virtual machine.
    const NUM_REGISTERS: usize = 32;
    /// The offset subtracted from the main address space to make it contiguous.
    const ADDR_COMPRESS_OFFSET: usize =
        Self::NUM_REGISTERS - (Self::NUM_REGISTERS >> Self::NUM_IGNORED_LOWER_BITS);

    /// Create a `PagedMemory` with capacity `MAX_PAGE_COUNT`.
    pub fn new_preallocated() -> Self {
        Self { page_table: VecMap::with_capacity(Self::MAX_PAGE_COUNT) }
    }

    /// Get a reference to the memory value at the given address, if it exists.
    pub fn get(&self, addr: u32) -> Option<&V> {
        let (upper, lower) = Self::indices(addr);
        self.page_table.get(upper)?.0.get(lower)
    }

    /// Get a mutable reference to the memory value at the given address, if it exists.
    pub fn get_mut(&mut self, addr: u32) -> Option<&mut V> {
        let (upper, lower) = Self::indices(addr);
        self.page_table.get_mut(upper)?.0.get_mut(lower)
    }

    /// Insert a value at the given address. Returns the previous value, if any.
    pub fn insert(&mut self, addr: u32, value: V) -> Option<V> {
        let (upper, lower) = Self::indices(addr);
        self.page_table
            .entry(upper)
            .or_insert_with(PagedMemory::<V>::new_page)
            .0
            .insert(lower, value)
    }

    /// Remove the value at the given address if it exists, returning it.
    pub fn remove(&mut self, addr: u32) -> Option<V> {
        let (upper, lower) = Self::indices(addr);
        match self.page_table.entry(upper) {
            vec_map::Entry::Vacant(_) => None,
            vec_map::Entry::Occupied(mut entry) => {
                let res = entry.get_mut().0.remove(lower);
                if entry.get().0.is_empty() {
                    entry.remove();
                }
                res
            }
        }
    }

    /// Gets the memory entry for the given address.
    pub fn entry(&mut self, addr: u32) -> Entry<'_, V> {
        let (upper, lower) = Self::indices(addr);
        let page_table_entry = self.page_table.entry(upper);
        if let vec_map::Entry::Occupied(occ_entry) = page_table_entry {
            if occ_entry.get().0.contains_key(lower) {
                Entry::Occupied(OccupiedEntry { lower, page_table_occupied_entry: occ_entry })
            } else {
                Entry::Vacant(VacantEntry {
                    lower,
                    page_table_entry: vec_map::Entry::Occupied(occ_entry),
                })
            }
        } else {
            Entry::Vacant(VacantEntry { lower, page_table_entry })
        }
    }

    /// Returns an iterator over the occupied addresses.
    pub fn keys(&self) -> impl Iterator<Item = u32> + '_ {
        self.page_table.iter().flat_map(|(upper, page)| {
            let upper = upper << Self::LOG_PAGE_LEN;
            page.0.iter().map(move |(lower, _)| Self::decompress_addr(upper + lower))
        })
    }

    /// Clears the page table. Drops all `Page`s, but retains the memory used by the table itself.
    pub fn clear(&mut self) {
        self.page_table.clear();
    }

    /// Break apart an address into an upper and lower index.
    #[inline]
    const fn indices(addr: u32) -> (usize, usize) {
        let index = Self::compress_addr(addr);
        (index >> Self::LOG_PAGE_LEN, index & Self::PAGE_MASK)
    }

    /// Compress an address from the sparse address space to a contiguous space.
    #[inline]
    const fn compress_addr(addr: u32) -> usize {
        let addr = addr as usize;
        if addr < Self::NUM_REGISTERS {
            addr
        } else {
            (addr >> Self::NUM_IGNORED_LOWER_BITS) + Self::ADDR_COMPRESS_OFFSET
        }
    }

    /// Decompress an address from a contiguous space to the sparse address space.
    #[inline]
    const fn decompress_addr(addr: usize) -> u32 {
        if addr < Self::NUM_REGISTERS {
            addr as u32
        } else {
            ((addr - Self::ADDR_COMPRESS_OFFSET) << Self::NUM_IGNORED_LOWER_BITS) as u32
        }
    }

    #[inline]
    fn new_page() -> Page<V> {
        Page::with_capacity(Self::PAGE_LEN)
    }
}

impl<V> Default for PagedMemory<V> {
    fn default() -> Self {
        Self { page_table: VecMap::default() }
    }
}

/// An entry of `PagedMemory`, for in-place manipulation.
pub enum Entry<'a, V> {
    Vacant(VacantEntry<'a, V>),
    Occupied(OccupiedEntry<'a, V>),
}

impl<'a, V> Entry<'a, V> {
    /// Ensures a value is in the entry, inserting the provided value if necessary.
    /// Returns a mutable reference to the value.
    pub fn or_insert(self, default: V) -> &'a mut V {
        match self {
            Entry::Vacant(entry) => entry.insert(default),
            Entry::Occupied(entry) => entry.into_mut(),
        }
    }

    /// Ensures a value is in the entry, computing a value if necessary.
    /// Returns a mutable reference to the value.
    pub fn or_insert_with<F: FnOnce() -> V>(self, default: F) -> &'a mut V {
        match self {
            Entry::Vacant(entry) => entry.insert(default()),
            Entry::Occupied(entry) => entry.into_mut(),
        }
    }

    /// Provides in-place mutable access to an occupied entry before any potential inserts into the map.
    pub fn and_modify<F: FnOnce(&mut V)>(mut self, f: F) -> Self {
        match &mut self {
            Entry::Vacant(_) => {}
            Entry::Occupied(entry) => f(entry.get_mut()),
        }
        self
    }
}

/// A vacant entry of `PagedMemory`, for in-place manipulation.
pub struct VacantEntry<'a, V> {
    lower: usize,
    page_table_entry: vec_map::Entry<'a, Page<V>>,
}

impl<'a, V> VacantEntry<'a, V> {
    /// Insert a value into the `VacantEntry`, returning a mutable reference to it.
    pub fn insert(self, value: V) -> &'a mut V {
        // By construction, the slot in the page is `None`.
        match self.page_table_entry.or_insert_with(PagedMemory::<V>::new_page).0.entry(self.lower) {
            vec_map::Entry::Vacant(entry) => entry.insert(value),
            vec_map::Entry::Occupied(_) => {
                panic!("entry with lower bits {:#x} should be vacant", self.lower)
            }
        }
    }
}

/// A vacant entry of `PagedMemory`, for in-place manipulation.
pub struct OccupiedEntry<'a, V> {
    lower: usize,
    page_table_occupied_entry: vec_map::OccupiedEntry<'a, Page<V>>,
}

impl<'a, V> OccupiedEntry<'a, V> {
    /// Get a reference to the value in the `OccupiedEntry`.
    pub fn get(&self) -> &V {
        self.page_table_occupied_entry.get().0.get(self.lower).unwrap()
    }

    /// Get a mutable reference to the value in the `OccupiedEntry`.
    pub fn get_mut(&mut self) -> &mut V {
        self.page_table_occupied_entry.get_mut().0.get_mut(self.lower).unwrap()
    }

    /// Insert a value in the `OccupiedEntry`, returning the previous value.
    pub fn insert(&mut self, value: V) -> V {
        replace(self.get_mut(), value)
    }

    /// Converts the `OccupiedEntry` the into a mutable reference to the associated value.
    pub fn into_mut(self) -> &'a mut V {
        self.page_table_occupied_entry.into_mut().0.get_mut(self.lower).unwrap()
    }

    /// Removes the value from the `OccupiedEntry` and returns it.
    pub fn remove(mut self) -> V {
        let res = self.page_table_occupied_entry.get_mut().0.remove(self.lower).unwrap();
        if self.page_table_occupied_entry.get().0.is_empty() {
            self.page_table_occupied_entry.remove();
        }
        res
    }
}

impl<V> FromIterator<(u32, V)> for PagedMemory<V> {
    fn from_iter<T: IntoIterator<Item = (u32, V)>>(iter: T) -> Self {
        let mut mmu = Self::default();
        for (k, v) in iter {
            mmu.insert(k, v);
        }
        mmu
    }
}

impl<V> IntoIterator for PagedMemory<V> {
    type Item = (u32, V);

    type IntoIter = IntoIter<V>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter { upper: 0, upper_iter: self.page_table.into_iter(), lower_iter: None }
    }
}

pub struct IntoIter<V> {
    upper: usize,
    upper_iter: vec_map::IntoIter<Page<V>>,
    lower_iter: Option<vec_map::IntoIter<V>>,
}

impl<V> Iterator for IntoIter<V> {
    type Item = (u32, V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Populate the lower iterator.
            let it = match &mut self.lower_iter {
                Some(it) => it,
                None => {
                    // Exit if the upper iterator has finished.
                    let (upper, page) = self.upper_iter.next()?;
                    self.upper = upper;
                    self.lower_iter.insert(page.0.into_iter())
                }
            };
            // Yield the next item.
            if let Some((lower, record)) = it.next() {
                return Some((
                    PagedMemory::<V>::decompress_addr(
                        (self.upper << PagedMemory::<V>::LOG_PAGE_LEN) + lower,
                    ),
                    record,
                ));
            }
            // If no next item in the lower iterator, it must be finished.
            self.lower_iter = None;
        }
    }
}
