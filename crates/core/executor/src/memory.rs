use serde::{de::DeserializeOwned, Deserialize, Serialize};
use vec_map::VecMap;

/// A page of memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<V>(VecMap<V>);

impl<V> Default for Page<V> {
    fn default() -> Self {
        Self(VecMap::default())
    }
}

const LOG_PAGE_LEN: usize = 15;
const PAGE_LEN: usize = 1 << LOG_PAGE_LEN;
const MAX_PAGE_COUNT: usize = ((1 << 31) - (1 << 27)) / 4 / PAGE_LEN + 1;
const NO_PAGE: usize = usize::MAX;
const PAGE_MASK: usize = PAGE_LEN - 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "V: Serialize"))]
#[serde(bound(deserialize = "V: DeserializeOwned"))]
pub struct NewPage<V>(Vec<Option<V>>);

impl<V: Copy> NewPage<V> {
    pub fn new() -> Self {
        Self(vec![None; PAGE_LEN])
    }
}

impl<V: Copy> Default for NewPage<V> {
    fn default() -> Self {
        Self::new()
    }
}

/// Paged memory. Balances both memory locality and total memory usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "V: Serialize"))]
#[serde(bound(deserialize = "V: DeserializeOwned"))]
pub struct PagedMemory<V: Copy> {
    /// The internal page table.
    pub page_table: Vec<NewPage<V>>,
    pub index: Vec<usize>,
}

impl<V: Copy> PagedMemory<V> {
    /// The number of lower bits to ignore, since addresses (except registers) are a multiple of 4.
    const NUM_IGNORED_LOWER_BITS: usize = 2;
    /// The number of registers in the virtual machine.
    const NUM_REGISTERS: usize = 32;
    /// The offset subtracted from the main address space to make it contiguous.
    const ADDR_COMPRESS_OFFSET: usize =
        Self::NUM_REGISTERS - (Self::NUM_REGISTERS >> Self::NUM_IGNORED_LOWER_BITS);

    /// Create a `PagedMemory` with capacity `MAX_PAGE_COUNT`.
    pub fn new_preallocated() -> Self {
        Self { page_table: Vec::new(), index: vec![NO_PAGE; MAX_PAGE_COUNT] }
    }

    /// Get a reference to the memory value at the given address, if it exists.
    pub fn get(&self, addr: u32) -> Option<&V> {
        let (upper, lower) = Self::indices(addr);
        let index = self.index[upper];
        if index == NO_PAGE {
            None
        } else {
            self.page_table[index].0[lower].as_ref()
        }
    }

    /// Get a mutable reference to the memory value at the given address, if it exists.
    pub fn get_mut(&mut self, addr: u32) -> Option<&mut V> {
        let (upper, lower) = Self::indices(addr);
        let index = self.index[upper];
        if index == NO_PAGE {
            None
        } else {
            self.page_table[index].0[lower].as_mut()
        }
    }

    /// Insert a value at the given address. Returns the previous value, if any.
    pub fn insert(&mut self, addr: u32, value: V) -> Option<V> {
        let (upper, lower) = Self::indices(addr);
        let mut index = self.index[upper];
        if index == NO_PAGE {
            index = self.page_table.len();
            self.index[upper] = index;
            self.page_table.push(NewPage::new());
        }
        self.page_table[index].0[lower].replace(value)
    }

    /// Remove the value at the given address if it exists, returning it.
    pub fn remove(&mut self, addr: u32) -> Option<V> {
        let (upper, lower) = Self::indices(addr);
        let index = self.index[upper];
        if index == NO_PAGE {
            None
        } else {
            self.page_table[index].0[lower].take()
        }
    }

    /// Gets the memory entry for the given address.
    pub fn entry(&mut self, addr: u32) -> Entry<'_, V> {
        let (upper, lower) = Self::indices(addr);
        let index = self.index[upper];
        if index == NO_PAGE {
            let index = self.page_table.len();
            self.index[upper] = index;
            self.page_table.push(NewPage::new());
            Entry::Vacant(VacantEntry { entry: &mut self.page_table[index].0[lower] })
        } else {
            let option = &mut self.page_table[index].0[lower];
            match option {
                Some(_) => Entry::Occupied(OccupiedEntry { entry: option }),
                None => Entry::Vacant(VacantEntry { entry: option }),
            }
        }
    }

    /// Returns an iterator over the occupied addresses.
    pub fn keys(&self) -> impl Iterator<Item = u32> + '_ {
        self.index.iter().enumerate().filter(|(_, &i)| i != NO_PAGE).flat_map(|(i, index)| {
            let upper = i << LOG_PAGE_LEN;
            self.page_table[*index]
                .0
                .iter()
                .enumerate()
                .filter_map(move |(lower, v)| v.map(|_| Self::decompress_addr(upper + lower)))
        })
    }

    /// Clears the page table. Drops all `Page`s, but retains the memory used by the table itself.
    pub fn clear(&mut self) {
        self.page_table.clear();
        self.index.fill(NO_PAGE);
    }

    /// Break apart an address into an upper and lower index.
    #[inline]
    const fn indices(addr: u32) -> (usize, usize) {
        let index = Self::compress_addr(addr);
        (index >> LOG_PAGE_LEN, index & PAGE_MASK)
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
}

impl<V: Copy> Default for PagedMemory<V> {
    fn default() -> Self {
        Self { page_table: Vec::new(), index: vec![NO_PAGE; MAX_PAGE_COUNT] }
    }
}

/// An entry of `PagedMemory`, for in-place manipulation.
pub enum Entry<'a, V: Copy> {
    Vacant(VacantEntry<'a, V>),
    Occupied(OccupiedEntry<'a, V>),
}

impl<'a, V: Copy> Entry<'a, V> {
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
pub struct VacantEntry<'a, V: Copy> {
    entry: &'a mut Option<V>,
}

impl<'a, V: Copy> VacantEntry<'a, V> {
    /// Insert a value into the `VacantEntry`, returning a mutable reference to it.
    pub fn insert(self, value: V) -> &'a mut V {
        // By construction, the slot in the page is `None`.
        *self.entry = Some(value);
        self.entry.as_mut().unwrap()
    }
}

/// A vacant entry of `PagedMemory`, for in-place manipulation.
pub struct OccupiedEntry<'a, V> {
    entry: &'a mut Option<V>,
}

impl<'a, V: Copy> OccupiedEntry<'a, V> {
    /// Get a reference to the value in the `OccupiedEntry`.
    pub fn get(&self) -> &V {
        self.entry.as_ref().unwrap()
    }

    /// Get a mutable reference to the value in the `OccupiedEntry`.
    pub fn get_mut(&mut self) -> &mut V {
        self.entry.as_mut().unwrap()
    }

    /// Insert a value in the `OccupiedEntry`, returning the previous value.
    pub fn insert(&mut self, value: V) -> V {
        self.entry.replace(value).unwrap()
    }

    /// Converts the `OccupiedEntry` the into a mutable reference to the associated value.
    pub fn into_mut(self) -> &'a mut V {
        self.entry.as_mut().unwrap()
    }

    /// Removes the value from the `OccupiedEntry` and returns it.
    pub fn remove(self) -> V {
        self.entry.take().unwrap()
    }
}

impl<V: Copy> FromIterator<(u32, V)> for PagedMemory<V> {
    fn from_iter<T: IntoIterator<Item = (u32, V)>>(iter: T) -> Self {
        let mut mmu = Self::default();
        for (k, v) in iter {
            mmu.insert(k, v);
        }
        mmu
    }
}

impl<V: Copy + 'static> IntoIterator for PagedMemory<V> {
    type Item = (u32, V);

    type IntoIter = Box<dyn Iterator<Item = Self::Item>>;

    fn into_iter(mut self) -> Self::IntoIter {
        Box::new(self.index.into_iter().enumerate().filter(|(_, i)| *i != NO_PAGE).flat_map(
            move |(i, index)| {
                let upper = i << LOG_PAGE_LEN;
                let replacement = NewPage::new();
                std::mem::replace(&mut self.page_table[index], replacement)
                    .0
                    .into_iter()
                    .enumerate()
                    .filter_map(move |(lower, v)| {
                        v.map(|v| (Self::decompress_addr(upper + lower), v))
                    })
            },
        ))
    }
}
