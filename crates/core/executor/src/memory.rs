use std::{
    iter::{Enumerate, Filter, FilterMap},
    mem::{replace, size_of},
};

use enum_map::IntoIter;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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

const NEW_LOG_PAGE_LEN: usize = 14;
const NEW_PAGE_LEN: usize = 1 << NEW_LOG_PAGE_LEN;
const NEW_MAX_PAGE_COUNT: usize = ((1 << 31) - (1 << 27)) / 4 / NEW_PAGE_LEN + 1;
const NO_PAGE: usize = usize::MAX;
const NEW_PAGE_MASK: usize = NEW_PAGE_LEN - 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "V: Serialize"))]
#[serde(bound(deserialize = "V: DeserializeOwned"))]
pub struct NewPage<V>(Vec<Option<V>>);

impl<V: Copy> NewPage<V> {
    pub fn new() -> Self {
        Self(vec![None; NEW_PAGE_LEN])
    }
}

/// Paged memory. Balances both memory locality and total memory usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "V: Serialize"))]
#[serde(bound(deserialize = "V: DeserializeOwned"))]
pub struct PagedMemory<V: Copy> {
    /// The internal page table.
    pub page_table: Vec<Box<NewPage<V>>>,
    pub index: Vec<usize>,
}

impl<V: Copy> PagedMemory<V> {
    /// The base 2 logarithm of the (maximum) page size in bytes.
    const LOG_PAGE_SIZE: usize = 12;
    /// The base 2 logarithm of the length of each page, considered as an array of `Option<V>`.
    const LOG_PAGE_LEN: usize =
        Self::LOG_PAGE_SIZE - size_of::<Option<Option<V>>>().next_power_of_two().ilog2() as usize;
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
        Self { page_table: Vec::new(), index: vec![NO_PAGE; NEW_MAX_PAGE_COUNT] }
    }

    /// Get a reference to the memory value at the given address, if it exists.
    pub fn get(&self, addr: u32) -> Option<&V> {
        let (upper, lower) = Self::indices(addr);
        // self.page_table.get(upper)?.0.get(lower)
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
        // self.page_table.get_mut(upper)?.0.get_mut(lower)
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
        // self.page_table
        //     .entry(upper)
        //     .or_insert_with(PagedMemory::<V>::new_page)
        //     .0
        //     .insert(lower, value)
        let mut index = self.index[upper];
        if index == NO_PAGE {
            index = self.page_table.len();
            self.index[upper] = index;
            self.page_table.push(Box::new(NewPage::new()));
        }
        self.page_table[index].0[lower].replace(value)
    }

    /// Remove the value at the given address if it exists, returning it.
    pub fn remove(&mut self, addr: u32) -> Option<V> {
        let (upper, lower) = Self::indices(addr);
        // match self.page_table.entry(upper) {
        //     vec_map::Entry::Vacant(_) => None,
        //     vec_map::Entry::Occupied(mut entry) => {
        //         let res = entry.get_mut().0.remove(lower);
        //         if entry.get().0.is_empty() {
        //             entry.remove();
        //         }
        //         res
        //     }
        // }
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
        // let page_table_entry = self.page_table.entry(upper);
        // if let vec_map::Entry::Occupied(occ_entry) = page_table_entry {
        //     if occ_entry.get().0.contains_key(lower) {
        //         Entry::Occupied(OccupiedEntry { lower, page_table_occupied_entry: occ_entry })
        //     } else {
        //         Entry::Vacant(VacantEntry {
        //             lower,
        //             page_table_entry: vec_map::Entry::Occupied(occ_entry),
        //         })
        //     }
        // } else {
        //     Entry::Vacant(VacantEntry { lower, page_table_entry })
        // }
        let index = self.index[upper];
        if index == NO_PAGE {
            let index = self.page_table.len();
            self.index[upper] = index;
            self.page_table.push(Box::new(NewPage::new()));
            Entry::Vacant(VacantEntry { entry: &mut self.page_table[index].0[lower] })
        } else {
            let option = &mut self.page_table[index].0[lower];
            match option {
                Some(v) => Entry::Occupied(OccupiedEntry { entry: option }),
                None => Entry::Vacant(VacantEntry { entry: option }),
            }
        }
    }

    /// Returns an iterator over the occupied addresses.
    pub fn keys(&self) -> impl Iterator<Item = u32> + '_ {
        // self.page_table.iter().flat_map(|(upper, page)| {
        //     let upper = upper << Self::LOG_PAGE_LEN;
        //     page.0.iter().map(move |(lower, _)| Self::decompress_addr(upper + lower))
        // })
        self.index.iter().enumerate().filter(|(_, &i)| i != NO_PAGE).flat_map(|(i, index)| {
            let upper = i << NEW_LOG_PAGE_LEN;
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
    #[inline(always)]
    const fn indices(addr: u32) -> (usize, usize) {
        let index = Self::compress_addr(addr);
        (index >> NEW_LOG_PAGE_LEN, index & NEW_PAGE_MASK)
    }

    /// Compress an address from the sparse address space to a contiguous space.
    #[inline(always)]
    const fn compress_addr(addr: u32) -> usize {
        let addr = addr as usize;
        if addr < Self::NUM_REGISTERS {
            addr
        } else {
            (addr >> Self::NUM_IGNORED_LOWER_BITS) + Self::ADDR_COMPRESS_OFFSET
        }
    }

    /// Decompress an address from a contiguous space to the sparse address space.
    #[inline(always)]
    const fn decompress_addr(addr: usize) -> u32 {
        if addr < Self::NUM_REGISTERS {
            addr as u32
        } else {
            ((addr - Self::ADDR_COMPRESS_OFFSET) << Self::NUM_IGNORED_LOWER_BITS) as u32
        }
    }

    #[inline(always)]
    fn new_page() -> Page<V> {
        Page::with_capacity(NEW_PAGE_LEN)
    }
}

impl<V: Copy> Default for PagedMemory<V> {
    fn default() -> Self {
        Self { page_table: Vec::new(), index: vec![NO_PAGE; NEW_MAX_PAGE_COUNT] }
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
}

/// A vacant entry of `PagedMemory`, for in-place manipulation.
pub struct VacantEntry<'a, V: Copy> {
    entry: &'a mut Option<V>,
}

impl<'a, V: Copy> VacantEntry<'a, V> {
    /// Insert a value into the `VacantEntry`, returning a mutable reference to it.
    pub fn insert(self, value: V) -> &'a mut V {
        // By construction, the slot in the page is `None`.
        // match self.page_table_entry.or_insert_with(PagedMemory::<V>::new_page).0.entry(self.lower) {
        //     vec_map::Entry::Vacant(entry) => entry.insert(value),
        //     vec_map::Entry::Occupied(_) => {
        //         panic!("entry with lower bits {:#x} should be vacant", self.lower)
        //     }
        // }
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
        // self.page_table_occupied_entry.get().0.get(self.lower).unwrap()
        self.entry.as_ref().unwrap()
    }

    /// Get a mutable reference to the value in the `OccupiedEntry`.
    pub fn get_mut(&mut self) -> &mut V {
        // self.page_table_occupied_entry.get_mut().0.get_mut(self.lower).unwrap()
        self.entry.as_mut().unwrap()
    }

    /// Insert a value in the `OccupiedEntry`, returning the previous value.
    pub fn insert(&mut self, value: V) -> V {
        // replace(self.get_mut(), value)
        self.entry.replace(value).unwrap()
    }

    /// Converts the `OccupiedEntry` the into a mutable reference to the associated value.
    pub fn into_mut(self) -> &'a mut V {
        // self.page_table_occupied_entry.into_mut().0.get_mut(self.lower).unwrap()
        self.entry.as_mut().unwrap()
    }

    /// Removes the value from the `OccupiedEntry` and returns it.
    pub fn remove(mut self) -> V {
        // let res = self.page_table_occupied_entry.get_mut().0.remove(self.lower).unwrap();
        // if self.page_table_occupied_entry.get().0.is_empty() {
        //     self.page_table_occupied_entry.remove();
        // }
        // res
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
                let upper = i << NEW_LOG_PAGE_LEN;
                let mut replacement = Box::new(NewPage::new());
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

// pub struct IntoIter<V: Copy> {
//     upper: usize,
//     upper_iter: Enumerate<std::array::IntoIter<usize, NEW_MAX_PAGE_COUNT>>,
//     lower_iter: Option<Enumerate<std::array::IntoIter<Option<V>, NEW_PAGE_LEN>>>,
//     // upper_iter: vec_map::IntoIter<Page<V>>,
//     // lower_iter: Option<vec_map::IntoIter<V>>,
// }

// impl<V: Copy> Iterator for IntoIter<V> {
//     type Item = (u32, V);

//     fn next(&mut self) -> Option<Self::Item> {
//         loop {
//             // Populate the lower iterator.
//             let it = match &mut self.lower_iter {
//                 Some(it) => it,
//                 None => {
//                     // Exit if the upper iterator has finished.
//                     let (upper, index) = self.upper_iter.next()?;
//                     if index == NO_PAGE {
//                         continue;
//                     }
//                     self.upper = upper;
//                     self.lower_iter.insert(self.page_table[index].0.into_iter())
//                 }
//             };
//             // Yield the next item.
//             if let Some((lower, record)) = it.next() {
//                 if let Some(val) = record {
//                     return Some((
//                         PagedMemory::<V>::decompress_addr((self.upper << NEW_LOG_PAGE_LEN) + lower),
//                         val,
//                     ));
//                 } else {
//                     continue;
//                 }
//             }
//             // If no next item in the lower iterator, it must be finished.
//             self.lower_iter = None;
//         }
//     }
// }
