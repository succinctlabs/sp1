use std::mem::{replace, size_of};

use serde::{Deserialize, Serialize};
use vec_map::VecMap;

use crate::events::MemoryRecord;

/// The base 2 logarithm of the (maximum) page size in bytes.
pub const LOG_PAGE_SIZE: usize = 12;
/// The base 2 logarithm of the length of each page, considered as an array of `Option<MemoryRecord>`.
pub const LOG_PAGE_LEN: usize =
    LOG_PAGE_SIZE - size_of::<Option<MemoryRecord>>().next_power_of_two().ilog2() as usize;
/// The length of each page, considered as an array of `Option<MemoryRecord>`.
pub const PAGE_LEN: usize = 1 << LOG_PAGE_LEN;
/// The mask for retrieving the lowest bits necessary to index within a page.
pub const PAGE_MASK: usize = PAGE_LEN - 1;
/// The maximum number of pages. Used for the length of the page table.
pub const MAX_PAGE_COUNT: usize = 1 << (u32::BITS as usize - LOG_PAGE_LEN - NUM_IGNORED_LOWER_BITS);
/// The number of lower bits to ignore, since addresses (except registers) are a multiple of 4.
pub const NUM_IGNORED_LOWER_BITS: usize = 2;
/// The number of registers in the virtual machine.
pub const NUM_REGISTERS: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<V>(VecMap<V>);

impl<V> Page<V> {
    pub fn new() -> Self {
        Self(VecMap::with_capacity(PAGE_LEN))
    }
}

impl<V> Default for Page<V> {
    fn default() -> Self {
        Self(VecMap::default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mmu<V> {
    pub page_table: VecMap<Page<V>>,
}

impl<V> Mmu<V> {
    pub fn new() -> Self {
        Self { page_table: VecMap::with_capacity(MAX_PAGE_COUNT) }
    }

    pub fn get(&self, addr: u32) -> Option<&V> {
        let (upper, lower) = Self::indices(addr);
        self.page_table.get(upper)?.0.get(lower)
    }

    pub fn get_mut(&mut self, addr: u32) -> Option<&mut V> {
        let (upper, lower) = Self::indices(addr);
        self.page_table.get_mut(upper)?.0.get_mut(lower)
    }

    pub fn insert(&mut self, addr: u32, value: V) -> Option<V> {
        let (upper, lower) = Self::indices(addr);
        self.page_table.entry(upper).or_insert_with(Page::default).0.insert(lower, value)
    }

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

    pub fn keys(&self) -> impl Iterator<Item = u32> + '_ {
        self.page_table.iter().flat_map(|(upper, page)| {
            let upper = upper << LOG_PAGE_LEN;
            page.0.iter().map(move |(lower, _)| Self::decompress_addr(upper + lower))
        })
    }

    #[inline]
    const fn indices(addr: u32) -> (usize, usize) {
        let index = Self::compress_addr(addr);
        (index >> LOG_PAGE_LEN, index & PAGE_MASK)
    }

    #[inline]
    const fn compress_addr(addr: u32) -> usize {
        let addr = addr as usize;
        if addr < NUM_REGISTERS {
            addr
        } else {
            (addr >> NUM_IGNORED_LOWER_BITS)
                + const { NUM_REGISTERS - (NUM_REGISTERS >> NUM_IGNORED_LOWER_BITS) }
        }
    }

    #[inline]
    const fn decompress_addr(addr: usize) -> u32 {
        if addr < NUM_REGISTERS {
            addr as u32
        } else {
            (addr as u32
                - const { (NUM_REGISTERS - (NUM_REGISTERS >> NUM_IGNORED_LOWER_BITS)) as u32 })
                << NUM_IGNORED_LOWER_BITS
        }
    }
}

impl<V> Default for Mmu<V> {
    fn default() -> Self {
        Self { page_table: VecMap::default() }
    }
}

pub enum Entry<'a, V> {
    Vacant(VacantEntry<'a, V>),
    Occupied(OccupiedEntry<'a, V>),
}

pub struct VacantEntry<'a, V> {
    lower: usize,
    page_table_entry: vec_map::Entry<'a, Page<V>>,
}

impl<'a, V> VacantEntry<'a, V> {
    pub fn insert(self, value: V) -> &'a mut V {
        // By construction, the slot in the page is `None`.
        match self.page_table_entry.or_insert_with(Default::default).0.entry(self.lower) {
            vec_map::Entry::Vacant(entry) => entry.insert(value),
            vec_map::Entry::Occupied(_) => {
                panic!("entry with lower bits {:#x} should be vacant", self.lower)
            }
        }
    }
}

pub struct OccupiedEntry<'a, V> {
    lower: usize,
    page_table_occupied_entry: vec_map::OccupiedEntry<'a, Page<V>>,
}

impl<'a, V> OccupiedEntry<'a, V> {
    pub fn get(&self) -> &V {
        self.page_table_occupied_entry.get().0.get(self.lower).unwrap()
    }

    pub fn get_mut(&mut self) -> &mut V {
        self.page_table_occupied_entry.get_mut().0.get_mut(self.lower).unwrap()
    }

    pub fn insert(&mut self, value: V) -> V {
        replace(self.get_mut(), value)
    }

    pub fn into_mut(self) -> &'a mut V {
        self.page_table_occupied_entry.into_mut().0.get_mut(self.lower).unwrap()
    }

    pub fn remove(mut self) -> V {
        let res = self.page_table_occupied_entry.get_mut().0.remove(self.lower).unwrap();
        if self.page_table_occupied_entry.get().0.is_empty() {
            self.page_table_occupied_entry.remove();
        }
        res
    }
}

impl<V> FromIterator<(u32, V)> for Mmu<V> {
    fn from_iter<T: IntoIterator<Item = (u32, V)>>(iter: T) -> Self {
        let mut mmu = Self::default();
        for (k, v) in iter {
            mmu.insert(k, v);
        }
        mmu
    }
}
