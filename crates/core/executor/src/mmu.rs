use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::events::MemoryRecord;

pub const LOG_BLOCK_SIZE: usize = 12 - std::mem::size_of::<Option<MemoryRecord>>().ilog2() as usize;
pub const BLOCK_SIZE: usize = 1 << LOG_BLOCK_SIZE;
pub const BLOCK_MASK: usize = BLOCK_SIZE - 1;

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page(#[serde_as(as = "Box<[_; BLOCK_SIZE]>")] Box<[Option<MemoryRecord>; BLOCK_SIZE]>);

impl Default for Page {
    fn default() -> Self {
        Self(Box::new([None; BLOCK_SIZE]))
    }
}

pub use btree_mmu::BTreeMmu;

pub mod btree_mmu {
    use std::collections::BTreeMap;
    use std::{
        collections::btree_map,
        mem::{replace, take},
    };

    use serde::{Deserialize, Serialize};

    use super::{Page, BLOCK_MASK, LOG_BLOCK_SIZE};
    use crate::events::MemoryRecord;

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct BTreeMmu {
        pub page_table: BTreeMap<usize, Page>,
    }

    impl BTreeMmu {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn get(&self, index: usize) -> Option<&MemoryRecord> {
            let (upper, lower) = Self::split_index(index);
            self.page_table.get(&upper)?.0[lower].as_ref()
        }

        pub fn get_mut(&mut self, index: usize) -> Option<&mut MemoryRecord> {
            let (upper, lower) = Self::split_index(index);
            self.page_table.get_mut(&upper)?.0[lower].as_mut()
        }

        pub fn insert(&mut self, index: usize, value: MemoryRecord) {
            let (upper, lower) = Self::split_index(index);
            if let Some(block) = self.page_table.get_mut(&upper) {
                block.0[lower] = Some(value);
            } else {
                let mut new_block = Page::default();
                new_block.0[lower] = Some(value);
                self.page_table.insert(upper, new_block);
            }
        }

        pub fn remove(&mut self, index: usize) -> Option<MemoryRecord> {
            let (upper, lower) = Self::split_index(index);
            take(&mut self.page_table.get_mut(&upper)?.0[lower])
        }

        pub fn entry(&mut self, index: usize) -> Entry<'_> {
            let (upper, lower) = Self::split_index(index);
            let page_table_entry = self.page_table.entry(upper);
            if let btree_map::Entry::Occupied(occ_entry) = page_table_entry {
                if occ_entry.get().0[lower].is_some() {
                    Entry::Occupied(OccupiedEntry { lower, page_table_occupied_entry: occ_entry })
                } else {
                    Entry::Vacant(VacantEntry {
                        index,
                        page_table_entry: btree_map::Entry::Occupied(occ_entry),
                    })
                }
            } else {
                Entry::Vacant(VacantEntry { index, page_table_entry })
            }
        }

        pub fn keys(&self) -> impl Iterator<Item = usize> + '_ {
            self.page_table.iter().flat_map(|(upper, page)| {
                page.0
                    .iter()
                    .enumerate()
                    .filter_map(move |(lower, record)| record.is_some().then_some(upper + lower))
            })
        }

        #[inline]
        fn split_index(index: usize) -> (usize, usize) {
            (index >> LOG_BLOCK_SIZE, index & BLOCK_MASK)
        }
    }

    #[derive(Debug)]
    pub enum Entry<'a> {
        Vacant(VacantEntry<'a>),
        Occupied(OccupiedEntry<'a>),
    }

    #[derive(Debug)]
    pub struct VacantEntry<'a> {
        index: usize,
        page_table_entry: btree_map::Entry<'a, usize, Page>,
    }

    impl<'a> VacantEntry<'a> {
        pub fn insert(self, value: MemoryRecord) -> &'a mut MemoryRecord {
            // By construction, the slot in the page is `None`.
            self.page_table_entry.or_default().0[self.index & BLOCK_MASK].insert(value)
        }

        pub fn into_key(self) -> usize {
            self.page_table_entry.key();
            self.index
        }

        pub fn key(&self) -> &usize {
            &self.index
        }
    }

    #[derive(Debug)]
    pub struct OccupiedEntry<'a> {
        lower: usize,
        page_table_occupied_entry: btree_map::OccupiedEntry<'a, usize, Page>,
    }

    impl<'a> OccupiedEntry<'a> {
        pub fn get(&self) -> &MemoryRecord {
            self.page_table_occupied_entry.get().0[self.lower].as_ref().unwrap()
        }

        pub fn get_mut(&mut self) -> &mut MemoryRecord {
            self.page_table_occupied_entry.get_mut().0[self.lower].as_mut().unwrap()
        }

        pub fn insert(&mut self, value: MemoryRecord) -> MemoryRecord {
            replace(self.get_mut(), value)
        }

        pub fn into_mut(self) -> &'a mut MemoryRecord {
            self.page_table_occupied_entry.into_mut().0[self.lower].as_mut().unwrap()
        }

        pub fn remove(mut self) -> MemoryRecord {
            self.page_table_occupied_entry.get_mut().0[self.lower].take().unwrap()
        }
    }

    // impl IntoIterator for BTreeMmu {
    //     type Item = (usize, MemoryRecord);

    //     type IntoIter = FlatMap<
    //         std::collections::btree_map::IntoIter<usize, Page>,
    //         FilterMap<
    //             Enumerate<std::array::IntoIter<Option<MemoryRecord>, BLOCK_SIZE>>,
    //             impl FnMut((usize, Option<MemoryRecord>)) -> Option<(usize, MemoryRecord)>,
    //         >,
    //         impl FnMut(
    //             (usize, Page),
    //         ) -> FilterMap<
    //             Enumerate<IntoIter<Option<MemoryRecord>, _>>,
    //             impl FnMut((usize, Option<MemoryRecord>)) -> Option<(usize, MemoryRecord)>,
    //         >,
    //     >;

    //     fn into_iter(self) -> Self::IntoIter {
    //         let flat_map = self.page_table.into_iter().flat_map(|(upper, page)| {
    //             page.0
    //                 .into_iter()
    //                 .enumerate()
    //                 .filter_map(|(lower, record)| Some((upper + lower, record?)))
    //         });
    //         flat_map
    //     }
    // }

    impl FromIterator<(usize, MemoryRecord)> for BTreeMmu {
        fn from_iter<T: IntoIterator<Item = (usize, MemoryRecord)>>(iter: T) -> Self {
            let mut mmu = Self::default();
            for (k, v) in iter {
                mmu.insert(k, v);
            }
            mmu
        }
    }
}

// use std::ops::{Index, IndexMut};

// impl Index<usize> for ByteSpace {
//     type Output = MemoryRecord;
//     fn index(&self, idx: usize) -> &MemoryRecord {
//         let hi = idx & !BLOCK_MASK;
//         let lo = idx & BLOCK_MASK;
//         let Some(block) = self.0.get(&hi) else { return &0 };
//         &block[lo]
//     }
// }

// impl IndexMut<usize> for ByteSpace {
//     fn index_mut(&mut self, idx: usize) -> &mut MemoryRecord {
//         let hi = idx & !BLOCK_MASK;
//         let lo = idx & BLOCK_MASK;
//         &mut self.0.entry(hi).or_insert([Default::default(); BLOCK_MASK + 1])[lo]
//     }
// }
