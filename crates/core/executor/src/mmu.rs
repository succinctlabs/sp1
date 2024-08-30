use std::collections::BTreeMap;
use std::ops::{Index, IndexMut};

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::events::MemoryRecord;

pub const BLOCK_SIZE: usize = 1 << (12 - std::mem::size_of::<MemoryRecord>().ilog2());
pub const BLOCK_MASK: usize = BLOCK_SIZE - 1;

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct Page(#[serde_as(as = "[_; BLOCK_SIZE]")] [MemoryRecord; BLOCK_SIZE]);

impl Default for Page {
    fn default() -> Self {
        Self([MemoryRecord::default(); BLOCK_SIZE])
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde_as]
pub struct Mmu {
    pub pages: BTreeMap<usize, Page>,
}

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

impl Mmu {
    pub fn get(&self, index: usize) -> Option<MemoryRecord> {
        let upper = index & !BLOCK_MASK;
        let lower = index & BLOCK_MASK;
        self.pages.get(&upper).map(|block| block.0[lower])
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut MemoryRecord> {
        let upper = index & !BLOCK_MASK;
        let lower = index & BLOCK_MASK;
        self.pages.get_mut(&upper).map(|block| &mut block.0[lower])
    }

    pub fn insert(&mut self, index: usize, value: MemoryRecord) {
        let upper = index & !BLOCK_MASK;
        let lower = index & BLOCK_MASK;
        if let Some(block) = self.pages.get_mut(&upper) {
            block.0[lower] = value;
        } else {
            let mut new_block = Page::default();
            new_block.0[lower] = value;
            self.pages.insert(upper, new_block);
        }
    }
}
