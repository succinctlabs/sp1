mod air;
mod columns;

use crate::air::Block;
use columns::*;
use sp1_derive::AlignedBorrow;

#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Clone)]
pub struct MemoryRecord<F> {
    pub addr: F,
    pub value: Block<F>,
    pub prev_value: Block<F>,
    pub timestamp: F,
    pub prev_timestamp: F,
    _private: (),
}

impl<F> MemoryRecord<F> {
    pub fn new_write(
        addr: F,
        value: Block<F>,
        timestamp: F,
        prev_value: Block<F>,
        prev_timestamp: F,
    ) -> Self {
        Self {
            addr,
            value,
            prev_value,
            timestamp,
            prev_timestamp,
            _private: (),
        }
    }

    pub fn new_read(addr: F, value: Block<F>, timestamp: F, prev_timestamp: F) -> Self {
        Self {
            addr,
            value,
            prev_value: value,
            timestamp,
            prev_timestamp,
            _private: (),
        }
    }
}

impl<T: Clone> MemoryReadWriteCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.access.prev_timestamp = record.prev_timestamp.clone();
        self.access.value = record.value.clone();
        self.prev_value = record.prev_value.clone();
    }
}

impl<T: Clone> MemoryWriteCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.access.prev_timestamp = record.prev_timestamp.clone();
        self.access.value = record.value.clone();
        self.prev_value = record.prev_value.clone();
    }
}

impl<T: Clone> MemoryReadCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.access.prev_timestamp = record.prev_timestamp.clone();
        self.access.value = record.value.clone();
    }
}

#[allow(dead_code)]
#[derive(PartialEq)]
pub enum MemoryChipKind {
    Init,
    Finalize,
}

pub struct MemoryGlobalChip {
    pub kind: MemoryChipKind,
}
