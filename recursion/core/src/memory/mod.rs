mod air;
mod columns;

use crate::air::Block;
pub use columns::*;

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

impl<F: Clone> MemoryRecord<F> {
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
            value: value.clone(),
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

impl<T: Clone> MemoryReadCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.access.prev_timestamp = record.prev_timestamp.clone();
        self.access.value = record.value.clone();
    }
}

impl<T: Clone> MemoryReadWriteSingleCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.access.prev_timestamp = record.prev_timestamp.clone();
        self.access.value = record.value.0[0].clone();
        self.prev_value = record.prev_value.0[0].clone();
    }
}

impl<T: Clone> MemoryReadSingleCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.access.prev_timestamp = record.prev_timestamp.clone();
        self.access.value = record.value.0[0].clone();
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
