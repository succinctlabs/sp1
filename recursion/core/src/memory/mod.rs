mod air;
mod columns;

use crate::air::Block;
use sp1_derive::AlignedBorrow;

#[derive(Debug, Clone)]
pub struct MemoryRecord<F> {
    pub addr: F,
    pub value: Block<F>,
    pub timestamp: F,
    pub prev_value: Block<F>,
    pub prev_timestamp: F,
}

pub trait MemoryAccessCols<T> {
    fn value(&self) -> Block<T>;
    fn prev_value(&self) -> Block<T>;
    fn timestamp(&self) -> T;
    fn prev_timestamp(&self) -> T;
}

pub trait MemoryAccessColsSingle<T> {
    fn value(&self) -> T;
    fn prev_value(&self) -> T;
    fn timestamp(&self) -> T;
    fn prev_timestamp(&self) -> T;
}

#[derive(AlignedBorrow, Default, Debug, Clone)]
#[repr(C)]
pub struct MemoryReadWriteCols<T> {
    pub prev_timestamp: T,
    pub timestamp: T,
    pub addr: T,
    pub prev_value: Block<T>,
    pub value: Block<T>,
}

impl<T: Clone> MemoryReadWriteCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.addr = record.addr.clone();
        self.value = record.value.clone();
        self.timestamp = record.timestamp.clone();
        self.prev_value = record.prev_value.clone();
        self.prev_timestamp = record.prev_timestamp.clone();
    }
}

impl<T: Clone> MemoryAccessCols<T> for MemoryReadWriteCols<T> {
    fn value(&self) -> Block<T> {
        self.value.clone()
    }

    fn prev_value(&self) -> Block<T> {
        self.prev_value.clone()
    }

    fn timestamp(&self) -> T {
        self.timestamp.clone()
    }

    fn prev_timestamp(&self) -> T {
        self.prev_timestamp.clone()
    }
}

#[derive(AlignedBorrow, Default, Debug, Clone)]
#[repr(C)]
pub struct MemoryReadColsWithoutAddr<T> {
    pub value: Block<T>,
    pub timestamp: T,
    pub prev_timestamp: T,
}

impl<T: Clone> MemoryReadColsWithoutAddr<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.value = record.value.clone();
        self.timestamp = record.timestamp.clone();
        self.prev_timestamp = record.prev_timestamp.clone();
    }
}

impl<T: Clone> MemoryAccessCols<T> for MemoryReadColsWithoutAddr<T> {
    fn value(&self) -> Block<T> {
        self.value.clone()
    }

    fn prev_value(&self) -> Block<T> {
        self.value()
    }

    fn timestamp(&self) -> T {
        self.timestamp.clone()
    }

    fn prev_timestamp(&self) -> T {
        self.prev_timestamp.clone()
    }
}

#[derive(AlignedBorrow, Default, Debug, Clone)]
#[repr(C)]
pub struct MemoryReadSingleColsWithoutAddr<T> {
    pub value: T,
    pub timestamp: T,
    pub prev_timestamp: T,
}

impl<T: Clone> MemoryReadSingleColsWithoutAddr<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.value = record.value.0[0].clone();
        self.timestamp = record.timestamp.clone();
        self.prev_timestamp = record.prev_timestamp.clone();
    }
}

impl<T: Clone> MemoryAccessColsSingle<T> for MemoryReadSingleColsWithoutAddr<T> {
    fn value(&self) -> T {
        self.value.clone()
    }

    fn prev_value(&self) -> T {
        self.value()
    }

    fn timestamp(&self) -> T {
        self.timestamp.clone()
    }

    fn prev_timestamp(&self) -> T {
        self.prev_timestamp.clone()
    }
}

#[derive(AlignedBorrow, Default, Debug, Clone)]
#[repr(C)]
pub struct MemoryReadWriteColsWithoutAddr<T> {
    pub value: Block<T>,
    pub prev_value: Block<T>,
    pub timestamp: T,
    pub prev_timestamp: T,
}
impl<T: Clone> MemoryReadWriteColsWithoutAddr<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.value = record.value.clone();
        self.prev_value = record.prev_value.clone();
        self.timestamp = record.timestamp.clone();
        self.prev_timestamp = record.prev_timestamp.clone();
    }
}

impl<T: Clone> MemoryAccessCols<T> for MemoryReadWriteColsWithoutAddr<T> {
    fn value(&self) -> Block<T> {
        self.value.clone()
    }

    fn prev_value(&self) -> Block<T> {
        self.prev_value.clone()
    }

    fn timestamp(&self) -> T {
        self.timestamp.clone()
    }

    fn prev_timestamp(&self) -> T {
        self.prev_timestamp.clone()
    }
}

#[derive(AlignedBorrow, Default, Debug, Clone)]
#[repr(C)]
pub struct MemoryReadWriteSingleColsWithoutAddr<T> {
    pub value: T,
    pub prev_value: T,
    pub timestamp: T,
    pub prev_timestamp: T,
}
impl<T: Clone> MemoryReadWriteSingleColsWithoutAddr<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.value = record.value.0[0].clone();
        self.prev_value = record.prev_value.0[0].clone();
        self.timestamp = record.timestamp.clone();
        self.prev_timestamp = record.prev_timestamp.clone();
    }
}

impl<T: Clone> MemoryAccessColsSingle<T> for MemoryReadWriteSingleColsWithoutAddr<T> {
    fn value(&self) -> T {
        self.value.clone()
    }

    fn prev_value(&self) -> T {
        self.prev_value.clone()
    }

    fn timestamp(&self) -> T {
        self.timestamp.clone()
    }

    fn prev_timestamp(&self) -> T {
        self.prev_timestamp.clone()
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
