mod air;
mod columns;

use p3_field::PrimeField32;

use crate::{
    air::Block,
    range_check::{RangeCheckEvent, RangeCheckOpcode},
};
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

impl<T: PrimeField32> MemoryReadWriteCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>, output: &mut Vec<RangeCheckEvent>) {
        self.prev_value = record.prev_value.clone();
        self.access.populate(record.value.clone(), record, output);
    }
}

impl<T: PrimeField32> MemoryReadCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>, output: &mut Vec<RangeCheckEvent>) {
        self.access.populate(record.value.clone(), record, output);
    }
}

impl<T: PrimeField32> MemoryReadWriteSingleCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>, output: &mut Vec<RangeCheckEvent>) {
        self.prev_value = record.prev_value[0].clone();
        self.access
            .populate(record.value[0].clone(), record, output);
    }
}

impl<T: PrimeField32> MemoryReadSingleCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>, output: &mut Vec<RangeCheckEvent>) {
        self.access
            .populate(record.value[0].clone(), record, output);
    }
}

impl<F: PrimeField32, TValue> MemoryAccessCols<F, TValue> {
    pub fn populate(
        &mut self,
        value: TValue,
        record: &MemoryRecord<F>,
        output: &mut Vec<RangeCheckEvent>,
    ) {
        self.value = value;
        self.prev_timestamp = record.prev_timestamp;

        // Calculate the diff between the current and previous timestamps and subtract 1.
        // We need to subtract 1 since we can to make sure that the ts diff is [1, 2^28].
        let diff_minus_one =
            record.timestamp.as_canonical_u32() - record.prev_timestamp.as_canonical_u32() - 1;
        let diff_16bit_limb = diff_minus_one & 0xffff;
        self.diff_16bit_limb = F::from_canonical_u32(diff_16bit_limb);
        let diff_12bit_limb = (diff_minus_one >> 16) & 0xfff;
        self.diff_12bit_limb = F::from_canonical_u32(diff_12bit_limb);

        output.push(RangeCheckEvent::new(
            RangeCheckOpcode::U16,
            diff_16bit_limb as u16,
        ));
        output.push(RangeCheckEvent::new(
            RangeCheckOpcode::U12,
            diff_12bit_limb as u16,
        ));
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
