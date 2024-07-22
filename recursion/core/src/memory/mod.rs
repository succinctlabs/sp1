mod air;
mod columns;

use p3_field::PrimeField32;

use crate::air::Block;
pub use air::compute_addr_diff;
pub use columns::*;

#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryRecord<F> {
    pub addr: F,
    pub value: Block<F>,
    pub prev_value: Block<F>,
    pub timestamp: F,
    pub prev_timestamp: F,
    pub diff_16bit_limb: F,
    pub diff_12bit_limb: F,
    _private: (),
}

/// Computes the difference between the current memory access timestamp and the previous one's.
///
/// This function will compute the difference minus one and then decompose the result into a 16 bit
/// limb and 12 bit limb.  The minus one is needed since a difference of zero is not valid.  Also,
/// we assume that the clk/timestamp value will always be less than 2^28.
fn compute_diff<F: PrimeField32>(timestamp: F, prev_timestamp: F) -> (F, F) {
    let diff_minus_one = timestamp.as_canonical_u32() - prev_timestamp.as_canonical_u32() - 1;
    let diff_16bit_limb = diff_minus_one & 0xffff;
    let diff_12bit_limb = (diff_minus_one >> 16) & 0xfff;
    (F::from_canonical_u32(diff_16bit_limb), F::from_canonical_u32(diff_12bit_limb))
}

impl<F: Clone + PrimeField32> MemoryRecord<F> {
    pub fn new_write(
        addr: F,
        value: Block<F>,
        timestamp: F,
        prev_value: Block<F>,
        prev_timestamp: F,
    ) -> Self {
        assert!(timestamp >= prev_timestamp);
        let (diff_16bit_limb, diff_12bit_limb) = compute_diff(timestamp, prev_timestamp);
        Self {
            addr,
            value,
            prev_value,
            timestamp,
            prev_timestamp,
            diff_16bit_limb,
            diff_12bit_limb,
            _private: (),
        }
    }

    pub fn new_read(addr: F, value: Block<F>, timestamp: F, prev_timestamp: F) -> Self {
        assert!(timestamp >= prev_timestamp);
        let (diff_16bit_limb, diff_12bit_limb) = compute_diff(timestamp, prev_timestamp);
        Self {
            addr,
            value,
            prev_value: value,
            timestamp,
            prev_timestamp,
            diff_16bit_limb,
            diff_12bit_limb,
            _private: (),
        }
    }
}

impl<T: PrimeField32> MemoryReadWriteCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.prev_value = record.prev_value;
        self.access.populate(record.value, record);
    }
}

impl<T: PrimeField32> MemoryReadCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.access.populate(record.value, record);
    }
}

impl<T: PrimeField32> MemoryReadWriteSingleCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.prev_value = record.prev_value[0];
        self.access.populate(record.value[0], record);
    }
}

impl<T: PrimeField32> MemoryReadSingleCols<T> {
    pub fn populate(&mut self, record: &MemoryRecord<T>) {
        self.access.populate(record.value[0], record);
    }
}

impl<F: PrimeField32, TValue> MemoryAccessCols<F, TValue> {
    /// Populate the memory access columns.
    pub fn populate(&mut self, value: TValue, record: &MemoryRecord<F>) {
        self.value = value;
        self.prev_timestamp = record.prev_timestamp;
        self.diff_16bit_limb = record.diff_16bit_limb;
        self.diff_12bit_limb = record.diff_12bit_limb;
    }
}

#[derive(Default)]
pub struct MemoryGlobalChip {
    pub fixed_log2_rows: Option<usize>,
}
