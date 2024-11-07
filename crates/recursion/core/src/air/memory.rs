use p3_field::PrimeField32;
use sp1_derive::AlignedBorrow;

use crate::air::Block;

#[derive(AlignedBorrow, Default, Debug, Clone)]
#[repr(C)]
pub struct MemoryInitCols<T> {
    pub addr: T,
    pub timestamp: T,
    pub value: Block<T>,
    pub is_initialize: T,
    pub is_finalize: T,

    /// This column is the least significant 16 bit limb of next_address - current_address.
    pub diff_16bit_limb: T,

    /// This column is the most significant 8 bit limb of next_address - current_address.
    pub diff_12bit_limb: T,

    /// Same for the address column.
    pub addr_16bit_limb: T,
    pub addr_12bit_limb: T,

    // An additional column to indicate if the memory row is a padded row.
    pub is_real: T,

    // A flag column for when range checks need to be applied to the diff columns. Range checks
    // always need to be applied to the address columns.
    pub is_range_check: T,
}

impl<T: PrimeField32> MemoryInitCols<T> {
    pub fn new() -> Self {
        Self {
            addr: T::zero(),
            timestamp: T::zero(),
            value: Block::from([T::zero(); 4]),
            is_initialize: T::zero(),
            is_finalize: T::zero(),
            diff_16bit_limb: T::zero(),
            diff_12bit_limb: T::zero(),
            addr_16bit_limb: T::zero(),
            addr_12bit_limb: T::zero(),
            is_real: T::zero(),
            is_range_check: T::zero(),
        }
    }
}

/// NOTE: These are very similar to core/src/memory/columns.rs
/// The reason we cannot use those structs directly is that they use "shard".
/// In our recursive VM, we don't have shards, we only have `clk` (i.e. timestamp).

/// Memory read access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryReadCols<T> {
    pub access: MemoryAccessCols<T, Block<T>>,
}

/// Memory read-write access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryReadWriteCols<T> {
    pub prev_value: Block<T>,
    pub access: MemoryAccessCols<T, Block<T>>,
}

/// Memory read access of a single field element.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryReadSingleCols<T> {
    pub access: MemoryAccessCols<T, T>,
}

/// Memory read-write access of a single field element.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryReadWriteSingleCols<T> {
    pub prev_value: T,
    pub access: MemoryAccessCols<T, T>,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryAccessCols<T, TValue> {
    /// The value of the memory access.
    pub value: TValue,

    /// The previous timestamp that this memory access is being read from.
    pub prev_timestamp: T,

    /// The following columns are decomposed limbs for the difference between the current access's
    /// timestamp and the previous access's timestamp.  Note the actual value of the timestamp
    /// is either the accesses' shard or clk depending on the value of compare_clk.

    /// This column is the least significant 16 bit limb of current access timestamp - prev access
    /// timestamp.
    pub diff_16bit_limb: T,

    /// This column is the most significant 12 bit limb of current access timestamp - prev access
    /// timestamp.
    pub diff_12bit_limb: T,
}

/// The common columns for all memory access types.
pub trait MemoryCols<T, TValue> {
    fn access(&self) -> &MemoryAccessCols<T, TValue>;

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T, TValue>;

    fn prev_value(&self) -> &TValue;

    fn prev_value_mut(&mut self) -> &mut TValue;

    fn value(&self) -> &TValue;

    fn value_mut(&mut self) -> &mut TValue;
}

pub trait MemoryAccessTimestampCols<T> {
    fn prev_timestamp(&self) -> &T;

    fn diff_16bit_limb(&self) -> &T;

    fn diff_12bit_limb(&self) -> &T;
}

impl<T> MemoryAccessTimestampCols<T> for MemoryAccessCols<T, Block<T>> {
    fn prev_timestamp(&self) -> &T {
        &self.prev_timestamp
    }

    fn diff_16bit_limb(&self) -> &T {
        &self.diff_16bit_limb
    }

    fn diff_12bit_limb(&self) -> &T {
        &self.diff_12bit_limb
    }
}

impl<T> MemoryAccessTimestampCols<T> for MemoryAccessCols<T, T> {
    fn prev_timestamp(&self) -> &T {
        &self.prev_timestamp
    }

    fn diff_16bit_limb(&self) -> &T {
        &self.diff_16bit_limb
    }

    fn diff_12bit_limb(&self) -> &T {
        &self.diff_12bit_limb
    }
}

impl<T> MemoryCols<T, Block<T>> for MemoryReadCols<T> {
    fn access(&self) -> &MemoryAccessCols<T, Block<T>> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T, Block<T>> {
        &mut self.access
    }

    fn prev_value(&self) -> &Block<T> {
        &self.access.value
    }

    fn prev_value_mut(&mut self) -> &mut Block<T> {
        &mut self.access.value
    }

    fn value(&self) -> &Block<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Block<T> {
        &mut self.access.value
    }
}

impl<T> MemoryCols<T, Block<T>> for MemoryReadWriteCols<T> {
    fn access(&self) -> &MemoryAccessCols<T, Block<T>> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T, Block<T>> {
        &mut self.access
    }

    fn prev_value(&self) -> &Block<T> {
        &self.prev_value
    }

    fn prev_value_mut(&mut self) -> &mut Block<T> {
        &mut self.prev_value
    }

    fn value(&self) -> &Block<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Block<T> {
        &mut self.access.value
    }
}

impl<T> MemoryCols<T, T> for MemoryReadSingleCols<T> {
    fn access(&self) -> &MemoryAccessCols<T, T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T, T> {
        &mut self.access
    }

    fn prev_value(&self) -> &T {
        &self.access.value
    }

    fn prev_value_mut(&mut self) -> &mut T {
        &mut self.access.value
    }

    fn value(&self) -> &T {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut T {
        &mut self.access.value
    }
}

impl<T> MemoryCols<T, T> for MemoryReadWriteSingleCols<T> {
    fn access(&self) -> &MemoryAccessCols<T, T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T, T> {
        &mut self.access
    }

    fn prev_value(&self) -> &T {
        &self.prev_value
    }

    fn prev_value_mut(&mut self) -> &mut T {
        &mut self.prev_value
    }

    fn value(&self) -> &T {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut T {
        &mut self.access.value
    }
}
