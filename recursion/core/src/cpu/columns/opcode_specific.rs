use std::fmt::{Debug, Formatter};
use std::mem::{size_of, transmute};

use static_assertions::const_assert;

use super::branch::BranchCols;
use super::heap_expand::HeapExpandCols;
use super::memory::MemoryCols;
use super::public_values::PublicValuesCols;

pub const NUM_OPCODE_SPECIFIC_COLS: usize = size_of::<OpcodeSpecificCols<u8>>();

/// Shared columns whose interpretation depends on the instruction being executed.
#[derive(Clone, Copy)]
#[repr(C)]
pub union OpcodeSpecificCols<T: Copy> {
    branch: BranchCols<T>,
    memory: MemoryCols<T>,
    public_values: PublicValuesCols<T>,
    heap_expand: HeapExpandCols<T>,
}

impl<T: Copy + Default> Default for OpcodeSpecificCols<T> {
    fn default() -> Self {
        // We must use the largest field to avoid uninitialized padding bytes.
        const_assert!(size_of::<MemoryCols<u8>>() == size_of::<OpcodeSpecificCols<u8>>());

        OpcodeSpecificCols {
            memory: MemoryCols::<T>::default(),
        }
    }
}

impl<T: Copy + Debug> Debug for OpcodeSpecificCols<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        // SAFETY: repr(C) ensures uniform fields are in declaration order with no padding.
        let self_arr: &[T; NUM_OPCODE_SPECIFIC_COLS] = unsafe { transmute(self) };
        Debug::fmt(self_arr, f)
    }
}

// SAFETY: Each view is a valid interpretation of the underlying array.
impl<T: Copy> OpcodeSpecificCols<T> {
    pub fn branch(&self) -> &BranchCols<T> {
        unsafe { &self.branch }
    }
    pub fn branch_mut(&mut self) -> &mut BranchCols<T> {
        unsafe { &mut self.branch }
    }

    pub fn memory(&self) -> &MemoryCols<T> {
        unsafe { &self.memory }
    }

    pub fn memory_mut(&mut self) -> &mut MemoryCols<T> {
        unsafe { &mut self.memory }
    }

    pub fn public_values(&self) -> &PublicValuesCols<T> {
        unsafe { &self.public_values }
    }

    pub fn public_values_mut(&mut self) -> &mut PublicValuesCols<T> {
        unsafe { &mut self.public_values }
    }

    pub fn heap_expand(&self) -> &HeapExpandCols<T> {
        unsafe { &self.heap_expand }
    }

    pub fn heap_expand_mut(&mut self) -> &mut HeapExpandCols<T> {
        unsafe { &mut self.heap_expand }
    }
}
