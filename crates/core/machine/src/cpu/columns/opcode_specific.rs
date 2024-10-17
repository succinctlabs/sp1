use crate::cpu::columns::{AuipcCols, BranchCols, JumpCols, MemoryColumns};
use std::{
    fmt::{Debug, Formatter},
    mem::{size_of, transmute},
};

use sp1_derive::AlignedBorrow;
use sp1_stark::Word;
use static_assertions::const_assert;

use super::ecall::EcallCols;

pub const NUM_OPCODE_SPECIFIC_COLS: usize = size_of::<OpcodeSpecificCols<u8>>();

/// Shared columns whose interpretation depends on the instruction being executed.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub union OpcodeSpecificCols<T: Copy> {
    memory: MemoryColumns<T>,
    branch: BranchCols<T>,
    jump: JumpCols<T>,
    auipc: AuipcCols<T>,
    ecall: EcallCols<T>,
}

impl<T: Copy + Default> Default for OpcodeSpecificCols<T> {
    fn default() -> Self {
        // We must use the largest field to avoid uninitialized padding bytes.
        const_assert!(size_of::<MemoryColumns<u8>>() == size_of::<OpcodeSpecificCols<u8>>());

        OpcodeSpecificCols { memory: MemoryColumns::default() }
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
    pub fn memory(&self) -> &MemoryColumns<T> {
        unsafe { &self.memory }
    }
    pub fn memory_mut(&mut self) -> &mut MemoryColumns<T> {
        unsafe { &mut self.memory }
    }
    pub fn branch(&self) -> &BranchCols<T> {
        unsafe { &self.branch }
    }
    pub fn branch_mut(&mut self) -> &mut BranchCols<T> {
        unsafe { &mut self.branch }
    }
    pub fn jump(&self) -> &JumpCols<T> {
        unsafe { &self.jump }
    }
    pub fn jump_mut(&mut self) -> &mut JumpCols<T> {
        unsafe { &mut self.jump }
    }
    pub fn auipc(&self) -> &AuipcCols<T> {
        unsafe { &self.auipc }
    }
    pub fn auipc_mut(&mut self) -> &mut AuipcCols<T> {
        unsafe { &mut self.auipc }
    }
    pub fn ecall(&self) -> &EcallCols<T> {
        unsafe { &self.ecall }
    }
    pub fn ecall_mut(&mut self) -> &mut EcallCols<T> {
        unsafe { &mut self.ecall }
    }
    pub fn most_significant_byte(&self) -> T {
        self.memory().most_significant_byte()
    }
    pub fn word_for_range_check(&self) -> Word<T> {
        self.memory().addr_word
    }
    pub fn range_check_bit(&self) -> T {
        self.memory().range_check_bit()
    }
    pub fn set_range_check_bit(&mut self, new_val: T) {
        self.memory_mut().addr_word_range_checker = new_val;
    }
}
