use std::borrow::BorrowMut;

use sp1_derive::AlignedBorrow;

pub(crate) const OPCODE_COUNT: usize = core::mem::size_of::<OpcodeSelectorCols<u8>>();

/// Selectors for the opcode.
///
/// This contains selectors for the different opcodes corresponding to variants of the [`Opcode`]
/// enum.
#[derive(AlignedBorrow, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct OpcodeSelectorCols<T> {
    // Arithmetic field instructions.
    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
    pub is_div: T,
    pub is_ext: T,

    // Memory instructions.
    pub is_load: T,
    pub is_store: T,

    // Branch instructions.
    pub is_beq: T,
    pub is_bne: T,
    pub is_bneinc: T,

    // Jump instructions.
    pub is_jal: T,
    pub is_jalr: T,

    // System instructions.
    pub is_trap: T,
    pub is_noop: T,
    pub is_halt: T,

    pub is_poseidon: T,
    pub is_fri_fold: T,
    pub is_commit: T,
    pub is_ext_to_felt: T,
    pub is_exp_reverse_bits_len: T,
    pub is_heap_expand: T,
}

impl<T: Copy> IntoIterator for &OpcodeSelectorCols<T> {
    type Item = T;

    type IntoIter = std::array::IntoIter<T, OPCODE_COUNT>;

    fn into_iter(self) -> Self::IntoIter {
        let mut array = [self.is_add; OPCODE_COUNT];
        let mut_ref: &mut OpcodeSelectorCols<T> = array.as_mut_slice().borrow_mut();

        *mut_ref = *self;
        array.into_iter()
    }
}
