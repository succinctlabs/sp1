use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::PrimeField;
use p3_field::PrimeField32;
use valida_derive::AlignedBorrow;

use crate::bytes::utils::shr_carry;
use crate::disassembler::WORD_SIZE;

use super::Word;

#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
pub struct IsZeroCols<T> {
    pub out: T,
    pub inv: T,
}

#[derive(AlignedBorrow, Default, Debug)]
#[repr(C)]
pub struct IsEqualCols<T> {
    pub out: T,
    pub inv: T,
}
