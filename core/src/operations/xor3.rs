use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;
use std::mem::size_of;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::disassembler::WORD_SIZE;

/// A set of columns needed to compute the xor of three operands
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Xor3Operation<T> {
    /// The result of `a ^ b ^ c`.
    pub value: Word<T>,

    /// The result of `a ^ b`.
    pub intermeddiate: Word<T>,
}

impl<F: Field> Xor3Operation<F> {
    pub fn populate(&mut self, a: u32, b: u32, c: u32) -> u32 {
        let expected = a ^ b ^ c;
        let a_bytes = a.to_le_bytes();
        let b_bytes = b.to_le_bytes();
        let c_bytes = c.to_le_bytes();
        for i in 0..WORD_SIZE {
            self.intermeddiate[i] = F::from_canonical_u8(a_bytes[i] ^ b_bytes[i]);
            self.value[i] = F::from_canonical_u8(a_bytes[i] ^ b_bytes[i] ^ c_bytes[i]);
        }
        expected
    }

    #[allow(unused_variables)]
    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        c: Word<AB::Var>,
        cols: Xor3Operation<AB::Var>,
    ) {
        // TODO:
    }
}
