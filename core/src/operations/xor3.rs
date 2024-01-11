use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;
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
    pub fn populate(&mut self, a: Word<F>, b: Word<F>, c: Word<F>) {
        for i in 0..WORD_SIZE {
            let element_a = a[i].to_string().parse::<u8>().unwrap();
            let element_b = b[i].to_string().parse::<u8>().unwrap();
            let element_c = c[i].to_string().parse::<u8>().unwrap();
            self.intermeddiate[i] = F::from_canonical_u8(element_a ^ element_b);
            self.value[i] = F::from_canonical_u8(element_a ^ element_b ^ element_c);
        }
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
