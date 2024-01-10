use core::borrow::Borrow;
use core::borrow::BorrowMut;
use p3_field::Field;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;
use crate::air::Word;
use crate::bytes::utils::shr_carry;
use crate::bytes::ByteOpcode;
use crate::disassembler::WORD_SIZE;
use p3_field::AbstractField;

/// A set of columns needed to compute the xor of three operands
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Add4Operation<T> {
    /// The result of `a ^ b ^ c`.
    pub value: Word<T>,

    /// Trace.
    pub carry: [T; 3],
}

impl<F: Field> Add4Operation<F> {
    pub fn populate(&mut self, a: Word<F>, b: Word<F>, c: Word<F>, d: Word<F>) {
        let a = u32::from_le_bytes(a.0.map(|x| x.to_string().parse::<u8>().unwrap()));
        let b = u32::from_le_bytes(b.0.map(|x| x.to_string().parse::<u8>().unwrap()));
        let c = u32::from_le_bytes(c.0.map(|x| x.to_string().parse::<u8>().unwrap()));
        let d = u32::from_le_bytes(d.0.map(|x| x.to_string().parse::<u8>().unwrap()));
        self.value = Word::from(a + b + c + d);
    }

    pub fn eval<AB: CurtaAirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        c: Word<AB::Var>,
        d: Word<AB::Var>,
        cols: Add4Operation<AB::Var>,
    ) {
        // TODO:
    }
}
