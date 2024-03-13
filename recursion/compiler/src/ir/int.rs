use core::marker::PhantomData;

use super::Builder;
use crate::asm::AsmInstruction;
use crate::ir::Felt;
use crate::ir::SymbolicInt;
use crate::ir::{Constant, Expression, SizedVariable, Variable};
use core::ops::{Add, Mul, Sub};
use p3_field::{AbstractField, PrimeField32};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Int(pub(crate) i32);

impl<B: Builder> Variable<B> for Int {
    fn uninit(builder: &mut B) -> Self {
        Int(builder.get_mem(4))
    }
}

impl<B: Builder> SizedVariable<B> for Int {
    fn size_of() -> usize {
        1
    }
}

impl<B: Builder> Expression<B> for Int {
    type Value = Int;

    fn assign(&self, value: Int, builder: &mut B) {
        builder.push(AsmInstruction::ADDI(value.0, self.0, B::F::zero()));
    }
}

impl<B: Builder> Constant<B> for Int {
    type Constant = u32;

    fn imm(&self, constant: Self::Constant, builder: &mut B) {
        let constant = B::F::from_canonical_u32(constant);
        builder.push(AsmInstruction::IMM(self.0, constant));
    }
}

impl<F: PrimeField32> From<Int> for Felt<F> {
    fn from(value: Int) -> Self {
        Felt(value.0, PhantomData)
    }
}

impl Add for Int {
    type Output = SymbolicInt;

    fn add(self, rhs: Self) -> SymbolicInt {
        SymbolicInt::from(self) + rhs
    }
}

impl Add<SymbolicInt> for Int {
    type Output = SymbolicInt;

    fn add(self, rhs: SymbolicInt) -> SymbolicInt {
        SymbolicInt::from(self) + rhs
    }
}

impl Sub for Int {
    type Output = SymbolicInt;

    fn sub(self, rhs: Self) -> SymbolicInt {
        SymbolicInt::from(self) - rhs
    }
}

impl Sub<SymbolicInt> for Int {
    type Output = SymbolicInt;

    fn sub(self, rhs: SymbolicInt) -> SymbolicInt {
        SymbolicInt::from(self) - rhs
    }
}

impl Mul for Int {
    type Output = SymbolicInt;

    fn mul(self, rhs: Self) -> SymbolicInt {
        SymbolicInt::from(self) * rhs
    }
}

impl Mul<SymbolicInt> for Int {
    type Output = SymbolicInt;

    fn mul(self, rhs: SymbolicInt) -> SymbolicInt {
        SymbolicInt::from(self) * rhs
    }
}
