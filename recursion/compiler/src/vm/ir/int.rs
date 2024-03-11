use core::marker::PhantomData;

use super::Felt;
use super::SymbolicInt;
use crate::syn::{Expression, FromConstant, SizedVariable, Variable};
use crate::vm::AsmInstruction;
use crate::vm::VmBuilder;
use core::ops::{Add, Mul, Sub};
use p3_field::{AbstractField, PrimeField32};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Int(pub(crate) i32);

impl<B: VmBuilder> Variable<B> for Int {
    fn uninit(builder: &mut B) -> Self {
        Int(builder.get_mem(4))
    }
}

impl<B: VmBuilder> SizedVariable<B> for Int {
    fn size_of() -> usize {
        1
    }
}

impl<B: VmBuilder> Expression<B> for Int {
    type Value = Int;

    fn assign(&self, value: Int, builder: &mut B) {
        builder.push(AsmInstruction::ADDI(value.0, self.0, B::F::zero()));
    }
}

impl<B: VmBuilder> FromConstant<B> for Int {
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
