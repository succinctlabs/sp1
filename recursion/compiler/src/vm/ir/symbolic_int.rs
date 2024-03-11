use super::*;
use crate::syn::Expression;
use crate::syn::{FromConstant, Variable};
use crate::vm::AsmInstruction;
use crate::vm::VmBuilder;
use alloc::rc::Rc;
use core::ops::{Add, Mul, Sub};
use p3_field::{AbstractField, PrimeField32};

#[derive(Debug, Clone)]
pub enum SymbolicInt {
    Const(u32),
    Value(Int),
    Add(Rc<SymbolicInt>, Rc<SymbolicInt>),
    Mul(Rc<SymbolicInt>, Rc<SymbolicInt>),
    Sub(Rc<SymbolicInt>, Rc<SymbolicInt>),
}

impl<B: VmBuilder> Expression<B> for SymbolicInt {
    type Value = Int;

    fn assign(&self, dst: Int, builder: &mut B) {
        match self {
            SymbolicInt::Const(c) => {
                dst.imm(*c, builder);
            }
            SymbolicInt::Value(v) => {
                v.assign(dst, builder);
            }
            SymbolicInt::Add(lhs, rhs) => match (&**lhs, &**rhs) {
                (SymbolicInt::Const(lhs), SymbolicInt::Const(rhs)) => {
                    let sum = *lhs + *rhs;
                    let sum = B::F::from_canonical_u32(sum);
                    builder.push(AsmInstruction::IMM(dst.0, sum));
                }
                (SymbolicInt::Const(lhs), SymbolicInt::Value(rhs)) => {
                    let lhs = B::F::from_canonical_u32(*lhs);
                    builder.push(AsmInstruction::ADDI(dst.0, rhs.0, lhs));
                }
                (SymbolicInt::Const(lhs), rhs) => {
                    let rhs_value = Int::uninit(builder);
                    rhs.assign(rhs_value, builder);
                    let lhs = B::F::from_canonical_u32(*lhs);
                    builder.push(AsmInstruction::ADDI(dst.0, rhs_value.0, lhs));
                }
                (SymbolicInt::Value(lhs), SymbolicInt::Const(rhs)) => {
                    let rhs = B::F::from_canonical_u32(*rhs);
                    builder.push(AsmInstruction::ADDI(dst.0, lhs.0, rhs));
                }
                (SymbolicInt::Value(lhs), SymbolicInt::Value(rhs)) => {
                    builder.push(AsmInstruction::ADD(dst.0, lhs.0, rhs.0));
                }
                (SymbolicInt::Value(lhs), rhs) => {
                    let rhs_value = Int::uninit(builder);
                    rhs.assign(rhs_value, builder);
                    builder.push(AsmInstruction::ADD(dst.0, lhs.0, rhs_value.0));
                }
                (lhs, SymbolicInt::Const(rhs)) => {
                    let lhs_value = Int::uninit(builder);
                    lhs.assign(lhs_value, builder);
                    let rhs = B::F::from_canonical_u32(*rhs);
                    builder.push(AsmInstruction::ADDI(dst.0, lhs_value.0, rhs));
                }
                (lhs, SymbolicInt::Value(rhs)) => {
                    let lhs_value = Int::uninit(builder);
                    lhs.assign(lhs_value, builder);
                    builder.push(AsmInstruction::ADD(dst.0, lhs_value.0, rhs.0));
                }
                (lhs, rhs) => {
                    let lhs_value = Int::uninit(builder);
                    lhs.assign(lhs_value, builder);
                    let rhs_value = Int::uninit(builder);
                    rhs.assign(rhs_value, builder);
                    builder.push(AsmInstruction::ADD(dst.0, lhs_value.0, rhs_value.0));
                }
            },
            SymbolicInt::Mul(lhs, rhs) => match (&**lhs, &**rhs) {
                (SymbolicInt::Const(lhs), SymbolicInt::Const(rhs)) => {
                    let product = *lhs * *rhs;
                    let product = B::F::from_canonical_u32(product);
                    builder.push(AsmInstruction::IMM(dst.0, product));
                }
                (SymbolicInt::Const(lhs), SymbolicInt::Value(rhs)) => {
                    let lhs = B::F::from_canonical_u32(*lhs);
                    builder.push(AsmInstruction::MULI(dst.0, rhs.0, lhs));
                }
                (SymbolicInt::Const(lhs), rhs) => {
                    let rhs_value = Int::uninit(builder);
                    rhs.assign(rhs_value, builder);
                    let lhs = B::F::from_canonical_u32(*lhs);
                    builder.push(AsmInstruction::MULI(dst.0, rhs_value.0, lhs));
                }
                (SymbolicInt::Value(lhs), SymbolicInt::Const(rhs)) => {
                    let rhs = B::F::from_canonical_u32(*rhs);
                    builder.push(AsmInstruction::MULI(dst.0, lhs.0, rhs));
                }
                (SymbolicInt::Value(lhs), SymbolicInt::Value(rhs)) => {
                    builder.push(AsmInstruction::MUL(dst.0, lhs.0, rhs.0));
                }
                (SymbolicInt::Value(lhs), rhs) => {
                    let rhs_value = Int::uninit(builder);
                    rhs.assign(rhs_value, builder);
                    builder.push(AsmInstruction::MUL(dst.0, lhs.0, rhs_value.0));
                }
                (lhs, SymbolicInt::Const(rhs)) => {
                    let lhs_value = Int::uninit(builder);
                    lhs.assign(lhs_value, builder);
                    let rhs = B::F::from_canonical_u32(*rhs);
                    builder.push(AsmInstruction::MULI(dst.0, lhs_value.0, rhs));
                }
                (lhs, SymbolicInt::Value(rhs)) => {
                    let lhs_value = Int::uninit(builder);
                    lhs.assign(lhs_value, builder);
                    builder.push(AsmInstruction::MUL(dst.0, lhs_value.0, rhs.0));
                }
                (lhs, rhs) => {
                    let lhs_value = Int::uninit(builder);
                    lhs.assign(lhs_value, builder);
                    let rhs_value = Int::uninit(builder);
                    rhs.assign(rhs_value, builder);
                    builder.push(AsmInstruction::MUL(dst.0, lhs_value.0, rhs_value.0));
                }
            },
            SymbolicInt::Sub(lhs, rhs) => match (&**lhs, &**rhs) {
                (SymbolicInt::Const(lhs), SymbolicInt::Const(rhs)) => {
                    let difference = *lhs - *rhs;
                    let difference = B::F::from_canonical_u32(difference);
                    builder.push(AsmInstruction::IMM(dst.0, difference));
                }
                (SymbolicInt::Const(lhs), SymbolicInt::Value(rhs)) => {
                    let lhs = B::F::from_canonical_u32(*lhs);
                    builder.push(AsmInstruction::SUBIN(dst.0, lhs, rhs.0));
                }
                (SymbolicInt::Const(lhs), rhs) => {
                    let rhs_value = Int::uninit(builder);
                    rhs.assign(rhs_value, builder);
                    let lhs = B::F::from_canonical_u32(*lhs);
                    builder.push(AsmInstruction::SUBIN(dst.0, lhs, rhs_value.0));
                }
                (SymbolicInt::Value(lhs), SymbolicInt::Const(rhs)) => {
                    let rhs = B::F::from_canonical_u32(*rhs);
                    builder.push(AsmInstruction::SUBI(dst.0, lhs.0, rhs));
                }
                (SymbolicInt::Value(lhs), SymbolicInt::Value(rhs)) => {
                    builder.push(AsmInstruction::SUB(dst.0, lhs.0, rhs.0));
                }
                (SymbolicInt::Value(lhs), rhs) => {
                    let rhs_value = Int::uninit(builder);
                    rhs.assign(rhs_value, builder);
                    builder.push(AsmInstruction::SUB(dst.0, lhs.0, rhs_value.0));
                }
                (lhs, SymbolicInt::Const(rhs)) => {
                    let lhs_value = Int::uninit(builder);
                    lhs.assign(lhs_value, builder);
                    let rhs = B::F::from_canonical_u32(*rhs);
                    builder.push(AsmInstruction::SUBI(dst.0, lhs_value.0, rhs));
                }
                (lhs, SymbolicInt::Value(rhs)) => {
                    let lhs_value = Int::uninit(builder);
                    lhs.assign(lhs_value, builder);
                    builder.push(AsmInstruction::SUB(dst.0, lhs_value.0, rhs.0));
                }
                (lhs, rhs) => {
                    let lhs_value = Int::uninit(builder);
                    lhs.assign(lhs_value, builder);
                    let rhs_value = Int::uninit(builder);
                    rhs.assign(rhs_value, builder);
                    builder.push(AsmInstruction::SUB(dst.0, lhs_value.0, rhs_value.0));
                }
            },
        }
    }
}

impl SymbolicInt {
    fn symbolic_field<F: PrimeField32>(&self) -> Symbolic<F> {
        match self {
            SymbolicInt::Const(c) => Symbolic::Const(F::from_canonical_u32(*c)),
            SymbolicInt::Value(v) => Symbolic::Value((*v).into()),
            SymbolicInt::Add(lhs, rhs) => lhs.symbolic_field::<F>() + rhs.symbolic_field::<F>(),
            SymbolicInt::Mul(lhs, rhs) => lhs.symbolic_field::<F>() * rhs.symbolic_field::<F>(),
            SymbolicInt::Sub(lhs, rhs) => lhs.symbolic_field::<F>() - rhs.symbolic_field::<F>(),
        }
    }
}

impl From<Int> for SymbolicInt {
    fn from(value: Int) -> Self {
        SymbolicInt::Value(value)
    }
}

impl From<u32> for SymbolicInt {
    fn from(value: u32) -> Self {
        SymbolicInt::Const(value)
    }
}

impl Add for SymbolicInt {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        SymbolicInt::Add(Rc::new(self), Rc::new(rhs))
    }
}

impl Mul for SymbolicInt {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        SymbolicInt::Mul(Rc::new(self), Rc::new(rhs))
    }
}

impl Sub for SymbolicInt {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        SymbolicInt::Sub(Rc::new(self), Rc::new(rhs))
    }
}

impl Add<Int> for SymbolicInt {
    type Output = Self;

    fn add(self, rhs: Int) -> Self {
        SymbolicInt::Add(Rc::new(self), Rc::new(SymbolicInt::Value(rhs)))
    }
}

impl Add<u32> for SymbolicInt {
    type Output = Self;

    fn add(self, rhs: u32) -> Self {
        SymbolicInt::Add(Rc::new(self), Rc::new(SymbolicInt::Const(rhs)))
    }
}

impl Mul<Int> for SymbolicInt {
    type Output = Self;

    fn mul(self, rhs: Int) -> Self {
        SymbolicInt::Mul(Rc::new(self), Rc::new(SymbolicInt::Value(rhs)))
    }
}

impl Mul<u32> for SymbolicInt {
    type Output = Self;

    fn mul(self, rhs: u32) -> Self {
        SymbolicInt::Mul(Rc::new(self), Rc::new(SymbolicInt::Const(rhs)))
    }
}

impl Sub<u32> for SymbolicInt {
    type Output = Self;

    fn sub(self, rhs: u32) -> Self {
        SymbolicInt::Sub(Rc::new(self), Rc::new(SymbolicInt::Const(rhs)))
    }
}

impl Sub<Int> for SymbolicInt {
    type Output = Self;

    fn sub(self, rhs: Int) -> Self {
        SymbolicInt::Sub(Rc::new(self), Rc::new(SymbolicInt::Value(rhs)))
    }
}

impl<F: PrimeField32> From<SymbolicInt> for Symbolic<F> {
    fn from(value: SymbolicInt) -> Self {
        value.symbolic_field()
    }
}

impl<F: PrimeField32> From<Int> for Symbolic<F> {
    fn from(value: Int) -> Self {
        Symbolic::Value(value.into())
    }
}
