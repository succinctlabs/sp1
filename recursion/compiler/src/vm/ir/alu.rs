use super::Bool;
use crate::syn::Expression;
use crate::syn::FromConstant;
use crate::syn::Variable;
use crate::vm::AsmInstruction;
use crate::vm::VmBuilder;
use alloc::rc::Rc;
use core::ops::{BitAnd, BitOr, BitXor, Not};
use p3_field::AbstractField;

#[derive(Debug, Clone)]
pub enum SymbolicLogic {
    Const(bool),
    Value(Bool),
    And(Rc<SymbolicLogic>, Rc<SymbolicLogic>),
    Or(Rc<SymbolicLogic>, Rc<SymbolicLogic>),
    Xor(Rc<SymbolicLogic>, Rc<SymbolicLogic>),
    Not(Rc<SymbolicLogic>),
}

impl<B: VmBuilder> Expression<B> for SymbolicLogic {
    type Value = Bool;

    fn assign(&self, dst: Bool, builder: &mut B) {
        match self {
            SymbolicLogic::Const(b) => {
                dst.imm(*b, builder);
            }
            SymbolicLogic::Value(v) => {
                v.assign(dst, builder);
            }
            SymbolicLogic::And(lhs, rhs) => match (&**lhs, &**rhs) {
                (SymbolicLogic::Const(lhs), SymbolicLogic::Const(rhs)) => {
                    dst.imm(*lhs && *rhs, builder);
                }
                (SymbolicLogic::Const(true), rhs) => {
                    rhs.assign(dst, builder);
                }
                (SymbolicLogic::Const(false), _) => {
                    dst.imm(false, builder);
                }
                (lhs, SymbolicLogic::Const(true)) => {
                    lhs.assign(dst, builder);
                }
                (SymbolicLogic::Value(lhs), SymbolicLogic::Value(rhs)) => {
                    builder.push(AsmInstruction::MUL(dst.0, lhs.0, rhs.0));
                }
                (SymbolicLogic::Value(lhs), rhs) => {
                    let rhs_value = Bool::uninit(builder);
                    rhs.assign(rhs_value, builder);
                    builder.push(AsmInstruction::MUL(dst.0, lhs.0, rhs_value.0));
                }
                (lhs, SymbolicLogic::Value(rhs)) => {
                    let lhs_value = Bool::uninit(builder);
                    lhs.assign(lhs_value, builder);
                    builder.push(AsmInstruction::MUL(dst.0, lhs_value.0, rhs.0));
                }
                (lhs, rhs) => {
                    let lhs_value = Bool::uninit(builder);
                    lhs.assign(lhs_value, builder);
                    let rhs_value = Bool::uninit(builder);
                    rhs.assign(rhs_value, builder);
                    builder.push(AsmInstruction::MUL(dst.0, lhs_value.0, rhs_value.0));
                }
            },
            SymbolicLogic::Or(lhs, rhs) => {
                let or = |lhs: &Bool, rhs: &Bool, builder: &mut B| {
                    // Set sum = lhs + rhs.
                    let sum = Bool::uninit(builder);
                    builder.push(AsmInstruction::ADD(sum.0, lhs.0, rhs.0));
                    // Set and = lhs & rhs.
                    let and = Bool::uninit(builder);
                    builder.push(AsmInstruction::MUL(and.0, lhs.0, rhs.0));
                    // Set value = lhs + rhs - (lhs & rhs).
                    builder.push(AsmInstruction::SUB(dst.0, sum.0, and.0));
                };
                match (&**lhs, &**rhs) {
                    (SymbolicLogic::Const(lhs), SymbolicLogic::Const(rhs)) => {
                        dst.imm(*lhs || *rhs, builder);
                    }
                    (SymbolicLogic::Const(true), _) => {
                        dst.imm(true, builder);
                    }
                    (SymbolicLogic::Const(false), rhs) => {
                        rhs.assign(dst, builder);
                    }
                    (_, SymbolicLogic::Const(true)) => {
                        dst.imm(true, builder);
                    }
                    (SymbolicLogic::Value(lhs), SymbolicLogic::Value(rhs)) => {
                        or(lhs, rhs, builder);
                    }
                    (SymbolicLogic::Value(lhs), rhs) => {
                        let rhs_value = Bool::uninit(builder);
                        rhs.assign(rhs_value, builder);
                        or(lhs, &rhs_value, builder);
                    }
                    (lhs, SymbolicLogic::Value(rhs)) => {
                        let lhs_value = Bool::uninit(builder);
                        lhs.assign(lhs_value, builder);
                        or(&lhs_value, rhs, builder);
                    }
                    (lhs, rhs) => {
                        let lhs_value = Bool::uninit(builder);
                        lhs.assign(lhs_value, builder);
                        let rhs_value = Bool::uninit(builder);
                        rhs.assign(rhs_value, builder);
                        or(&lhs_value, &rhs_value, builder);
                    }
                }
            }
            SymbolicLogic::Xor(lhs, rhs) => {
                let xor = |lhs: &Bool, rhs: &Bool, builder: &mut B| {
                    // Set sum = lhs + rhs
                    let sum = Bool::uninit(builder);
                    builder.push(AsmInstruction::ADD(sum.0, lhs.0, rhs.0));
                    let two_times_and = Bool::uninit(builder);
                    // set two_times_and = (lhs & rhs)
                    builder.push(AsmInstruction::MUL(two_times_and.0, lhs.0, rhs.0));
                    // set two_times_and = 2 * (lhs & rhs)
                    builder.push(AsmInstruction::MULI(
                        two_times_and.0,
                        two_times_and.0,
                        B::F::two(),
                    ));
                    // Set value = lhs + rhs - 2 * (lhs & rhs)
                    builder.push(AsmInstruction::SUB(dst.0, sum.0, two_times_and.0));
                };
                match (&**lhs, &**rhs) {
                    (SymbolicLogic::Const(lhs), SymbolicLogic::Const(rhs)) => {
                        dst.imm(lhs ^ rhs, builder);
                    }
                    (SymbolicLogic::Const(true), SymbolicLogic::Value(rhs)) => {
                        // Set value = 1 - rhs
                        builder.push(AsmInstruction::SUBIN(dst.0, B::F::one(), rhs.0));
                    }
                    (SymbolicLogic::Const(true), rhs) => {
                        let rhs_value = Bool::uninit(builder);
                        rhs.assign(rhs_value, builder);
                        // Set value = 1 - rhs
                        builder.push(AsmInstruction::SUBIN(dst.0, B::F::one(), rhs_value.0));
                    }
                    (SymbolicLogic::Const(false), rhs) => {
                        rhs.assign(dst, builder);
                    }
                    (SymbolicLogic::Value(lhs), SymbolicLogic::Const(true)) => {
                        builder.push(AsmInstruction::SUBIN(dst.0, B::F::one(), lhs.0));
                    }
                    (lhs, SymbolicLogic::Const(true)) => {
                        let lhs_value = Bool::uninit(builder);
                        lhs.assign(lhs_value, builder);
                        builder.push(AsmInstruction::SUBIN(dst.0, B::F::one(), lhs_value.0));
                    }
                    (SymbolicLogic::Value(lhs), SymbolicLogic::Value(rhs)) => {
                        xor(lhs, rhs, builder);
                    }
                    (SymbolicLogic::Value(lhs), rhs) => {
                        let rhs_value = Bool::uninit(builder);
                        rhs.assign(rhs_value, builder);
                        xor(lhs, &rhs_value, builder);
                    }
                    (lhs, SymbolicLogic::Value(rhs)) => {
                        let lhs_value = Bool::uninit(builder);
                        lhs.assign(lhs_value, builder);
                        xor(&lhs_value, rhs, builder);
                    }
                    (lhs, rhs) => {
                        let lhs_value = Bool::uninit(builder);
                        lhs.assign(lhs_value, builder);
                        let rhs_value = Bool::uninit(builder);
                        rhs.assign(rhs_value, builder);
                        xor(&lhs_value, &rhs_value, builder);
                    }
                }
            }
            SymbolicLogic::Not(inner) => {
                (SymbolicLogic::from(true) ^ (**inner).clone()).assign(dst, builder);
            }
        }
    }
}

impl From<bool> for SymbolicLogic {
    fn from(b: bool) -> Self {
        SymbolicLogic::Const(b)
    }
}

impl From<Bool> for SymbolicLogic {
    fn from(b: Bool) -> Self {
        SymbolicLogic::Value(b)
    }
}

impl BitAnd for SymbolicLogic {
    type Output = SymbolicLogic;

    fn bitand(self, rhs: Self) -> Self::Output {
        SymbolicLogic::And(Rc::new(self), Rc::new(rhs))
    }
}

impl BitAnd<Bool> for SymbolicLogic {
    type Output = SymbolicLogic;

    fn bitand(self, rhs: Bool) -> Self::Output {
        SymbolicLogic::And(Rc::new(self), Rc::new(SymbolicLogic::from(rhs)))
    }
}

impl BitAnd<bool> for SymbolicLogic {
    type Output = SymbolicLogic;

    fn bitand(self, rhs: bool) -> Self::Output {
        SymbolicLogic::And(Rc::new(self), Rc::new(SymbolicLogic::from(rhs)))
    }
}

impl BitOr for SymbolicLogic {
    type Output = SymbolicLogic;

    fn bitor(self, rhs: Self) -> Self::Output {
        SymbolicLogic::Or(Rc::new(self), Rc::new(rhs))
    }
}

impl BitOr<Bool> for SymbolicLogic {
    type Output = SymbolicLogic;

    fn bitor(self, rhs: Bool) -> Self::Output {
        SymbolicLogic::Or(Rc::new(self), Rc::new(SymbolicLogic::from(rhs)))
    }
}

impl BitOr<bool> for SymbolicLogic {
    type Output = SymbolicLogic;

    fn bitor(self, rhs: bool) -> Self::Output {
        SymbolicLogic::Or(Rc::new(self), Rc::new(SymbolicLogic::from(rhs)))
    }
}

impl BitXor for SymbolicLogic {
    type Output = SymbolicLogic;

    fn bitxor(self, rhs: Self) -> Self::Output {
        SymbolicLogic::Xor(Rc::new(self), Rc::new(rhs))
    }
}

impl BitXor<Bool> for SymbolicLogic {
    type Output = SymbolicLogic;

    fn bitxor(self, rhs: Bool) -> Self::Output {
        SymbolicLogic::Xor(Rc::new(self), Rc::new(SymbolicLogic::from(rhs)))
    }
}

impl BitXor<bool> for SymbolicLogic {
    type Output = SymbolicLogic;

    fn bitxor(self, rhs: bool) -> Self::Output {
        SymbolicLogic::Xor(Rc::new(self), Rc::new(SymbolicLogic::from(rhs)))
    }
}

impl Not for SymbolicLogic {
    type Output = SymbolicLogic;

    fn not(self) -> Self::Output {
        SymbolicLogic::Not(Rc::new(self))
    }
}
