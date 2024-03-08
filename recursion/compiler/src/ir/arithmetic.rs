use crate::asm::Instruction;
use crate::ir::*;
use alloc::rc::Rc;
use core::ops::{Add, Div, Mul, Neg, Sub};

#[derive(Debug, Clone)]
pub enum Symbolic<F> {
    Const(F),
    Value(Felt<F>),
    Add(Rc<Symbolic<F>>, Rc<Symbolic<F>>),
    Mul(Rc<Symbolic<F>>, Rc<Symbolic<F>>),
    Sub(Rc<Symbolic<F>>, Rc<Symbolic<F>>),
    Div(Rc<Symbolic<F>>, Rc<Symbolic<F>>),
    Neg(Rc<Symbolic<F>>),
}

impl<B: Builder> Expression<B> for Symbolic<B::F> {
    type Value = Felt<B::F>;

    fn assign(&self, value: Felt<B::F>, builder: &mut B) {
        match self {
            Symbolic::Value(v) => {
                v.assign(value, builder);
            }
            Symbolic::Add(lhs, rhs) => {
                match (&**lhs, &**rhs) {
                    (Symbolic::Const(lhs), Symbolic::Const(rhs)) => {
                        let sum = *lhs + *rhs;
                        builder.push(Instruction::IMM(value.0, sum));
                    }
                    (Symbolic::Const(lhs), Symbolic::Value(rhs)) => {
                        builder.push(Instruction::ADDI(value.0, rhs.0, *lhs));
                    }
                    (Symbolic::Const(lhs), rhs) => {
                        let rhs_value = Felt::uninit(builder);
                        rhs.assign(rhs_value, builder);
                        builder.push(Instruction::ADDI(value.0, rhs_value.0, *lhs));
                    }
                    (Symbolic::Value(lhs), Symbolic::Const(rhs)) => {
                        builder.push(Instruction::ADDI(value.0, lhs.0, *rhs));
                    }
                    (Symbolic::Value(lhs), Symbolic::Value(rhs)) => {
                        builder.push(Instruction::ADD(value.0, lhs.0, rhs.0));
                    }
                    (Symbolic::Value(lhs), rhs) => {
                        let rhs_value = Felt::uninit(builder);
                        rhs.assign(rhs_value, builder);
                        builder.push(Instruction::ADD(value.0, lhs.0, rhs_value.0));
                    }
                    (lhs, Symbolic::Const(rhs)) => {
                        let lhs_value = Felt::uninit(builder);
                        lhs.assign(lhs_value, builder);
                        builder.push(Instruction::ADDI(value.0, lhs_value.0, *rhs));
                    }
                    (lhs, Symbolic::Value(rhs)) => {
                        let lhs_value = Felt::uninit(builder);
                        lhs.assign(lhs_value, builder);
                        builder.push(Instruction::ADD(value.0, lhs_value.0, rhs.0));
                    }
                    (lhs, rhs) => {
                        let lhs_value = Felt::uninit(builder);
                        lhs.assign(lhs_value, builder);
                        let rhs_value = Felt::uninit(builder);
                        rhs.assign(rhs_value, builder);
                        builder.push(Instruction::ADD(value.0, lhs_value.0, rhs_value.0));
                    }
                }
                // let lhs = match lhs.as_ref() {
                //     Symbolic::Value(v) => *v,
                //     _ => {
                //         let lhs_value = F::uninit(builder);
                //         lhs.assign(lhs_value, builder);
                //         lhs_value
                //     }
                // };
                // let rhs = match rhs.as_ref() {
                //     Symbolic::Value(v) => *v,
                //     _ => {
                //         let rhs_value = F::uninit(builder);
                //         rhs.assign(rhs_value, builder);
                //         rhs_value
                //     }
                // };
                // builder.push(Instruction::ADD(value.0, lhs.0, rhs.0));
            }
            _ => todo!(),
        }
    }
}

impl<F> From<Felt<F>> for Symbolic<F> {
    fn from(value: Felt<F>) -> Self {
        Symbolic::Value(value)
    }
}

impl<F> Add for Symbolic<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Symbolic::Add(Rc::new(self), Rc::new(rhs))
    }
}

impl<F> Mul for Symbolic<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Symbolic::Mul(Rc::new(self), Rc::new(rhs))
    }
}

impl<F> Sub for Symbolic<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Symbolic::Sub(Rc::new(self), Rc::new(rhs))
    }
}

impl<F> Div for Symbolic<F> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        Symbolic::Div(Rc::new(self), Rc::new(rhs))
    }
}

impl<F> Neg for Symbolic<F> {
    type Output = Self;

    fn neg(self) -> Self {
        Symbolic::Neg(Rc::new(self))
    }
}

impl<F> Add<Felt<F>> for Symbolic<F> {
    type Output = Self;

    fn add(self, rhs: Felt<F>) -> Self {
        Symbolic::Add(Rc::new(self), Rc::new(Symbolic::Value(rhs)))
    }
}

impl<F> Mul<Felt<F>> for Symbolic<F> {
    type Output = Self;

    fn mul(self, rhs: Felt<F>) -> Self {
        Symbolic::Mul(Rc::new(self), Rc::new(Symbolic::Value(rhs)))
    }
}

impl<F> Sub<Felt<F>> for Symbolic<F> {
    type Output = Self;

    fn sub(self, rhs: Felt<F>) -> Self {
        Symbolic::Sub(Rc::new(self), Rc::new(Symbolic::Value(rhs)))
    }
}

impl<F> Div<Felt<F>> for Symbolic<F> {
    type Output = Self;

    fn div(self, rhs: Felt<F>) -> Self {
        Symbolic::Div(Rc::new(self), Rc::new(Symbolic::Value(rhs)))
    }
}
