use crate::asm::Instruction;
use crate::ir::*;
use alloc::rc::Rc;

pub enum ArithmeticExpression<T> {
    Value(T),
    Add(Rc<ArithmeticExpression<T>>, Rc<ArithmeticExpression<T>>),
    Mul(Rc<ArithmeticExpression<T>>, Rc<ArithmeticExpression<T>>),
    Sub(Rc<ArithmeticExpression<T>>, Rc<ArithmeticExpression<T>>),
    Div(Rc<ArithmeticExpression<T>>, Rc<ArithmeticExpression<T>>),
    Neg(Rc<ArithmeticExpression<T>>),
}

impl<B: Builder> Expression<B> for ArithmeticExpression<F> {
    type Value = F;

    fn eval(&self, builder: &mut B) -> F {
        match self {
            ArithmeticExpression::Value(value) => *value,
            ArithmeticExpression::Add(lhs, rhs) => {
                let lhs = lhs.eval(builder);
                let rhs = rhs.eval(builder);
                let rs = F::uninit(builder);

                builder.push(Instruction::ADD(rs, lhs, rhs));

                rs
            }
            ArithmeticExpression::Mul(lhs, rhs) => {
                let lhs = lhs.eval(builder);
                let rhs = rhs.eval(builder);
                let rs = F::uninit(builder);

                builder.push(Instruction::MUL(rs, lhs, rhs));

                rs
            }
            ArithmeticExpression::Sub(lhs, rhs) => {
                let lhs = lhs.eval(builder);
                let rhs = rhs.eval(builder);
                let rs = F::uninit(builder);

                builder.push(Instruction::SUB(rs, lhs, rhs));

                rs
            }
            ArithmeticExpression::Div(lhs, rhs) => {
                let lhs = lhs.eval(builder);
                let rhs = rhs.eval(builder);
                let rs = F::uninit(builder);

                builder.push(Instruction::DIV(rs, lhs, rhs));

                rs
            }
            _ => todo!(),
        }
    }
}
