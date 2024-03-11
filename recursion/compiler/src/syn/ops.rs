use super::{variable::FromConstant, BaseBuilder, Expression};

use core::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Sub};

pub trait ArithmeticVariable<B: BaseBuilder>:
    FromConstant<B>
    + Add<Output = Self::Expression>
    + Sub<Output = Self::Expression>
    + Mul<Output = Self::Expression>
{
    type Expression: Expression<B, Value = Self>;
}

pub trait RingVariable<B: BaseBuilder>:
    ArithmeticVariable<B> + Neg<Output = Self::Expression>
{
    fn zero() -> Self::Constant;
    fn one() -> Self::Constant;
}

pub trait FieldVariable<B: BaseBuilder>: RingVariable<B> + Div<Output = Self::Expression> {}
