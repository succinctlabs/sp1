use super::{variable::FromConstant, BaseBuilder, Expression};
use p3_field::Field;

use core::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Not, Sub};

pub trait FieldBuilder: BaseBuilder {
    type Felt: FieldVariable<Self>;
}

pub trait AlgebraicVariable<B: BaseBuilder>:
    FromConstant<B, Constant = Self::ArithConst>
    + Add<Output = Self::ArithExpr>
    + Sub<Output = Self::ArithExpr>
    + Mul<Output = Self::ArithExpr>
    + Neg<Output = Self::ArithExpr>
    + Add<Self::Constant, Output = Self::ArithExpr>
    + Sub<Self::Constant, Output = Self::ArithExpr>
    + Mul<Self::Constant, Output = Self::ArithExpr>
    + Add<Self::ArithExpr, Output = Self::ArithExpr>
    + Sub<Self::ArithExpr, Output = Self::ArithExpr>
    + Mul<Self::ArithExpr, Output = Self::ArithExpr>
{
    type ArithConst: Add<Output = Self>
        + Sub<Output = Self>
        + Mul<Output = Self>
        + Add<Self, Output = Self::ArithExpr>
        + Sub<Self, Output = Self::ArithExpr>
        + Mul<Self, Output = Self::ArithExpr>;

    type ArithExpr: Expression<B, Value = Self>
        + From<Self::Constant>
        + From<Self>
        + Add<Output = Self>
        + Sub<Output = Self>
        + Mul<Output = Self>
        + Neg<Output = Self>;

    fn zero() -> Self::Constant;

    fn one() -> Self::Constant;
}

pub trait FieldVariable<B: BaseBuilder>:
    AlgebraicVariable<B, ArithConst = Self::F, ArithExpr = Self::FieldExpr>
    + Div<Output = Self::ArithExpr>
{
    type F: Field;

    type FieldExpr: Div<Output = Self::ArithExpr>
        + Div<Self::Constant, Output = Self::ArithExpr>
        + Div<Self, Output = Self::ArithExpr>;
}

pub trait LogicalVariable<B: BaseBuilder>:
    FromConstant<B, Constant = Self::AluConst>
    + BitAnd<Output = Self::AluExpr>
    + BitOr<Output = Self::AluExpr>
    + BitXor<Output = Self::AluExpr>
    + Not<Output = Self::AluExpr>
    + BitAnd<Self::Constant, Output = Self::AluExpr>
    + BitOr<Self::Constant, Output = Self::AluExpr>
    + BitXor<Self::Constant, Output = Self::AluExpr>
    + Not<Output = Self::AluExpr>
    + BitAnd<Self::AluExpr, Output = Self::AluExpr>
    + BitOr<Self::AluExpr, Output = Self::AluExpr>
    + BitXor<Self::AluExpr, Output = Self::AluExpr>
{
    type AluConst: From<bool>;

    type AluExpr: Expression<B, Value = Self>
        + From<bool>
        + From<Self::Constant>
        + From<Self>
        + BitAnd<Output = Self>
        + BitOr<Output = Self>
        + BitXor<Output = Self>
        + Not<Output = Self>;
}
