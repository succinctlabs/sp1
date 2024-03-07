mod arithmetic;
mod field;
mod int;
mod ptr;

use crate::builder::Builder;

pub use arithmetic::*;
pub use field::*;
pub use int::*;
pub use ptr::*;

pub trait Expression<B: Builder> {
    type Value;

    fn eval(&self, builder: &mut B) -> Self::Value;
}

pub trait Variable<B: Builder> {
    fn uninit(builder: &mut B) -> Self;
}

pub trait FromConstant<B: Builder>: SizedVariable<B> {
    type Constant;

    fn constant(builder: &mut B, value: Self::Constant) -> Self;
}

pub trait SizedVariable<B: Builder>: Variable<B> {
    fn size_of() -> usize;
}
