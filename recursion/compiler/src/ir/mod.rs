mod alu;
mod arithmetic;
mod bool;
mod field;
mod int;
mod ptr;

use crate::builder::Builder;

pub use alu::*;
pub use arithmetic::*;
pub use bool::*;
pub use field::*;
pub use int::*;
pub use ptr::*;

pub trait Expression<B: Builder> {
    type Value;

    fn assign(&self, value: Self::Value, builder: &mut B);
}

pub trait Variable<B: Builder>: Sized + Copy {
    fn uninit(builder: &mut B) -> Self;
}

pub trait Constant<B: Builder>: Variable<B> {
    type Constant: Sized;

    fn imm(&self, constant: Self::Constant, builder: &mut B);
}

pub trait SizedVariable<B: Builder>: Variable<B> {
    fn size_of() -> usize;
}
