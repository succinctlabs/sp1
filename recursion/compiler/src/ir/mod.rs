mod alu;
mod bool;
mod field;
mod int;
mod symbolic_field;
mod symbolic_int;

use crate::builder::Builder;

pub use alu::*;
pub use bool::*;
pub use field::*;
pub use int::*;
pub use symbolic_field::*;
pub use symbolic_int::*;

pub trait Expression<B: Builder> {
    type Value: Variable<B>;

    fn assign(&self, dst: Self::Value, builder: &mut B);
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
