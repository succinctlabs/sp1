mod arithmetic;
mod field;
mod int;
mod ptr;

use crate::asm::Instruction;
use crate::builder::Builder;

pub use arithmetic::*;
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

pub trait Constant<B: Builder>: Sized {
    type Value: Variable<B>;

    fn imm(&self, value: Self::Value, builder: &mut B);
}

pub trait SizedVariable<B: Builder>: Variable<B> {
    fn size_of() -> usize;
}

impl<B: Builder> Constant<B> for B::F {
    type Value = Felt<B::F>;

    fn imm(&self, value: Self::Value, builder: &mut B) {
        builder.push(Instruction::IMM(value.0, *self));
    }
}
