use super::BaseBuilder;
use core::borrow::Borrow;

pub struct Eq<A, B>(A, B);

pub trait Variable<B: BaseBuilder>: Copy {
    fn uninit(builder: &mut B) -> Self;

    fn eq(&self, other: impl Borrow<Self>) -> Eq<Self, Self> {
        Eq(*self, *other.borrow())
    }
}

pub trait FromConstant<B: BaseBuilder>: Variable<B> {
    type Constant: Sized;

    fn imm(&self, constant: Self::Constant, builder: &mut B);
}

pub trait Expression<B: BaseBuilder> {
    type Value: Variable<B>;

    fn assign(&self, dst: Self::Value, builder: &mut B);
}

pub trait SizedVariable<B: BaseBuilder>: Variable<B> {
    fn size_of() -> usize;
}
