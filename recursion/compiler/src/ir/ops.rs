use super::Bool;
use super::Builder;
use super::Variable;

pub trait Eq<B: Builder, Rhs = Self>: Variable<B> {
    type Output;
    fn eq(&self, other: Self, builder: &mut B) -> Self::Output;
}
