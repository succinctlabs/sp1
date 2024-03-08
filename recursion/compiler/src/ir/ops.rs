use super::Bool;
use super::Builder;
use super::Variable;

pub trait Eq<B: Builder, Rhs = Self>: Variable<B> {
    fn eq(&self, other: Self, builder: &mut B) -> Bool;
}
