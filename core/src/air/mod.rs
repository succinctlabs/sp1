mod bool;
mod word;

pub use bool::Bool;
use p3_air::AirBuilder;
use p3_field::AbstractField;
pub use word::Word;

/// An extension of the `AirBuilder` trait with additional methods for Curta types.
///
/// All `AirBuilder` implementations automatically implement this trait.
pub trait CurtaAirBuilder: AirBuilder {
    fn assert_is_valid<V: AirVariable<I>, I>(&mut self, value: V)
    where
        I: Into<Self::Expr>,
    {
        value.eval_is_valid(self);
    }

    fn assert_is_equal<V: AirVariable<I>, I>(&mut self, left: V, right: V)
    where
        I: Into<Self::Expr>,
    {
        left.eval_is_equal(right, self);
    }
}

impl<AB: AirBuilder> CurtaAirBuilder for AB {}

/// A trait for representing types in an AIR table that have validity constraints.
pub trait AirVariable<T> {
    /// The validity constraints for this type.
    fn eval_is_valid<AB: AirBuilder>(self, builder: &mut AB)
    where
        T: Into<AB::Expr>;

    fn eval_is_equal<AB: AirBuilder>(self, other: Self, builder: &mut AB)
    where
        T: Into<AB::Expr>;
}

pub fn reduce<AB: AirBuilder>(input: Word<AB::Var>) -> AB::Expr {
    let base = [1, 1 << 8, 1 << 16, 1 << 24].map(AB::Expr::from_canonical_u32);

    input
        .0
        .into_iter()
        .enumerate()
        .map(|(i, x)| base[i].clone() * x)
        .sum()
}
