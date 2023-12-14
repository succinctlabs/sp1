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
    fn assert_word_eq<I: Into<Self::Expr>>(&mut self, left: Word<I>, right: Word<I>) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }

    fn assert_is_bool<I: Into<Self::Expr>>(&mut self, value: Bool<I>) {
        self.assert_bool(value.0);
    }
}

impl<AB: AirBuilder> CurtaAirBuilder for AB {}

pub fn reduce<AB: AirBuilder>(input: Word<AB::Var>) -> AB::Expr {
    let base = [1, 1 << 8, 1 << 16, 1 << 24].map(AB::Expr::from_canonical_u32);

    input
        .0
        .into_iter()
        .enumerate()
        .map(|(i, x)| base[i].clone() * x)
        .sum()
}
