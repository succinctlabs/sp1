mod bool;
mod word;

pub use bool::Bool;
use p3_air::AirBuilder;
use p3_field::AbstractField;
pub use word::Word;

/// A trait for representing types in an AIR table that have validity constraints.
pub trait AirVariable<AB: AirBuilder> {
    /// The number of elements in this type.
    fn size_of() -> usize;

    /// The validity constraints for this type.
    fn eval_is_valid(&self, builder: &mut AB);
}

/// A trait for representing constraints on an AIR table.
pub trait AirConstraint<AB: AirBuilder> {
    fn eval(&self, builder: &mut AB);
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
