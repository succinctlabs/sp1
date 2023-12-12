mod bool;
mod word;

use p3_air::AirBuilder;

pub use bool::Bool;
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
