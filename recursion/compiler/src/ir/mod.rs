use p3_field::{extension::BinomiallyExtendable, Field};

mod builder;
mod collections;
mod instructions;
mod ptr;
mod symbolic;
mod types;
mod var;

pub use builder::*;
pub use collections::*;
pub use instructions::*;
pub use ptr::*;
pub use symbolic::*;
pub use types::*;
pub use var::*;

pub trait Config: Clone {
    type N: Field;
    type F: Field + BinomiallyExtendable<D>;
}
