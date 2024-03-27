use p3_field::{ExtensionField, PrimeField};

mod builder;
mod collections;
mod instructions;
mod ptr;
mod symbolic;
mod types;
mod utils;
mod var;

pub use builder::*;
pub use collections::*;
pub use instructions::*;
pub use ptr::*;
pub use symbolic::*;
pub use types::*;
pub use var::*;

pub trait Config: Clone {
    type N: PrimeField;
    type F: PrimeField;
    type EF: ExtensionField<Self::F>;
}
