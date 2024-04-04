use p3_field::{ExtensionField, PrimeField, TwoAdicField};

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
    type F: PrimeField + TwoAdicField;
    type EF: ExtensionField<Self::F> + TwoAdicField;
}
