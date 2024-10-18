use p3_field::{ExtensionField, PrimeField, PrimeField32, TwoAdicField};

mod arithmetic;
mod bits;
mod builder;
mod collections;
mod fold;
mod instructions;
mod poseidon;
mod ptr;
mod symbolic;
mod types;
mod utils;
mod var;

pub use arithmetic::*;
pub use builder::*;
pub use collections::*;
pub use fold::*;
pub use instructions::*;
pub use ptr::*;
pub use symbolic::*;
pub use types::*;
pub use var::*;

pub trait Config: Clone + Default {
    type N: PrimeField;
    type F: PrimeField32 + TwoAdicField;
    type EF: ExtensionField<Self::F> + TwoAdicField;
}
