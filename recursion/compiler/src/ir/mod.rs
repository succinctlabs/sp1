use p3_field::{ExtensionField, Field};

mod builder;
mod heap;
mod instructions;
mod ops;
mod symbolic;
mod types;

pub use builder::*;
pub use heap::*;
pub use instructions::*;
pub use ops::*;
pub use symbolic::*;
pub use types::*;

pub trait Config: Clone {
    type N: Field;
    type F: Field;
    type EF: ExtensionField<Self::F>;
}
