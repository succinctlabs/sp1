#![no_std]

extern crate alloc;

pub mod asm;
pub mod builder;
pub mod ir;

pub mod prelude {
    pub use crate::asm::*;
    pub use crate::builder::*;
    pub use crate::ir::*;
}
