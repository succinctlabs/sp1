#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]
#![warn(clippy::print_stdout)]

extern crate alloc;

pub mod circuit;
pub mod config;
pub mod constraints;
pub mod ir;

pub mod prelude {
    pub use crate::ir::*;
    pub use sp1_recursion_derive::DslVariable;
}
