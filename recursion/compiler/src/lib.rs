#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]
extern crate alloc;

pub mod asm;
pub mod gnark;
pub mod ir;
pub mod util;

pub mod prelude {
    pub use crate::asm::AsmCompiler;
    pub use crate::ir::*;
    pub use sp1_recursion_derive::DslVariable;
}
