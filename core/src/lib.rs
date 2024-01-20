#![allow(
    clippy::eq_op,
    clippy::new_without_default,
    clippy::field_reassign_with_default,
    clippy::unnecessary_cast,
    clippy::cast_abs_to_unsigned,
    clippy::needless_range_loop,
    clippy::type_complexity,
    clippy::unnecessary_unwrap
)]

pub mod air;
pub mod alu;
pub mod bytes;
pub mod cpu;
pub mod disassembler;
pub mod field;
pub mod lookup;
pub mod memory;
pub mod operations;
pub mod precompiles;
pub mod program;
pub mod runtime;
pub mod stark;
pub mod utils;

extern crate alloc;
