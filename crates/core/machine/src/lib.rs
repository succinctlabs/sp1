#![allow(
    clippy::new_without_default,
    clippy::field_reassign_with_default,
    clippy::unnecessary_cast,
    clippy::cast_abs_to_unsigned,
    clippy::needless_range_loop,
    clippy::type_complexity,
    clippy::unnecessary_unwrap,
    clippy::default_constructed_unit_structs,
    clippy::box_default,
    clippy::assign_op_pattern,
    deprecated,
    incomplete_features
)]
#![warn(unused_extern_crates)]

pub mod air;
pub mod alu;
pub mod bytes;
pub mod cpu;
pub mod io;
pub mod memory;
pub mod operations;
pub mod program;
pub mod riscv;
pub mod syscall;
pub mod utils;

/// The global version for all components of SP1.
///
/// This string should be updated whenever any step in verifying an SP1 proof changes, including
/// core, recursion, and plonk-bn254. This string is used to download SP1 artifacts and the gnark
/// docker image.
pub const SP1_CIRCUIT_VERSION: &str = "v3.0.0";

// Re-export the `SP1ReduceProof` struct from sp1_core_machine.
//
// This is done to avoid a circular dependency between sp1_core_machine and sp1_core_executor, and
// enable crates that depend on sp1_core_machine to import the `SP1ReduceProof` type directly.
pub mod reduce {
    pub use sp1_core_executor::SP1ReduceProof;
}
