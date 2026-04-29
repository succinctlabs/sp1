//! `libzkevm` — SP1 platform SDK implementing the eth-act/zkvm-standards C ABI.
//!
//! This crate is **scaffolding**. Every `#[no_mangle] extern "C"` export
//! has the exact signature of the corresponding C declaration in
//! `standards/c-interface-accelerators/zkvm_accelerators.h`,
//! `standards/io-interface/README.md`, and the standard-termination spec,
//! but the precompile bodies are stubs that return `ZKVM_EFAIL`. A human
//! will replace each stub with a real implementation, typically by:
//!
//!   1. dispatching to an existing SP1 precompile syscall
//!      (e.g. `KECCAK_PERMUTE`, `SECP256K1_ADD`, ...) with input/output
//!      marshalling, or
//!   2. calling into one of SP1's patched no-std crypto crates
//!      (`sha2`, `sha3`, `crypto-bigint`, ...) which already wrap the
//!      precompiles, or
//!   3. introducing a new SP1 syscall number and runtime handler.
//!
//! This crate is the **rlib**. The matching staticlib (`libzkevm.a` for
//! C/Go/Zig consumers) is produced by the sibling `libzkevm-cabi` crate.
//!
//! See `README.md` for the human TODO list.

#![no_std]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

pub mod ecall;
pub mod halt;
pub mod io;
pub mod precompile;

mod status;
pub use status::ZkvmStatus;

/// Entry-point macro re-exported from `sp1-zkvm`. A Rust guest using
/// libzkevm's C ABI can write
///
/// ```ignore
/// #![no_main]
/// zkevm::entrypoint!(main);
///
/// pub fn main() {
///     // ... call into `zkevm::io`, `zkevm::halt`, etc.
/// }
/// ```
///
/// instead of hand-rolling `#[no_mangle] pub extern "C" fn main() -> i32 { ...; 0 }`.
/// The macro generates that wrapper; `_start` (also from `sp1-zkvm`)
/// calls it and forwards the return value to `syscall_halt`.
pub use sp1_zkvm::entrypoint;
