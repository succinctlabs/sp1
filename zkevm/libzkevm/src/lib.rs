//! `libzkevm` — SP1 platform SDK implementing the eth-act/zkvm-standards C ABI.
//!
//! Every `#[no_mangle] extern "C"` export has the exact signature of the
//! corresponding C declaration in `standards/c-interface-accelerators/zkvm_accelerators.h`,
//! `standards/io-interface/README.md`, and the standard-termination spec.
//! Each accelerator body is one of:
//!
//!   1. a thin wrapper around an existing SP1 precompile syscall
//!      (`KECCAK_PERMUTE`, `SECP256K1_*`, `BN254_*`, `BLS12381_*`, ...)
//!      via a patched no-std crypto crate from `sp1-patches/*`, or
//!   2. a pure-software implementation for primitives without a
//!      corresponding SP1 syscall (`ripemd160`, `modexp`, `blake2f`).
//!
//! See `precompile/mod.rs` for the per-function dispatch table.
//!
//! This crate is the **rlib**. The matching staticlib (`libzkevm.a` for
//! C/Go/Zig consumers) is produced by the sibling `libzkevm-cabi` crate.

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
