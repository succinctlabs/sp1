//! `libzkevm-cabi` — C ABI staticlib facade for `libzkevm`.
//!
//! This crate exists to produce `libzkevm.a`. The actual implementations
//! live in the `libzkevm` rlib (a member of the SP1 root workspace);
//! this crate just pulls the rlib in so cargo emits the staticlib
//! archive containing every `#[no_mangle] extern "C"` symbol.
//!
//! `panic_impl` comes from `sp1-zkvm`'s transitive deps (the succinct
//! toolchain's `std` stub), so we don't declare one here. The panic
//! handler in that stub routes to `syscall_halt(1)`.

// Force the linker to keep all of libzkevm's `#[no_mangle]` symbols
// (the package name is `libzkevm` but the lib name is `zkevm`, so it's
// imported as `zkevm` in Rust code).
pub use zkevm::*;
