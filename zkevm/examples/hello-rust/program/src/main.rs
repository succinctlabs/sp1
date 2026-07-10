//! hello-rust — Rust guest smoke test for the SP1 zkEVM SDK.
//!
//! Demonstrates the `libzkevm` C ABI from a Rust guest:
//!   * `_start` and `__start` come from `sp1-zkvm` (pulled in transitively
//!     via `libzkevm`). `__start` initializes the public-values hasher /
//!     allocator / deferred-proofs digest, calls `main`, then forwards
//!     the `i32` return value to `syscall_halt`.
//!   * `read_input` / `write_output` / `zkvm_halt` come from `libzkevm`'s
//!     `extern "C"` exports — i.e. exactly the symbols a C/Go/Zig guest
//!     would see.
//!
//! SP1 users who just want a Rust guest should use `sp1_zkvm::*`
//! directly. This example exists to validate the C-ABI path from Rust.

#![no_main]

zkevm::entrypoint!(main);

pub fn main() {
    let mut buf_ptr: *const u8 = core::ptr::null();
    let mut buf_size: usize = 0;
    unsafe {
        zkevm::io::read_input(&mut buf_ptr, &mut buf_size);
    }

    if buf_size != 0 && !buf_ptr.is_null() {
        unsafe {
            zkevm::io::write_output(buf_ptr, buf_size);
        }
    } else {
        const HELLO: &[u8] = b"hello from rust\n";
        unsafe {
            zkevm::io::write_output(HELLO.as_ptr(), HELLO.len());
        }
    }
}
