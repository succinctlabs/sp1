//! panic — read a single byte; if non-zero, panic.
//!
//! Demonstrates the failed-termination path:
//!   * `panic!()` routes through Rust's panic_handler (provided by the
//!     succinct toolchain's `std` stub) -> `syscall_halt(1)`.
//!   * The eth-act standard-termination spec calls this "failed
//!     termination"; the verifier sees a halted-with-non-zero-exit-code
//!     proof.

#![no_main]

zkevm::entrypoint!(main);

pub fn main() {
    let mut buf_ptr: *const u8 = core::ptr::null();
    let mut buf_size: usize = 0;
    unsafe {
        zkevm::io::read_input(&mut buf_ptr, &mut buf_size);
    }

    let flag = if buf_size >= 1 && !buf_ptr.is_null() { unsafe { *buf_ptr } } else { 0 };

    if flag != 0 {
        panic!("guest panicked because input flag was {}", flag);
    }

    // Successful path: emit a small confirmation payload.
    const OK: &[u8] = b"no panic\n";
    unsafe {
        zkevm::io::write_output(OK.as_ptr(), OK.len());
    }
}
