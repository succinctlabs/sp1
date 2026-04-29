//! Termination / halt wrappers.
//!
//! Spec: `standards/standard-termination-semantics/README.md` (eth-act).
//!
//! Delegates to `sp1_zkvm::syscalls::syscall_halt`, which commits the
//! public-values digest and the deferred-proofs digest before issuing
//! the HALT ecall. `sp1-zkvm`'s `__start` also forwards `main`'s `i32`
//! return value as the exit code, so a C program's `int main(void) {
//! return code; }` propagates correctly to the verifier without any
//! explicit `zkvm_halt` call.

/// `void zkvm_halt(uint8_t exit_code)` — never returns.
///
/// Successful termination: `exit_code == 0`. Non-zero indicates failure
/// per the standard-termination spec.
#[no_mangle]
pub extern "C" fn zkvm_halt(exit_code: u8) -> ! {
    sp1_zkvm::syscalls::syscall_halt(exit_code);
}

/// POSIX `exit` alias.
#[no_mangle]
pub extern "C" fn exit(status: i32) -> ! {
    zkvm_halt((status & 0xFF) as u8)
}

/// POSIX `_exit` alias.
#[no_mangle]
pub extern "C" fn _exit(status: i32) -> ! {
    zkvm_halt((status & 0xFF) as u8)
}

/// `abort()` — failed termination with a non-zero exit code.
#[no_mangle]
pub extern "C" fn abort() -> ! {
    zkvm_halt(1)
}

/// glibc-style assertion failure shim. Standard `<assert.h>` expands a
/// failed `assert(...)` into a call to `__assert_fail`; we ignore the
/// diagnostic strings and route to `zkvm_halt(1)` so a guest using libc's
/// `<assert.h>` halts with a non-zero exit code.
#[no_mangle]
pub extern "C" fn __assert_fail(
    _assertion: *const core::ffi::c_char,
    _file: *const core::ffi::c_char,
    _line: u32,
    _function: *const core::ffi::c_char,
) -> ! {
    zkvm_halt(1)
}
