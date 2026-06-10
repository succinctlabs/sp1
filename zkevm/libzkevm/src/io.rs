//! Input/output wrappers.
//!
//! Spec: `standards/io-interface/README.md` (eth-act).
//!
//! ```c
//! void read_input(const uint8_t** buf_ptr, size_t* buf_size);
//! void write_output(const uint8_t* output, size_t size);
//! ```
//!
//! ## SP1 mapping
//!
//! `write_output` delegates to `sp1_zkvm::syscalls::syscall_write` against
//! `FD_PUBLIC_VALUES = 13`. That wrapper updates SP1's public-values
//! hasher with the bytes being written, so the digest committed at
//! `zkvm_halt` time is correct.
//!
//! `read_input` calls `sp1_zkvm`'s `read_vec_raw` on first invocation —
//! that drains the next chunk from the SP1 hint stream into the embedded
//! allocator's reserved input region — and caches `(ptr, len)` for
//! subsequent idempotent calls.
//!
//! ## Host-side contract
//!
//! `read_input` exposes the **first** chunk in SP1's hint stream and
//! ignores any subsequent chunks. The host MUST push the entire private
//! input as a single chunk, e.g.
//!
//! ```ignore
//! let mut stdin = SP1Stdin::new();
//! stdin.write_slice(&serialized_block_bytes); // one call only
//! ```
//!
//! Multiple `stdin.write{,_slice,_value}` calls produce multiple chunks;
//! everything past the first is invisible to a C/Go/Zig guest using
//! `read_input`. (For multi-chunk consumers, call `read_vec_raw`
//! directly via `sp1_zkvm`.)

use core::cell::UnsafeCell;
use sp1_zkvm::ReadVecResult;

// Mirrors `sp1_primitives::consts::fd::FD_PUBLIC_VALUES` (which is
// `LOWEST_ALLOWED_FD + 3 = 13`). Inlined here so we don't need to add a
// dep on sp1-primitives just for one constant.
const FD_PUBLIC_VALUES: u32 = 13;

/// Standardized: `void read_input(const uint8_t** buf_ptr, size_t* buf_size)`.
/// Idempotent. Both pointers must be non-null.
#[no_mangle]
pub unsafe extern "C" fn read_input(buf_ptr: *mut *const u8, buf_size: *mut usize) {
    if buf_ptr.is_null() || buf_size.is_null() {
        // `abort()` semantics (the alias itself is zkvm-target-only).
        crate::halt::zkvm_halt(1);
    }

    // Cache the (ptr, len) of the first successful read so subsequent calls
    // are idempotent. SP1 zkVM is single-threaded, so an UnsafeCell is fine.
    struct Cached(UnsafeCell<Option<(*const u8, usize)>>);
    unsafe impl Sync for Cached {}
    static CACHED: Cached = Cached(UnsafeCell::new(None));

    if let Some((p, n)) = *CACHED.0.get() {
        *buf_ptr = p;
        *buf_size = n;
        return;
    }

    extern "C" {
        fn read_vec_raw() -> ReadVecResult;
    }
    let result = read_vec_raw();
    let p = result.ptr as *const u8;
    let n = result.len;
    *CACHED.0.get() = Some((p, n));
    *buf_ptr = p;
    *buf_size = n;
}

/// Standardized: `void write_output(const uint8_t* output, size_t size)`.
/// May be called multiple times; observable result is the concatenation.
#[no_mangle]
pub unsafe extern "C" fn write_output(output: *const u8, size: usize) {
    if size == 0 {
        return;
    }
    sp1_zkvm::syscalls::syscall_write(FD_PUBLIC_VALUES, output, size);
}
