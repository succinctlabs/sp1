use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::syscalls::{syscall_halt, syscall_write};

/// The random number generator seed for the zkVM.
///
/// In the future, we can pass in this seed from the host or have the verifier generate it.
const PRNG_SEED: u64 = 0x123456789abcdef0;

// Single-threaded RNG state — the SP1 zkVM is single-threaded by construction
// so we don't need a Mutex. `static mut` access is gated by the
// `target_os = "zkvm"` cfg on `sys_rand` below.
static mut RNG: Option<StdRng> = None;

/// Generates random bytes.
///
/// # Safety
///
/// Make sure that `buf` has at least `nwords` words.
#[no_mangle]
pub unsafe extern "C" fn sys_rand(recv_buf: *mut u8, words: usize) {
    // Print the insecure-RNG warning to fd 2 (stderr) at most once per
    // program. zkVM is single-threaded so a `static mut` flag is fine; on
    // host targets `syscall_write` is `unreachable!()` so we skip the
    // print there (host builds of sp1-zkvm don't actually run `sys_rand`
    // in practice — they exist for `cargo check` only).
    static mut WARNED: bool = false;
    unsafe {
        let warned_ptr = core::ptr::addr_of_mut!(WARNED);
        if !*warned_ptr {
            *warned_ptr = true;
            #[cfg(target_os = "zkvm")]
            {
                const WARNING: &[u8] = b"WARNING: Using insecure random number generator.\n";
                syscall_write(2, WARNING.as_ptr(), WARNING.len());
            }
        }
    }

    // SAFETY: zkVM is single-threaded.
    let rng = unsafe {
        let rng_ptr = core::ptr::addr_of_mut!(RNG);
        if (*rng_ptr).is_none() {
            *rng_ptr = Some(StdRng::seed_from_u64(PRNG_SEED));
        }
        (*rng_ptr).as_mut().unwrap()
    };
    for i in 0..words {
        let element = recv_buf.add(i);
        *element = rng.gen();
    }
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn sys_panic(msg_ptr: *const u8, len: usize) -> ! {
    sys_write(2, msg_ptr, len);
    syscall_halt(1);
}

#[allow(unused_variables)]
#[no_mangle]
pub const fn sys_getenv(
    recv_buf: *mut u32,
    words: usize,
    varname: *const u8,
    varname_len: usize,
) -> usize {
    0
}

#[allow(unused_variables)]
#[no_mangle]
pub const fn sys_alloc_words(nwords: usize) -> *mut u32 {
    core::ptr::null_mut()
}

#[allow(unused_unsafe)]
#[no_mangle]
pub fn sys_write(fd: u32, write_buf: *const u8, nbytes: usize) {
    unsafe {
        syscall_write(fd, write_buf, nbytes);
    }
}
