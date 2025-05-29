use std::sync::Mutex;

use lazy_static::lazy_static;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::syscalls::{syscall_halt, syscall_write};

/// The random number generator seed for the zkVM.
///
/// In the future, we can pass in this seed from the host or have the verifier generate it.
const PRNG_SEED: u64 = 0x123456789abcdef0;

lazy_static! {
    /// A lazy static to generate a global random number generator.
    static ref RNG: Mutex<StdRng> = Mutex::new(StdRng::seed_from_u64(PRNG_SEED));
}

/// A lazy static to print a warning once for using the `sys_rand` system call.
static SYS_RAND_WARNING: std::sync::Once = std::sync::Once::new();

/// Generates random bytes.
///
/// # Safety
///
/// Make sure that `buf` has at least `nwords` words.
#[no_mangle]
pub unsafe extern "C" fn sys_rand(recv_buf: *mut u8, words: usize) {
    SYS_RAND_WARNING.call_once(|| {
        eprintln!("WARNING: Using insecure random number generator.");
    });
    let mut rng = RNG.lock().unwrap();
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
    usize::MAX
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
