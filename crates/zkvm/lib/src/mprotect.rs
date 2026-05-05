use sp1_primitives::consts::LOG_PAGE_SIZE;

use crate::{syscall_mprotect, syscall_mprotect_flush};

/// Verifies the next proof in the proof input stream given a verification key digest and public
/// values digest. If the proof is invalid, the function will panic.
///
/// Enable this function by adding the `verify` feature to both the `sp1-lib` AND `sp1-zkvm` crates.
pub fn mprotect(addr: *const u8, len: usize, prot: u8) {
    let start = addr as usize;
    let end = start + len;

    (start..end).step_by(1 << LOG_PAGE_SIZE).for_each(|addr| unsafe {
        syscall_mprotect(addr as *const u8, prot);
    });

    unsafe {
        syscall_mprotect_flush();
    }
}
