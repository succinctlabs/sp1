//! keccak — read bytes, compute keccak256 via the libzkevm precompile,
//! write the 32-byte digest.
//!
//! Demonstrates the first real (non-stub) precompile body in libzkevm:
//! the inner keccak-f permutation is dispatched to SP1's `KECCAK_PERMUTE`
//! syscall while the sponge construction (absorb / pad / squeeze) is
//! handled in software inside `libzkevm::precompile::hash::zkvm_keccak256`.

#![no_main]

use zkevm::precompile::types::Keccak256Hash;

zkevm::entrypoint!(main);

extern "C" {
    fn zkvm_keccak256(data: *const u8, len: usize, output: *mut Keccak256Hash) -> i32;
}

pub fn main() {
    let mut buf_ptr: *const u8 = core::ptr::null();
    let mut buf_size: usize = 0;
    unsafe {
        zkevm::io::read_input(&mut buf_ptr, &mut buf_size);
    }

    let mut digest = Keccak256Hash { data: [0u8; 32] };
    let status = unsafe { zkvm_keccak256(buf_ptr, buf_size, &mut digest as *mut _) };
    if status != 0 {
        panic!("zkvm_keccak256 returned {status}");
    }

    unsafe {
        zkevm::io::write_output(digest.data.as_ptr(), digest.data.len());
    }
}
