//! sha256 — read bytes, compute SHA-256 via the libzkevm precompile,
//! write the 32-byte digest.
//!
//! Same shape as `examples/keccak/`. The patched `sha2` crate's inner
//! `compress256` is replaced with calls to SP1's `SHA_EXTEND` +
//! `SHA_COMPRESS` precompiles when `target_os = "zkvm"`; on host it
//! falls back to the stock RustCrypto implementation.

#![no_main]

use zkevm::precompile::types::Sha256Hash;

zkevm::entrypoint!(main);

extern "C" {
    fn zkvm_sha256(data: *const u8, len: usize, output: *mut Sha256Hash) -> i32;
}

pub fn main() {
    let mut buf_ptr: *const u8 = core::ptr::null();
    let mut buf_size: usize = 0;
    unsafe {
        zkevm::io::read_input(&mut buf_ptr, &mut buf_size);
    }

    let mut digest = Sha256Hash { data: [0u8; 32] };
    let status = unsafe { zkvm_sha256(buf_ptr, buf_size, &mut digest as *mut _) };
    if status != 0 {
        panic!("zkvm_sha256 returned {status}");
    }

    unsafe {
        zkevm::io::write_output(digest.data.as_ptr(), digest.data.len());
    }
}
