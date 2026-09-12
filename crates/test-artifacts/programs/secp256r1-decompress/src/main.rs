#![no_main]
// This fixture exists to exercise the SECP256R1_DECOMPRESS precompile, which is decommissioned
// and has no AIR, so the syscall is deprecated. The ELF is still declared in
// `sp1-test-artifacts` but nothing runs it; it is kept so the fixture is ready if the
// precompile is ever reinstated. See https://github.com/succinctlabs/sp1/issues/2926.
#![allow(deprecated)]

use sp1_zkvm::syscalls::syscall_secp256r1_decompress;

sp1_zkvm::entrypoint!(main);

#[inline]
fn as_bytes_le(xs: &mut [u64; 8]) -> &mut [u8; 64] {
    #[cfg(not(target_endian = "little"))]
    compile_error!("expected target to be little endian");
    // SAFETY: Arrays are always laid out in the obvious way. Any possible element value is
    // always valid. The pointee types have the same size, and the target of each transmute has
    // finer alignment than the source.
    // Although not a safety invariant, note that the guest target is always little-endian,
    // which was just sanity-checked, so this will always have the expected behavior.
    unsafe { core::mem::transmute::<&mut [u64; 8], &mut [u8; 64]>(xs) }
}

pub fn main() {
    let compressed_key: [u8; 33] = sp1_zkvm::io::read_vec().try_into().unwrap();

    for _ in 0..4 {
        let mut decompressed_key: [u64; 8] = [0; 8];

        as_bytes_le(&mut decompressed_key)[..32].copy_from_slice(&compressed_key[1..]);
        let is_odd = match compressed_key[0] {
            2 => false,
            3 => true,
            _ => panic!("Invalid compressed key"),
        };
        syscall_secp256r1_decompress(&mut decompressed_key, is_odd);

        let mut result: [u8; 65] = [0; 65];
        result[0] = 4;
        result[1..].copy_from_slice(as_bytes_le(&mut decompressed_key));

        sp1_zkvm::io::commit_slice(&result);
    }
}
