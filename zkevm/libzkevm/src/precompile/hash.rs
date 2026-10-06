//! Hash precompile bodies.
//!
//! `zkvm_keccak256` is the first non-stub. The general pattern: most
//! accelerator implementations sit on top of one or more SP1 syscalls
//! plus some bookkeeping in software. SP1's `KECCAK_PERMUTE` precompile
//! only does the inner keccak-f[1600] permutation; the sponge construction
//! (absorb/pad/squeeze) is handled by `tiny-keccak` (sp1-patches'
//! patched fork — `keccakf` redirects to the precompile syscall when
//! `target_os = "zkvm"`).

use crate::precompile::types::{Keccak256Hash, Ripemd160Hash, Sha256Hash};
use crate::status::{ZKVM_EFAIL, ZKVM_EOK};
use ripemd::Ripemd160;
use sha2::Digest;
use tiny_keccak::{Hasher, Keccak};

/// `zkvm_status zkvm_keccak256(const uint8_t* data, size_t len, zkvm_keccak256_hash* output)`.
///
/// Feed `data[..len]` into `tiny_keccak::Keccak::v256()` and write the
/// 32-byte digest to `*output`. The patched `tiny-keccak`'s inner
/// `keccakf` is replaced with an `ecall` against SP1's `KECCAK_PERMUTE`
/// precompile (`syscall = 0x00_01_01_09`) at `target_os = "zkvm"`.
#[no_mangle]
pub unsafe extern "C" fn zkvm_keccak256(
    data: *const u8,
    len: usize,
    output: *mut Keccak256Hash,
) -> i32 {
    if data.is_null() && len != 0 {
        return ZKVM_EFAIL;
    }
    if output.is_null() {
        return ZKVM_EFAIL;
    }
    let input = if len == 0 { &[] } else { core::slice::from_raw_parts(data, len) };
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(&mut (*output).data);
    ZKVM_EOK
}

/// `zkvm_status zkvm_sha256(const uint8_t* data, size_t len, zkvm_sha256_hash* output)`.
///
/// Feed `data[..len]` into `sha2::Sha256` and write the 32-byte digest
/// to `*output`. The patched `sha2`'s `compress256` calls
/// `syscall_sha256_extend` + `syscall_sha256_compress` at
/// `target_os = "zkvm"`, dispatching to SP1's `SHA_EXTEND`
/// (`0x00_30_01_05`) + `SHA_COMPRESS` (`0x00_01_01_06`) precompiles.
#[no_mangle]
pub unsafe extern "C" fn zkvm_sha256(data: *const u8, len: usize, output: *mut Sha256Hash) -> i32 {
    if data.is_null() && len != 0 {
        return ZKVM_EFAIL;
    }
    if output.is_null() {
        return ZKVM_EFAIL;
    }
    let input = if len == 0 { &[] } else { core::slice::from_raw_parts(data, len) };
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    (*output).data.copy_from_slice(&digest);
    ZKVM_EOK
}

/// `zkvm_status zkvm_ripemd160(const uint8_t* data, size_t len, zkvm_ripemd160_hash* output)`.
///
/// SP1 path: no precompile; software impl via the stock RustCrypto `ripemd`
/// crate. Output layout per the header is 12 zero bytes followed by 20 hash
/// bytes — the 12-byte prefix is zeroed before writing the digest.
#[no_mangle]
pub unsafe extern "C" fn zkvm_ripemd160(
    data: *const u8,
    len: usize,
    output: *mut Ripemd160Hash,
) -> i32 {
    if data.is_null() && len != 0 {
        return ZKVM_EFAIL;
    }
    if output.is_null() {
        return ZKVM_EFAIL;
    }
    let input = if len == 0 { &[] } else { core::slice::from_raw_parts(data, len) };
    let mut hasher = Ripemd160::new();
    hasher.update(input);
    let digest = hasher.finalize();
    let out = &mut (*output).data;
    *out = [0u8; 32];
    out[12..].copy_from_slice(&digest);
    ZKVM_EOK
}
