//! Hash precompile bodies.
//!
//! `zkvm_keccak256` is the first non-stub. The general pattern: most
//! accelerator implementations sit on top of one or more SP1 syscalls
//! plus some bookkeeping in software. SP1's `KECCAK_PERMUTE` precompile
//! only does the inner keccak-f[1600] permutation; the sponge construction
//! (absorb/pad/squeeze) stays in this crate.
//!
//! Reference choice: rather than depend on the patched `tiny-keccak`
//! crate (which has version-conflict issues with SP1 6.1 on the
//! `p3-field` transitive dep), we drive the sponge by hand. The
//! permutation itself is the only expensive part and that goes through
//! the precompile.

use crate::precompile::types::{Keccak256Hash, Ripemd160Hash, Sha256Hash};
use crate::status::{ZKVM_EFAIL, ZKVM_EOK};

/// Keccak-256 sponge rate (bits absorbed per permutation): r = 1088 = 17 lanes × 64 bits.
const KECCAK256_RATE_BYTES: usize = 136;

/// `zkvm_status zkvm_keccak256(const uint8_t* data, size_t len, zkvm_keccak256_hash* output)`.
///
/// Implements the Keccak-256 sponge construction:
///   * absorb full `136`-byte chunks via XOR + permutation;
///   * pad the last (possibly empty) chunk with `0x01 ... 0x80`
///     (Keccak padding, *not* SHA-3 which uses `0x06 ... 0x80`);
///   * squeeze the first 32 bytes of the state as the digest.
///
/// The permutation step calls `sp1_zkvm::syscalls::syscall_keccak_permute`,
/// which dispatches to SP1's `KECCAK_PERMUTE` precompile (`t0 = 0x00_01_01_09`)
/// at `target_os = "zkvm"` and is `unreachable!` on host (this function
/// is meaningful only inside the zkVM).
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

    // 25-lane Keccak state, addressable as both bytes and u64 lanes for
    // the syscall (which takes `*mut [u64; 25]`). The all-zero start
    // state is the standard initial sponge state.
    #[repr(C, align(8))]
    struct State([u64; 25]);
    let mut state = State([0u64; 25]);

    // SAFETY: `state` is 8-byte aligned and `25 * 8 = 200` bytes.
    let state_bytes: &mut [u8; 200] = &mut *(core::ptr::addr_of_mut!(state.0) as *mut [u8; 200]);

    let input = if len == 0 { &[] } else { core::slice::from_raw_parts(data, len) };

    // Absorb full rate-sized chunks.
    let mut chunks = input.chunks_exact(KECCAK256_RATE_BYTES);
    for chunk in chunks.by_ref() {
        for (s, b) in state_bytes.iter_mut().zip(chunk.iter()) {
            *s ^= *b;
        }
        sp1_zkvm::syscalls::syscall_keccak_permute(core::ptr::addr_of_mut!(state.0));
    }

    // Final (short) chunk: XOR + Keccak padding (`0x01` ... `0x80`).
    let tail = chunks.remainder();
    for (s, b) in state_bytes.iter_mut().zip(tail.iter()) {
        *s ^= *b;
    }
    state_bytes[tail.len()] ^= 0x01;
    state_bytes[KECCAK256_RATE_BYTES - 1] ^= 0x80;
    sp1_zkvm::syscalls::syscall_keccak_permute(core::ptr::addr_of_mut!(state.0));

    // Squeeze the first 32 bytes (256 bits) as the digest.
    (*output).data.copy_from_slice(&state_bytes[..32]);

    ZKVM_EOK
}

/// `zkvm_status zkvm_sha256(const uint8_t* data, size_t len, zkvm_sha256_hash* output)`.
///
/// SP1 path: loop over `SHA_EXTEND` + `SHA_COMPRESS` with FIPS-180 padding.
#[no_mangle]
pub unsafe extern "C" fn zkvm_sha256(data: *const u8, len: usize, output: *mut Sha256Hash) -> i32 {
    if data.is_null() && len != 0 {
        return ZKVM_EFAIL;
    }
    if output.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation
    crate::ecall::ecall3(
        crate::ecall::placeholder::TODO_SHA256,
        data as usize,
        len,
        output as usize,
    );
    ZKVM_EFAIL
}

/// `zkvm_status zkvm_ripemd160(const uint8_t* data, size_t len, zkvm_ripemd160_hash* output)`.
///
/// SP1 path: no precompile; software impl is acceptable since RIPEMD-160 is
/// not on the L1 STF hot path. Output is 20 hash bytes followed by 12 zero
/// bytes (header docs).
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
    // TODO: implementation (likely software, padded to 32 bytes).
    crate::ecall::ecall3(
        crate::ecall::placeholder::TODO_RIPEMD160,
        data as usize,
        len,
        output as usize,
    );
    ZKVM_EFAIL
}
