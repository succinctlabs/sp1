//! BLAKE2f compression function — Ethereum precompile 0x09 (EIP-152).

use crate::ecall;
use crate::precompile::types::{Blake2fMessage, Blake2fOffset, Blake2fState};
use crate::status::ZKVM_EFAIL;

/// `zkvm_status zkvm_blake2f(rounds, h, m, t, f)`.
///
/// SP1 path: no precompile yet — needs new runtime support, since BLAKE2f is
/// performance-sensitive and a software implementation is unlikely to meet
/// the L1 STF target.
#[no_mangle]
pub unsafe extern "C" fn zkvm_blake2f(
    rounds: u32,
    h: *mut Blake2fState,
    m: *const Blake2fMessage,
    t: *const Blake2fOffset,
    f: u8,
) -> i32 {
    if h.is_null() || m.is_null() || t.is_null() {
        return ZKVM_EFAIL;
    }
    // TODO: implementation. Args > 4 — pack into a struct on the stack and
    // pass via a0 when wiring the real syscall.
    let _ = (rounds, h, m, t, f);
    ecall::ecall0(ecall::placeholder::TODO_BLAKE2F);
    ZKVM_EFAIL
}
