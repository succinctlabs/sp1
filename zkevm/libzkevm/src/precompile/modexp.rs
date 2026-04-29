//! Modular exponentiation — Ethereum precompile 0x05.

use crate::ecall;
use crate::status::ZKVM_EFAIL;

/// `zkvm_status zkvm_modexp(...)`.
///
/// SP1 path: needs new runtime support, or a software impl on top of
/// `UINT256_*` precompiles for sizes ≤ 256 bits and a generic bigint
/// fallback otherwise.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn zkvm_modexp(
    base: *const u8,
    base_len: usize,
    exp: *const u8,
    exp_len: usize,
    modulus: *const u8,
    mod_len: usize,
    output: *mut u8,
) -> i32 {
    if (base.is_null() && base_len != 0)
        || (exp.is_null() && exp_len != 0)
        || (modulus.is_null() && mod_len != 0)
        || output.is_null()
    {
        return ZKVM_EFAIL;
    }
    // TODO: implementation. Args don't fit in 4 a-regs; pass a struct via a0
    // when wiring the real syscall.
    let _ = (base, base_len, exp, exp_len, modulus, mod_len, output);
    ecall::ecall0(ecall::placeholder::TODO_MODEXP);
    ZKVM_EFAIL
}
