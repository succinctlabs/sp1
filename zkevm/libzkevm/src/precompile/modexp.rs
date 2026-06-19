//! Modular exponentiation — Ethereum precompile 0x05.

use crate::status::{ZKVM_EFAIL, ZKVM_EOK};
use num_bigint_dig::BigUint;

/// `zkvm_status zkvm_modexp(...)`.
///
/// Computes `(base^exp) mod modulus` for arbitrary-precision big-endian
/// inputs and writes exactly `mod_len` BE bytes to `output`. Software
/// implementation via `num-bigint-dig`'s `BigUint::modpow`; SP1 has no
/// modexp precompile syscall.
///
/// `mod_len == 0` writes nothing and returns OK. `modulus == 0` follows
/// EIP-198: result is zero (no division by zero error to surface).
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
        || (output.is_null() && mod_len != 0)
    {
        return ZKVM_EFAIL;
    }

    let base_bytes =
        if base_len == 0 { &[][..] } else { core::slice::from_raw_parts(base, base_len) };
    let exp_bytes = if exp_len == 0 { &[][..] } else { core::slice::from_raw_parts(exp, exp_len) };
    let mod_bytes =
        if mod_len == 0 { &[][..] } else { core::slice::from_raw_parts(modulus, mod_len) };

    if mod_len == 0 {
        return ZKVM_EOK;
    }

    let out_slice = core::slice::from_raw_parts_mut(output, mod_len);
    out_slice.fill(0);

    let m = BigUint::from_bytes_be(mod_bytes);
    if m == BigUint::default() {
        // modulus == 0 → output zero per EIP-198 (no surface error).
        return ZKVM_EOK;
    }

    let b = BigUint::from_bytes_be(base_bytes);
    let e = BigUint::from_bytes_be(exp_bytes);
    let r = b.modpow(&e, &m);

    let r_bytes = r.to_bytes_be();
    // `r` is < modulus, so its byte-length is ≤ mod_len. Right-align with
    // leading zeros so the result is mod_len BE bytes.
    let off = mod_len - r_bytes.len();
    out_slice[off..].copy_from_slice(&r_bytes);
    ZKVM_EOK
}
