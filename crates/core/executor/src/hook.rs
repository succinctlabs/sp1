use core::fmt::Debug;

use std::sync::{Arc, RwLock, RwLockWriteGuard};

use hashbrown::HashMap;
use sp1_curves::{edwards::ed25519::ed25519_sqrt, params::FieldParameters, BigUint, Integer, One};

use crate::Executor;

/// A runtime hook, wrapped in a smart pointer.
pub type BoxedHook<'a> = Arc<RwLock<dyn Hook + Send + Sync + 'a>>;

pub use sp1_primitives::consts::fd::*;

/// A runtime hook. May be called during execution by writing to a specified file descriptor,
/// accepting and returning arbitrary data.
pub trait Hook {
    /// Invoke the runtime hook with a standard environment and arbitrary data.
    /// Returns the computed data.
    fn invoke_hook(&mut self, env: HookEnv, buf: &[u8]) -> Vec<Vec<u8>>;
}

impl<F: FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>>> Hook for F {
    /// Invokes the function `self` as a hook.
    fn invoke_hook(&mut self, env: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
        self(env, buf)
    }
}

/// Wrap a function in a smart pointer so it may be placed in a `HookRegistry`.
///
/// Note: the Send + Sync requirement may be logically extraneous. Requires further investigation.
pub fn hookify<'a>(
    f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
) -> BoxedHook<'a> {
    Arc::new(RwLock::new(f))
}

/// A registry of hooks to call, indexed by the file descriptors through which they are accessed.
#[derive(Clone)]
pub struct HookRegistry<'a> {
    /// Table of registered hooks. Prefer using `Runtime::hook`, ` Runtime::hook_env`,
    /// and `HookRegistry::get` over interacting with this field directly.
    pub(crate) table: HashMap<u32, BoxedHook<'a>>,
}

impl<'a> HookRegistry<'a> {
    /// Create a default [`HookRegistry`].
    #[must_use]
    pub fn new() -> Self {
        HookRegistry::default()
    }

    /// Create an empty [`HookRegistry`].
    #[must_use]
    pub fn empty() -> Self {
        Self { table: HashMap::default() }
    }

    /// Get a hook with exclusive write access, if it exists.
    ///
    /// Note: This function should not be called in async contexts, unless you know what you are
    /// doing.
    #[must_use]
    pub fn get(&self, fd: u32) -> Option<RwLockWriteGuard<dyn Hook + Send + Sync + 'a>> {
        // Calling `.unwrap()` panics on a poisoned lock. Should never happen normally.
        self.table.get(&fd).map(|x| x.write().unwrap())
    }
}

impl Default for HookRegistry<'_> {
    fn default() -> Self {
        // When `LazyCell` gets stabilized (1.81.0), we can use it to avoid unnecessary allocations.
        let table = HashMap::from([
            // Note: To ensure any `fd` value is synced with `zkvm/precompiles/src/io.rs`,
            // add an assertion to the test `hook_fds_match` below.
            (FD_ECRECOVER_HOOK, hookify(hook_ecrecover)),
            (FD_EDDECOMPRESS, hookify(hook_ed_decompress)),
            (FD_RSA_MUL_MOD, hookify(hook_rsa_mul_mod)),
            (FD_BLS12_381_SQRT, hookify(bls::hook_bls12_381_sqrt)),
            (FD_BLS12_381_INVERSE, hookify(bls::hook_bls12_381_inverse)),
        ]);

        Self { table }
    }
}

impl Debug for HookRegistry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut keys = self.table.keys().collect::<Vec<_>>();
        keys.sort_unstable();
        f.debug_struct("HookRegistry")
            .field(
                "table",
                &format_args!("{{{} hooks registered at {:?}}}", self.table.len(), keys),
            )
            .finish()
    }
}

/// Environment that a hook may read from.
pub struct HookEnv<'a, 'b: 'a> {
    /// The runtime.
    pub runtime: &'a Executor<'b>,
}

/// The hook for the `ecrecover` patches.
///
/// The input should be of the form [(`curve_id_u8` | `r_is_y_odd_u8` << 7) || `r` || `alpha`] where:
/// * `curve_id` is 1 for secp256k1 and 2 for secp256r1
/// * `r_is_y_odd` is 0 if r is even and 1 if r is is odd
/// * r is the x-coordinate of the point, which should be 32 bytes,
/// * alpha := r * r * r * (a * r) + b, which should be 32 bytes.
///
/// Returns vec![vec![1], `y`, `r_inv`] if the point is decompressable
/// and vec![vec![0],`nqr_hint`] if not.
#[must_use]
pub fn hook_ecrecover(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
    assert!(buf.len() == 64 + 1, "ecrecover should have length 65");

    let curve_id = buf[0] & 0b0111_1111;
    let r_is_y_odd = buf[0] & 0b1000_0000 != 0;

    let r_bytes: [u8; 32] = buf[1..33].try_into().unwrap();
    let alpha_bytes: [u8; 32] = buf[33..65].try_into().unwrap();

    match curve_id {
        1 => ecrecover::handle_secp256k1(r_bytes, alpha_bytes, r_is_y_odd),
        2 => ecrecover::handle_secp256r1(r_bytes, alpha_bytes, r_is_y_odd),
        _ => unimplemented!("Unsupported curve id: {}", curve_id),
    }
}

mod ecrecover {
    use sp1_curves::{k256, p256};

    /// The non-quadratic residue for the curve for secp256k1 and secp256r1.
    const NQR: [u8; 32] = {
        let mut nqr = [0; 32];
        nqr[31] = 3;
        nqr
    };

    pub(super) fn handle_secp256k1(r: [u8; 32], alpha: [u8; 32], r_y_is_odd: bool) -> Vec<Vec<u8>> {
        use k256::elliptic_curve::ff::PrimeField;
        use k256::FieldBytes as K256FieldBytes;
        use k256::FieldElement as K256FieldElement;
        use k256::Scalar as K256Scalar;

        let r = K256FieldElement::from_bytes(K256FieldBytes::from_slice(&r)).unwrap();
        debug_assert!(!bool::from(r.is_zero()), "r should not be zero");

        let alpha = K256FieldElement::from_bytes(K256FieldBytes::from_slice(&alpha)).unwrap();
        assert!(!bool::from(alpha.is_zero()), "alpha should not be zero");

        // nomralize the y-coordinate always to be consistent.
        if let Some(mut y_coord) = alpha.sqrt().into_option().map(|y| y.normalize()) {
            let r = K256Scalar::from_repr(r.to_bytes()).unwrap();
            let r_inv = r.invert().expect("Non zero r scalar");

            if r_y_is_odd != bool::from(y_coord.is_odd()) {
                y_coord = y_coord.negate(1);
                y_coord = y_coord.normalize();
            }

            vec![vec![1], y_coord.to_bytes().to_vec(), r_inv.to_bytes().to_vec()]
        } else {
            let nqr_field = K256FieldElement::from_bytes(K256FieldBytes::from_slice(&NQR)).unwrap();
            let qr = alpha * nqr_field;
            let root = qr.sqrt().expect("if alpha is not a square, then qr should be a square");

            vec![vec![0], root.to_bytes().to_vec()]
        }
    }

    pub(super) fn handle_secp256r1(r: [u8; 32], alpha: [u8; 32], r_y_is_odd: bool) -> Vec<Vec<u8>> {
        use p256::elliptic_curve::ff::PrimeField;
        use p256::FieldBytes as P256FieldBytes;
        use p256::FieldElement as P256FieldElement;
        use p256::Scalar as P256Scalar;

        let r = P256FieldElement::from_bytes(P256FieldBytes::from_slice(&r)).unwrap();
        debug_assert!(!bool::from(r.is_zero()), "r should not be zero");

        let alpha = P256FieldElement::from_bytes(P256FieldBytes::from_slice(&alpha)).unwrap();
        debug_assert!(!bool::from(alpha.is_zero()), "alpha should not be zero");

        if let Some(mut y_coord) = alpha.sqrt().into_option() {
            let r = P256Scalar::from_repr(r.to_bytes()).unwrap();
            let r_inv = r.invert().expect("Non zero r scalar");

            if r_y_is_odd != bool::from(y_coord.is_odd()) {
                y_coord = -y_coord;
            }

            vec![vec![1], y_coord.to_bytes().to_vec(), r_inv.to_bytes().to_vec()]
        } else {
            let nqr_field = P256FieldElement::from_bytes(P256FieldBytes::from_slice(&NQR)).unwrap();
            let qr = alpha * nqr_field;
            let root = qr.sqrt().expect("if alpha is not a square, then qr should be a square");

            vec![vec![0], root.to_bytes().to_vec()]
        }
    }
}

/// Checks if a compressed Edwards point can be decompressed.
///
/// # Arguments
/// * `env` - The environment in which the hook is invoked.
/// * `buf` - The buffer containing the compressed Edwards point.
///    - The compressed Edwards point is 32 bytes.
///    - The high bit of the last byte is the sign bit.
///
/// Returns vec![vec![1]] if the point is decompressable.
/// Returns vec![vec![0], `v_inv`, `nqr_hint`] if the point is not decompressable.
///
/// WARNING: This function merely hints at the validity of the compressed point. These values must
/// be constrained by the zkVM for correctness.
#[must_use]
pub fn hook_ed_decompress(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
    const NQR_CURVE_25519: u8 = 2;
    let modulus = sp1_curves::edwards::ed25519::Ed25519BaseField::modulus();

    let mut bytes: [u8; 32] = buf[..32].try_into().unwrap();
    // Mask the sign bit.
    bytes[31] &= 0b0111_1111;

    // The AIR asserts canon inputs, so hint here if it cant be satisfied.
    let y = BigUint::from_bytes_le(&bytes);
    if y >= modulus {
        return vec![vec![0]];
    }

    let v = BigUint::from_bytes_le(&buf[32..]);
    // This is computed as dy^2 - 1
    // so it should always be in the field.
    assert!(v < modulus, "V is not a valid field element");

    // For a point to be decompressable, (yy - 1) / (yy * d + 1) must be a quadratic residue.
    let v_inv = v.modpow(&(&modulus - BigUint::from(2u64)), &modulus);
    let u = (&y * &y + &modulus - BigUint::one()) % &modulus;
    let u_div_v = (&u * &v_inv) % &modulus;

    // Note: Our sqrt impl doesnt care about canon representation,
    // however we have already checked that were less than the modulus.
    if ed25519_sqrt(&u_div_v).is_some() {
        vec![vec![1]]
    } else {
        let qr = (u_div_v * NQR_CURVE_25519) % &modulus;
        let root = ed25519_sqrt(&qr).unwrap();

        // Pad the results, since this may not be a full 32 bytes.
        let v_inv_bytes = v_inv.to_bytes_le();
        let mut v_inv_padded = [0_u8; 32];
        v_inv_padded[..v_inv_bytes.len()].copy_from_slice(&v_inv.to_bytes_le());

        let root_bytes = root.to_bytes_le();
        let mut root_padded = [0_u8; 32];
        root_padded[..root_bytes.len()].copy_from_slice(&root.to_bytes_le());

        vec![vec![0], v_inv_padded.to_vec(), root_padded.to_vec()]
    }
}

mod bls {
    use super::pad_to_be;
    use super::{BigUint, HookEnv};
    use sp1_curves::params::FieldParameters;
    use sp1_curves::weierstrass::bls12_381::Bls12381BaseField;
    use sp1_curves::Zero;

    /// A non-quadratic residue for the `12_381` base field in big endian.
    pub const NQR_BLS12_381: [u8; 48] = {
        let mut nqr = [0; 48];
        nqr[47] = 2;
        nqr
    };

    /// The base field modulus for the `12_381` curve, in little endian.
    pub const BLS12_381_MODULUS: &[u8] = Bls12381BaseField::MODULUS;

    /// Given a field element, in big endian, this function computes the square root.
    ///
    /// - If the field element is the additive identity, this function returns `vec![vec![1], vec![0; 48]]`.
    /// - If the field element is a quadratic residue, this function returns `vec![vec![1], vec![sqrt(fe)]  ]`.
    /// - If the field element (fe) is not a quadratic residue, this function returns `vec![vec![0], vec![sqrt(``NQR_BLS12_381`` * fe)]]`.
    pub fn hook_bls12_381_sqrt(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
        let field_element = BigUint::from_bytes_be(&buf[..48]);

        // This should be checked in the VM as its easier than dispatching a hook call.
        // But for completeness we include this happy path also.
        if field_element.is_zero() {
            return vec![vec![1], vec![0; 48]];
        }

        let modulus = BigUint::from_bytes_le(BLS12_381_MODULUS);

        // Since `BLS12_381_MODULUS` == 3 mod 4,. we can use shanks methods.
        // This means we only need to exponentiate by `(modulus + 1) / 4`.
        let exp = (&modulus + BigUint::from(1u64)) / BigUint::from(4u64);
        let sqrt = field_element.modpow(&exp, &modulus);

        // Shanks methods only works if the field element is a quadratic residue.
        // So we need to check if the square of the sqrt is equal to the field element.
        let square = (&sqrt * &sqrt) % &modulus;
        if square != field_element {
            let nqr = BigUint::from_bytes_be(&NQR_BLS12_381);
            let qr = (&nqr * &field_element) % &modulus;

            // By now, the product of two non-quadratic residues is a quadratic residue.
            // So we can use shanks methods again to get its square root.
            //
            // We pass this root back to the VM to constrain the "failure" case.
            let root = qr.modpow(&exp, &modulus);

            assert!((&root * &root) % &modulus == qr, "NQR sanity check failed, this is a bug.");

            return vec![vec![0], pad_to_be(&root, 48)];
        }

        vec![vec![1], pad_to_be(&sqrt, 48)]
    }

    /// Given a field element, in big endian, this function computes the inverse.
    ///
    /// This functions will panic if the additive identity is passed in.
    pub fn hook_bls12_381_inverse(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
        let field_element = BigUint::from_bytes_be(&buf[..48]);

        // Zero is not invertible, and we dont want to have to return a status from here.
        assert!(!field_element.is_zero(), "Field element is the additive identity");

        let modulus = BigUint::from_bytes_le(BLS12_381_MODULUS);

        // Compute the inverse using Fermat's little theorem, ie, a^(p-2) = a^-1 mod p.
        let inverse = field_element.modpow(&(&modulus - BigUint::from(2u64)), &modulus);

        vec![pad_to_be(&inverse, 48)]
    }
}

/// Given the product of some 256-byte numbers and a modulus, this function does a modular
/// reduction and hints back the values to the vm in order to constrain it.
///
/// # Arguments
///
/// * `env` - The environment in which the hook is invoked.
/// * `buf` - The buffer containing the le bytes of the 512 byte product and the 256 byte modulus.
///
/// Returns The le bytes of the product % modulus (512 bytes)
/// and the quotient floor(product/modulus) (256 bytes).
///
/// WANRING: This function is used to perform a modular reduction outside of the zkVM context.
/// These values must be constrained by the zkVM for correctness.
#[must_use]
pub fn hook_rsa_mul_mod(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(
        buf.len(),
        256 + 256 + 256,
        "rsa_mul_mod input should have length 256 + 256 + 256, this is a bug."
    );

    let prod: &[u8; 512] = buf[..512].try_into().unwrap();
    let m: &[u8; 256] = buf[512..].try_into().unwrap();

    let prod = BigUint::from_bytes_le(prod);
    let m = BigUint::from_bytes_le(m);

    let (q, rem) = prod.div_rem(&m);

    let mut rem = rem.to_bytes_le();
    rem.resize(256, 0);

    let mut q = q.to_bytes_le();
    q.resize(256, 0);

    vec![rem, q]
}

pub(crate) mod deprecated_hooks {
    use super::HookEnv;
    use sp1_curves::k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sp1_curves::k256::elliptic_curve::ops::Invert;
    use sp1_curves::p256::ecdsa::Signature as p256Signature;

    /// Recovers the public key from the signature and message hash using the k256 crate.
    ///
    /// # Arguments
    ///
    /// * `env` - The environment in which the hook is invoked.
    /// * `buf` - The buffer containing the signature and message hash.
    ///     - The signature is 65 bytes, the first 64 bytes are the signature and the last byte is the
    ///       recovery ID.
    ///     - The message hash is 32 bytes.
    ///
    /// The result is returned as a pair of bytes, where the first 32 bytes are the X coordinate
    /// and the second 32 bytes are the Y coordinate of the decompressed point.
    ///
    /// WARNING: This function is used to recover the public key outside of the zkVM context. These
    /// values must be constrained by the zkVM for correctness.
    #[must_use]
    pub fn hook_ecrecover(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
        assert_eq!(buf.len(), 65 + 32, "ecrecover input should have length 65 + 32");
        let (sig, msg_hash) = buf.split_at(65);
        let sig: &[u8; 65] = sig.try_into().unwrap();
        let msg_hash: &[u8; 32] = msg_hash.try_into().unwrap();

        let mut recovery_id = sig[64];
        let mut sig = Signature::from_slice(&sig[..64]).unwrap();

        if let Some(sig_normalized) = sig.normalize_s() {
            sig = sig_normalized;
            recovery_id ^= 1;
        };
        let recid = RecoveryId::from_byte(recovery_id).expect("Computed recovery ID is invalid!");

        let recovered_key = VerifyingKey::recover_from_prehash(&msg_hash[..], &sig, recid).unwrap();
        let bytes = recovered_key.to_sec1_bytes();

        let (_, s) = sig.split_scalars();
        let s_inverse = s.invert();

        vec![bytes.to_vec(), s_inverse.to_bytes().to_vec()]
    }

    /// Recovers s inverse from the signature using the secp256r1 crate.
    ///
    /// # Arguments
    ///
    /// * `env` - The environment in which the hook is invoked.
    /// * `buf` - The buffer containing the signature.
    ///     - The signature is 64 bytes.
    ///
    /// The result is a single 32 byte vector containing s inverse.
    #[must_use]
    pub fn hook_r1_ecrecover(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
        assert_eq!(buf.len(), 64, "ecrecover input should have length 64");
        let sig: &[u8; 64] = buf.try_into().unwrap();
        let sig = p256Signature::from_slice(sig).unwrap();

        let (_, s) = sig.split_scalars();
        let s_inverse = s.invert();

        vec![s_inverse.to_bytes().to_vec()]
    }

    /// Recovers the public key from the signature and message hash using the k256 crate.
    ///
    /// # Arguments
    ///
    /// * `env` - The environment in which the hook is invoked.
    /// * `buf` - The buffer containing the signature and message hash.
    ///     - The signature is 65 bytes, the first 64 bytes are the signature and the last byte is the
    ///       recovery ID.
    ///     - The message hash is 32 bytes.
    ///
    /// The result is returned as a status and a pair of bytes, where the first 32 bytes are the X coordinate
    /// and the second 32 bytes are the Y coordinate of the decompressed point.
    ///
    /// A status of 0 indicates that the public key could not be recovered.
    ///
    /// WARNING: This function is used to recover the public key outside of the zkVM context. These
    /// values must be constrained by the zkVM for correctness.
    #[must_use]
    pub fn hook_ecrecover_v2(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
        assert_eq!(
            buf.len(),
            65 + 32,
            "ecrecover input should have length 65 + 32, this is a bug."
        );
        let (sig, msg_hash) = buf.split_at(65);
        let sig: &[u8; 65] = sig.try_into().unwrap();
        let msg_hash: &[u8; 32] = msg_hash.try_into().unwrap();

        let mut recovery_id = sig[64];
        let mut sig = Signature::from_slice(&sig[..64]).unwrap();

        if let Some(sig_normalized) = sig.normalize_s() {
            sig = sig_normalized;
            recovery_id ^= 1;
        };
        let recid = RecoveryId::from_byte(recovery_id)
            .expect("Computed recovery ID is invalid, this is a bug.");

        // Attempting to recvover the public key has failed, write a 0 to indicate to the caller.
        let Ok(recovered_key) = VerifyingKey::recover_from_prehash(&msg_hash[..], &sig, recid)
        else {
            return vec![vec![0]];
        };

        let bytes = recovered_key.to_sec1_bytes();

        let (_, s) = sig.split_scalars();
        let s_inverse = s.invert();

        vec![vec![1], bytes.to_vec(), s_inverse.to_bytes().to_vec()]
    }

    /// Checks if a compressed Edwards point can be decompressed.
    ///
    /// # Arguments
    /// * `env` - The environment in which the hook is invoked.
    /// * `buf` - The buffer containing the compressed Edwards point.
    ///    - The compressed Edwards point is 32 bytes.
    ///    - The high bit of the last byte is the sign bit.
    ///
    /// The result is either `0` if the point cannot be decompressed, or `1` if it can.
    ///
    /// WARNING: This function merely hints at the validity of the compressed point. These values must
    /// be constrained by the zkVM for correctness.
    #[must_use]
    pub fn hook_ed_decompress(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
        let Ok(point) = sp1_curves::curve25519_dalek::CompressedEdwardsY::from_slice(buf) else {
            return vec![vec![0]];
        };

        if sp1_curves::edwards::ed25519::decompress(&point).is_some() {
            vec![vec![1]]
        } else {
            vec![vec![0]]
        }
    }
}

/// Pads a big uint to the given length in big endian.
fn pad_to_be(val: &BigUint, len: usize) -> Vec<u8> {
    // First take the byes in little endian
    let mut bytes = val.to_bytes_le();
    // Resize so we get the full padding correctly.
    bytes.resize(len, 0);
    // Convert back to big endian.
    bytes.reverse();

    bytes
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use super::*;

    #[test]
    pub fn registry_new_is_inhabited() {
        assert_ne!(HookRegistry::new().table.len(), 0);
        println!("{:?}", HookRegistry::new());
    }

    #[test]
    pub fn registry_empty_is_empty() {
        assert_eq!(HookRegistry::empty().table.len(), 0);
    }
}
