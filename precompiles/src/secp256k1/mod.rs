#![allow(unused)]

use anyhow::Context;
use anyhow::{anyhow, Result};
use core::convert::TryInto;
use k256::ecdsa::hazmat::bits2field;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::elliptic_curve::ff::PrimeFieldBits;
use k256::elliptic_curve::ops::Invert;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{PublicKey, Scalar, Secp256k1};

/// Decompresses a compressed public key using secp256k1_decompress precompile.
pub fn decompress_pubkey(compressed_key: &[u8; 33]) -> Result<[u8; 65]> {
    cfg_if::cfg_if! {
        if #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))] {
            let mut decompressed_key: [u8; 64] = [0; 64];
            decompressed_key[..32].copy_from_slice(&compressed_key[1..]);
            let is_odd = match compressed_key[0] {
                2 => false,
                3 => true,
                _ => return Err(anyhow!("Invalid compressed key")),
            };
            unsafe {
                syscall_secp256k1_decompress(&mut decompressed_key, is_odd);
            }

            let mut result: [u8; 65] = [0; 65];
            result[0] = 4;
            result[1..].copy_from_slice(&decompressed_key);
            Ok(result)
        } else {
            let public_key = PublicKey::from_sec1_bytes(compressed_key).context("invalid pubkey")?;
            let bytes = public_key.to_encoded_point(false).to_bytes();
            let mut result: [u8; 65] = [0; 65];
            result.copy_from_slice(&bytes);
            Ok(result)
        }
    }
}

/// Verifies a secp256k1 signature using the public key and the message hash. If the s_inverse is
/// provided, it will be validated and used to verify the signature. Otherwise, the inverse of s
/// will be computed and used.
pub fn verify_signature(
    pubkey: &[u8; 65],
    msg_hash: &[u8; 32],
    signature: &Signature,
    s_inverse: Option<&Scalar>,
) -> bool {
    cfg_if::cfg_if! {
        if #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))] {
            let pubkey_x = Scalar::from_repr(bits2field::<Secp256k1>(&pubkey[1..33]).unwrap()).unwrap();
            let pubkey_y = Scalar::from_repr(bits2field::<Secp256k1>(&pubkey[33..]).unwrap()).unwrap();

            // Convert the public key to an affine point
            let affine = AffinePoint::from(pubkey_x, pubkey_y);

            let field = bits2field::<Secp256k1>(msg_hash);
            if field.is_err() {
                return false;
            }
            let field = Scalar::from_repr(field.unwrap()).unwrap();
            let z = field;
            let (r, s) = signature.split_scalars();
            let computed_s_inv;
            let s_inv = match s_inverse {
                Some(s_inv) => {
                    assert_eq!(s_inv * s.as_ref(), Scalar::ONE);
                    s_inv
                }
                None => {
                    computed_s_inv = s.invert();
                    &computed_s_inv
                }
            };

            let u1 = z * s_inv;
            let u2 = *r * s_inv;

            let res = double_and_add_base(&u1, &GENERATOR, &u2, &affine).unwrap();
            let mut x_bytes_be = [0u8; 32];
            for i in 0..8 {
                x_bytes_be[i * 4..(i * 4) + 4].copy_from_slice(&res.limbs[i].to_le_bytes());
            }
            x_bytes_be.reverse();

            let x_field = bits2field::<Secp256k1>(&x_bytes_be);
            if x_field.is_err() {
                return false;
            }
            *r == Scalar::from_repr(x_field.unwrap()).unwrap()
        } else {
            let public_key = PublicKey::from_sec1_bytes(pubkey);
            if public_key.is_err() {
                return false;
            }
            let public_key = public_key.unwrap();

            let verify_key = VerifyingKey::from(&public_key);
            let res = verify_key
                .verify_prehash(msg_hash, signature)
                .context("invalid signature");

            res.is_ok()
        }
    }
}

extern "C" {
    /// Add-assign `P += Q` two affine points with given raw slice pointers 'p' and 'q'.
    fn syscall_secp256k1_add(p: *mut u32, q: *const u32);
    fn syscall_secp256k1_double(p: *mut u32);
    fn syscall_secp256k1_decompress(p: &mut [u8; 64], is_odd: bool);
}

/// An affine point on the Edwards curve.
///
/// The point is represented internally by bytes in order to ensure a contiguous memory layout.
///
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct AffinePoint {
    limbs: [u32; 16],
}

impl AffinePoint {
    pub fn from(x: Scalar, y: Scalar) -> Self {
        let mut x_bytes = x.to_bytes();
        let mut y_bytes = y.to_bytes();
        // convert to LE
        x_bytes.reverse();
        y_bytes.reverse();
        let mut limbs = [0; 16];
        for i in 0..8 {
            let x_byte = u32::from_le_bytes(x_bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            let y_byte = u32::from_le_bytes(y_bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            limbs[i] = x_byte;
            limbs[i + 8] = y_byte;
        }
        Self { limbs }
    }

    pub const fn from_limbs(limbs: [u32; 16]) -> Self {
        Self { limbs }
    }

    pub fn add_assign(&mut self, other: &AffinePoint) {
        unsafe {
            syscall_secp256k1_add(self.limbs.as_mut_ptr(), other.limbs.as_ptr());
        }
    }

    pub fn double(&mut self) {
        unsafe {
            syscall_secp256k1_double(self.limbs.as_mut_ptr());
        }
    }
}

#[allow(non_snake_case)]
fn double_and_add_base(
    a: &Scalar,
    A: &AffinePoint,
    b: &Scalar,
    B: &AffinePoint,
) -> Option<AffinePoint> {
    let mut res: Option<AffinePoint> = None;
    let mut temp_A = *A;
    let mut temp_B = *B;

    let a_bits = a.to_le_bits();
    let b_bits = b.to_le_bits();
    for (a_bit, b_bit) in a_bits.iter().zip(b_bits) {
        if *a_bit {
            match res.as_mut() {
                Some(res) => res.add_assign(&temp_A),
                None => res = Some(temp_A),
            };
        }

        if b_bit {
            match res.as_mut() {
                Some(res) => res.add_assign(&temp_B),
                None => res = Some(temp_B),
            };
        }

        temp_A.double();
        temp_B.double();
    }

    res
}

const GENERATOR: AffinePoint = AffinePoint::from_limbs([
    385357720, 1509065051, 768485593, 43777243, 3464956679, 1436574357, 4191992748, 2042521214,
    4212184248, 2621952143, 2793755673, 4246189128, 235997352, 1571093500, 648266853, 1211816567,
]);
