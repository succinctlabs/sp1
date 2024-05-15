#![allow(unused)]

use crate::utils::{AffinePoint, CurveOperations};
use crate::{syscall_secp384r1_add, syscall_secp384r1_double};
use anyhow::Context;
use anyhow::{anyhow, Result};
use core::convert::TryInto;
use k256::ecdsa::hazmat::bits2field;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::RecoveryId;
use p384::ecdsa::{Signature, VerifyingKey};
use p384::elliptic_curve::ff::PrimeFieldBits;
use p384::elliptic_curve::ops::Invert;
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::elliptic_curve::PrimeField;
use p384::{NistP384, PublicKey, Scalar};

use crate::io;
use crate::unconstrained;

const NUM_WORDS: usize = 24;

#[derive(Copy, Clone)]
pub struct Secp384r1Operations;

impl CurveOperations<NUM_WORDS> for Secp384r1Operations {
    const GENERATOR: [u32; NUM_WORDS] = [
        1920338615, 978607672, 3210029420, 1426256477, 2186553912, 1509376480, 2343017368,
        1847409506, 4079005044, 2394015518, 3196781879, 2861025826, 2431258207, 2051218812,
        494829981, 174109134, 3052452032, 3923390739, 681186428, 4176747965, 2459098153,
        1570674879, 2519084143, 907533898,
    ];

    fn add_assign(limbs: &mut [u32; NUM_WORDS], other: &[u32; NUM_WORDS]) {
        unsafe {
            syscall_secp384r1_add(limbs.as_mut_ptr(), other.as_ptr());
        }
    }

    fn double(limbs: &mut [u32; NUM_WORDS]) {
        unsafe {
            syscall_secp384r1_double(limbs.as_mut_ptr());
        }
    }
}

/// Verifies a secp384r1 signature using the public key and the message hash. If the s_inverse is
/// provided, it will be validated and used to verify the signature. Otherwise, the inverse of s
/// will be computed and used.
///
/// Warning: this function does not check if the key is actually on the curve.
pub fn verify_signature(
    pubkey: &[u8; 97],
    msg_hash: &[u8; 48],
    signature: &Signature,
    s_inverse: Option<&Scalar>,
) -> bool {
    cfg_if::cfg_if! {
        if #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))] {
            let pubkey_x = Scalar::from_repr(bits2field::<NistP384>(&pubkey[1..49]).unwrap()).unwrap();
            let pubkey_y = Scalar::from_repr(bits2field::<NistP384>(&pubkey[49..]).unwrap()).unwrap();

            let mut pubkey_x_le_bytes = pubkey_x.to_bytes();
            pubkey_x_le_bytes.reverse();
            let mut pubkey_y_le_bytes = pubkey_y.to_bytes();
            pubkey_y_le_bytes.reverse();

            // Convert the public key to an affine point
            let affine = AffinePoint::<Secp384r1Operations, NUM_WORDS>::from(pubkey_x_le_bytes.into(), pubkey_y_le_bytes.into());

            const GENERATOR: AffinePoint<Secp384r1Operations, NUM_WORDS> = AffinePoint::<Secp384r1Operations, NUM_WORDS>::generator_in_affine();

            let field = bits2field::<NistP384>(msg_hash);
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
            let mut x_bytes_be = [0u8; 48];
            for i in 0..8 {
                x_bytes_be[i * 4..(i * 4) + 4].copy_from_slice(&res.limbs[i].to_le_bytes());
            }
            x_bytes_be.reverse();

            let x_field = bits2field::<NistP384>(&x_bytes_be);
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

#[allow(non_snake_case)]
fn double_and_add_base(
    a: &Scalar,
    A: &AffinePoint<Secp384r1Operations, NUM_WORDS>,
    b: &Scalar,
    B: &AffinePoint<Secp384r1Operations, NUM_WORDS>,
) -> Option<AffinePoint<Secp384r1Operations, NUM_WORDS>> {
    let mut res: Option<AffinePoint<Secp384r1Operations, NUM_WORDS>> = None;
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

/// Outside of the VM, computes the pubkey and s_inverse value from a signature and a message hash.
///
/// WARNING: The values are read from outside of the VM and are not constrained to be correct.
/// Either use `decompress_pubkey` and `verify_signature` to verify the results of this function, or
/// use `ecrecover`.
pub fn unconstrained_ecrecover(sig: &[u8; 97], msg_hash: &[u8; 48]) -> ([u8; 49], Scalar) {
    unconstrained! {
        let mut recovery_id = sig[96];
        let mut sig = Signature::from_slice(&sig[..96]).unwrap();

        if let Some(sig_normalized) = sig.normalize_s() {
            sig = sig_normalized;
            recovery_id ^= 1
        };
        let recid = RecoveryId::from_byte(recovery_id).expect("Recovery ID is valid");

        let recovered_key = VerifyingKey::recover_from_prehash(&msg_hash[..], &sig, recid).unwrap();
        let bytes = recovered_key.to_sec1_bytes();
        io::hint_slice(&bytes);

        let (_, s) = sig.split_scalars();
        let s_inverse = s.invert();
        io::hint_slice(&s_inverse.to_bytes());
    }

    let recovered_bytes: [u8; 49] = io::read_vec().try_into().unwrap();

    let s_inv_bytes: [u8; 48] = io::read_vec().try_into().unwrap();
    let s_inverse = Scalar::from_repr(bits2field::<NistP384>(&s_inv_bytes).unwrap()).unwrap();

    (recovered_bytes, s_inverse)
}
