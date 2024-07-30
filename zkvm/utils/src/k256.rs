use anyhow::{anyhow, Result};
use k256::{
    ecdsa::hazmat::bits2field,
    elliptic_curve::{ff::PrimeFieldBits, PrimeField},
};
/// ECDSA/secp256k1 verification key (i.e. public key)
use sp1_lib::{
    io::{self, FD_ECRECOVER_HOOK},
    syscall_secp256k1_decompress,
    utils::AffinePoint as SP1AffinePoint,
};
use sp1_lib::{secp256k1::Secp256k1AffinePoint, unconstrained};

use k256::{ecdsa::Signature, Scalar, Secp256k1};

#[allow(non_snake_case)]
pub(crate) fn double_and_add_base(
    a: &Scalar,
    A: &Secp256k1AffinePoint,
    b: &Scalar,
    B: &Secp256k1AffinePoint,
) -> Option<Secp256k1AffinePoint> {
    let mut res: Option<Secp256k1AffinePoint> = None;
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
/// use `recover_ecdsa`.
pub(crate) fn unconstrained_recover_ecdsa(
    sig: &[u8; 65],
    msg_hash: &[u8; 32],
) -> ([u8; 33], Scalar) {
    // The `unconstrained!` wrapper is used since none of these computations directly affect
    // the output values of the VM. The remainder of the function sets the constraints on the values
    // instead. Removing the `unconstrained!` wrapper slightly increases the cycle count.
    unconstrained! {
        let mut buf = [0; 65 + 32];
        let (buf_sig, buf_msg_hash) = buf.split_at_mut(sig.len());
        buf_sig.copy_from_slice(sig);
        buf_msg_hash.copy_from_slice(msg_hash);
        io::write(FD_ECRECOVER_HOOK, &buf);
    }
    let recovered_bytes: [u8; 33] = io::read_vec().try_into().unwrap();
    let s_inv_bytes: [u8; 32] = io::read_vec().try_into().unwrap();
    let s_inverse = Scalar::from_repr(bits2field::<Secp256k1>(&s_inv_bytes).unwrap()).unwrap();
    (recovered_bytes, s_inverse)
}

pub(crate) fn verify_signature(
    pubkey: &[u8; 65],
    msg_hash: &[u8; 32],
    signature: &Signature,
    s_inverse: Option<&Scalar>,
) -> bool {
    let pubkey_x = Scalar::from_repr(bits2field::<Secp256k1>(&pubkey[1..33]).unwrap()).unwrap();
    let pubkey_y = Scalar::from_repr(bits2field::<Secp256k1>(&pubkey[33..]).unwrap()).unwrap();
    let mut pubkey_x_le_bytes = pubkey_x.to_bytes();
    pubkey_x_le_bytes.reverse();
    let mut pubkey_y_le_bytes = pubkey_y.to_bytes();
    pubkey_y_le_bytes.reverse();
    // Convert the public key to an affine point
    let affine =
        Secp256k1AffinePoint::from_le_bytes(&[pubkey_x_le_bytes, pubkey_y_le_bytes].concat());
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
            computed_s_inv = s.invert().unwrap();
            &computed_s_inv
        }
    };
    let u1 = z * s_inv;
    let u2 = *r * s_inv;
    let res = double_and_add_base(
        &u1,
        &Secp256k1AffinePoint(Secp256k1AffinePoint::GENERATOR),
        &u2,
        &affine,
    )
    .unwrap();
    let mut x_bytes_be = [0u8; 32];
    for i in 0..8 {
        x_bytes_be[i * 4..(i * 4) + 4].copy_from_slice(&res.0[i].to_le_bytes());
    }
    x_bytes_be.reverse();
    let x_field = bits2field::<Secp256k1>(&x_bytes_be);
    if x_field.is_err() {
        return false;
    }
    *r == Scalar::from_repr(x_field.unwrap()).unwrap()
}

pub(crate) fn decompress_pubkey(compressed_key: &[u8; 33]) -> Result<[u8; 65]> {
    let mut decompressed_key: [u8; 64] = [0; 64];
    decompressed_key[..32].copy_from_slice(&compressed_key[1..]);
    let is_odd = match compressed_key[0] {
        2 => false,
        3 => true,
        _ => return Err(anyhow!("invalid compressed key")),
    };

    unsafe {
        syscall_secp256k1_decompress(&mut decompressed_key, is_odd);
    }

    let mut result: [u8; 65] = [0; 65];
    result[0] = 4;
    result[1..].copy_from_slice(&decompressed_key);
    Ok(result)
}
