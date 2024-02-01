#![no_main]

extern crate succinct_zkvm;

use alloy_primitives::U256;
use k256::ecdsa::hazmat::bits2field;
use k256::ecdsa::hazmat::VerifyPrimitive;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::ff::PrimeFieldBits;
use k256::elliptic_curve::ops::Invert;
use k256::elliptic_curve::ops::LinearCombination;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::{Field, PrimeField};
use k256::ProjectivePoint;
use k256::Secp256k1;
use k256::{
    ecdsa::{Signature as K256Signature, VerifyingKey as K256VerifyingKey},
    PublicKey as K256PublicKey, Scalar,
};

succinct_zkvm::entrypoint!(main);

extern "C" {
    /// Add-assign `P += Q` two affine points with given raw slice pointers 'p' and 'q'.
    fn syscall_secp256k1_add(p: *mut u32, q: *const u32);
    fn syscall_secp256k1_double(p: *mut u32);
    fn syscall_secp256k1_decompress(p: *mut [u8; 64], is_odd: bool);
}

/// An affine point on the Edwards curve.
///
/// The point is represented internally by bytes in order to ensure a contiguous memory layout.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AffinePoint {
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

    pub fn mul_by_pow_2(&self, k: u32) -> Self {
        let mut tmp: AffinePoint = *self;
        for _ in 0..k {
            tmp.double();
        }
        tmp
    }

    pub fn x(&self) -> [u8; 32] {
        let mut x_bytes_le = [0u8; 32];
        for i in 0..8 {
            x_bytes_le[i * 4..i * 4 + 4].copy_from_slice(&self.limbs[i].to_le_bytes());
        }
        x_bytes_le.reverse();
        x_bytes_le
    }
}
// #[allow(non_snake_case)]
// pub fn mul(a: &Scalar, A: &EdwardsPoint, b: &Scalar) -> EdwardsPoint {
//     let A = AffinePoint::from(*A);

//     double_and_add_base(a, &A, b).into()
// }

fn secp256k1_basepoint() -> AffinePoint {
    AffinePoint::from(
        Scalar::from_str_vartime(
            "55066263022277343669578718895168534326250603453777594175500187360389116729240",
        )
        .unwrap(),
        Scalar::from_str_vartime(
            "32670510020758816978083085130507043184471273380659243275938904335757337482424",
        )
        .unwrap(),
    )
}

#[allow(non_snake_case)]
fn double_and_add_base(
    a: &Scalar,
    A: &AffinePoint,
    b: &Scalar,
    B: &AffinePoint,
) -> Option<AffinePoint> {
    let mut res: Option<AffinePoint> = None;
    // let mut temp_B = secp256k1_basepoint();
    let mut temp_A = *A;
    let mut temp_B = *B;

    let a_bits = a.to_le_bits();
    let b_bits = b.to_le_bits();
    for (a_bit, b_bit) in a_bits.iter().zip(b_bits) {
        if *a_bit {
            match res.as_mut() {
                Some(mut res) => res.add_assign(&temp_A),
                None => res = Some(temp_A),
            };
        }

        if b_bit {
            match res.as_mut() {
                Some(mut res) => res.add_assign(&temp_B),
                None => res = Some(temp_B),
            };
        }

        temp_A.double();
        temp_B.double();
    }

    res
}

fn k256_decompress(compressed_key: [u8; 33]) -> [u8; 65] {
    let mut decompressed_key: [u8; 64] = [0; 64];
    decompressed_key[..32].copy_from_slice(&compressed_key[1..]);
    let is_odd = match compressed_key[0] {
        2 => false,
        3 => true,
        _ => panic!("Invalid compressed key"),
    };
    unsafe {
        syscall_secp256k1_decompress(&mut decompressed_key, is_odd);
    }

    let mut result: [u8; 65] = [0; 65];
    result[0] = 4;
    result[1..].copy_from_slice(&decompressed_key);

    result
}

pub fn main() {
    let pubkey_bytes = [
        2, 78, 59, 129, 175, 156, 34, 52, 202, 208, 157, 103, 156, 230, 3, 94, 209, 57, 35, 71,
        206, 100, 206, 64, 95, 93, 205, 54, 34, 138, 37, 222, 110,
    ];
    let r = U256::from_be_bytes([
        201, 207, 134, 51, 59, 203, 6, 93, 20, 0, 50, 236, 170, 181, 217, 40, 27, 222, 128, 242,
        27, 150, 135, 179, 233, 65, 97, 222, 66, 213, 24, 149,
    ]);
    let s = U256::from_be_bytes([
        114, 122, 16, 138, 11, 141, 16, 20, 101, 65, 64, 51, 195, 247, 5, 169, 199, 184, 38, 229,
        150, 118, 96, 70, 238, 17, 131, 219, 200, 174, 170, 104,
    ]);
    let message_hash = [
        136, 207, 189, 126, 81, 199, 164, 5, 64, 178, 51, 207, 104, 182, 42, 209, 223, 62, 146, 70,
        47, 28, 96, 24, 214, 214, 126, 174, 15, 59, 8, 245,
    ];

    let signature =
        K256Signature::from_scalars(r.to_be_bytes(), s.to_be_bytes()).expect("r, s invalid");
    let public_key_k256 = K256PublicKey::from_sec1_bytes(&pubkey_bytes).expect("invalid pubkey");

    let verify_key = K256VerifyingKey::from(&public_key_k256);
    let field = bits2field::<Secp256k1>(message_hash.as_slice()).unwrap();

    let v_affine = verify_key.as_affine();
    let q = ProjectivePoint::from(v_affine);
    let sig = signature;
    let z = Scalar::from_repr(field).unwrap();
    let (r, s) = sig.split_scalars();
    let s_inv = *s.invert_vartime();
    let u1 = z * s_inv;
    let u2 = *r * s_inv;
    println!(
        "=====\ngenerator: {:?}\nu1: {:?}\nq: {:?}\nu2: {:?}\n",
        ProjectivePoint::generator().to_affine().x(),
        u1,
        q.to_affine().x(),
        u2
    );
    // let x = ProjectivePoint::lincomb(&ProjectivePoint::generator(), &u1, &q, &u2).to_affine();
    // println!("=====x: {:?} ", x.x());

    // verify_key
    //     .verify_prehash(&message_hash, &signature)
    //     .expect("invalid signature");
    // println!("Normal verification worked");
    // println!("cycle-tracker-end: normal");

    let public_key = k256_decompress(pubkey_bytes);
    let pubkey_x = Scalar::from_repr(bits2field::<Secp256k1>(&public_key[1..33]).unwrap()).unwrap();
    let pubkey_y = Scalar::from_repr(bits2field::<Secp256k1>(&public_key[33..]).unwrap()).unwrap();
    let affine = AffinePoint::from(pubkey_x, pubkey_y);
    let field = bits2field::<Secp256k1>(message_hash.as_slice()).unwrap();
    let z = Scalar::from_repr(field).unwrap();
    let (r, s) = signature.split_scalars();
    let s_inv = *s.invert_vartime();
    assert_eq!(s_inv * s.as_ref(), Scalar::ONE);
    let u1 = z * s_inv;
    let u2 = *r * s_inv;
    let generator = AffinePoint::from_limbs([
        385357720, 1509065051, 768485593, 43777243, 3464956679, 1436574357, 4191992748, 2042521214,
        4212184248, 2621952143, 2793755673, 4246189128, 235997352, 1571093500, 648266853,
        1211816567,
    ]);
    // println!(
    //     "=====\ngenerator: {:?}\nu1: {:?}\nq: {:?}\nu2: {:?}\n",
    //     generator.x(),
    //     u1,
    //     affine.x(),
    //     u2
    // );
    let res = double_and_add_base(&u1, &generator, &u2, &affine).unwrap();
    // println!("=====x: {:?} ", res.x());
    let mut x_bytes_be = [0u8; 32];
    for i in 0..8 {
        x_bytes_be[i * 4..i * 4 + 4].copy_from_slice(&res.limbs[i].to_le_bytes());
    }
    x_bytes_be.reverse();
    let x_field = bits2field::<Secp256k1>(&x_bytes_be).unwrap();
    if *r == Scalar::from_repr(x_field).unwrap() {
        println!("Signature verifies!");
    } else {
        panic!("invalid signature");
    }

    println!("Done");
}
