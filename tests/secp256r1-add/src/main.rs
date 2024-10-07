#![no_main]
sp1_zkvm::entrypoint!(main);

use p256::elliptic_curve::group::prime::PrimeCurveAffine;
use p256::elliptic_curve::group::GroupEncoding;
// use p256::elliptic_curve::{CurveArithmetic, PrimeCurveArithmetic};
// use p256::primeorder::{point_arithmetic, PrimeCurveParams};
use hex_literal::hex;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToCompactEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint};
use p256::{Scalar, U256};
use sp1_curves::params::FieldParameters;
use sp1_zkvm::lib::secp256r1::Secp256r1Point;

// const UNCOMPRESSED_BASEPOINT: &[u8] = &hex!(
//     "04 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
//         4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
// );

pub fn main() {
    // let a = sp1_curves::weierstrass::secp256r1::Secp256r1Point::from_le_bytes(&);
    // #![cfg(all(feature = "arithmetic"))]
    let G = AffinePoint::generator();
    let G_encoded = G.to_encoded_point(false);
    // let G_bytes = G.to_bytes();
    println!("G_encoded_bytes: {:?}", G_encoded.as_bytes());
    let scalar_2 = Scalar::from(2u32);
    let scalar_3 = Scalar::from(3u32);
    let double_G = G * scalar_2;
    let triple_G = G * scalar_3;
    let double_G_encoded = double_G.to_encoded_point(false);
    let triple_G_encoded = triple_G.to_encoded_point(false);
    println!("double_G_encoded_bytes: {:?}", double_G_encoded.as_bytes());
    println!("triple_G_encoded_bytes: {:?}", triple_G_encoded.as_bytes());

    // let double_G_bytes = double_G.to_bytes();
    // println!("double_G_bytes: {:?}", double_G_bytes);
    // let triple_G_bytes = triple_G.to_bytes();
    // println!("triple_G_bytes: {:?}", triple_G_bytes);

    common_test_utils::weierstrass_add::test_weierstrass_add::<
        Secp256r1Point,
        { sp1_lib::secp256r1::N },
    >(
        &G_encoded.as_bytes(),
        &double_G_encoded.as_bytes(),
        &triple_G_encoded.as_bytes(),
        sp1_curves::weierstrass::secp256r1::Secp256r1BaseField::MODULUS,
    );
}
