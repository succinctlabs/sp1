//! Modulo defining the Secp256k1 curve and its base field. The constants are all taken from
//! https://en.bitcoin.it/wiki/Secp256k1.

use std::str::FromStr;

use num::{BigUint, Zero};
use serde::{Deserialize, Serialize};

use super::{SWCurve, WeierstrassParameters};
use crate::operations::field::params::{NB_BITS_PER_LIMB, NUM_LIMBS};
use crate::utils::ec::field::{FieldParameters, MAX_NB_LIMBS};
use crate::utils::ec::EllipticCurveParameters;
use k256::FieldElement;
use num::traits::FromBytes;
use num::traits::ToBytes;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256k1 curve parameter
pub struct Secp256k1Parameters;

pub type Secp256k1 = SWCurve<Secp256k1Parameters>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256k1 base field parameter
pub struct Secp256k1BaseField;

impl FieldParameters for Secp256k1BaseField {
    const NB_BITS_PER_LIMB: usize = NB_BITS_PER_LIMB;

    const NB_LIMBS: usize = NUM_LIMBS;

    const NB_WITNESS_LIMBS: usize = 2 * Self::NB_LIMBS - 2;

    const MODULUS: [u8; MAX_NB_LIMBS] = [
        0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    /// A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 14;

    fn modulus() -> BigUint {
        BigUint::from_bytes_le(&Self::MODULUS)
    }
}

impl EllipticCurveParameters for Secp256k1Parameters {
    type BaseField = Secp256k1BaseField;
}

impl WeierstrassParameters for Secp256k1Parameters {
    const A: [u16; MAX_NB_LIMBS] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    const B: [u16; MAX_NB_LIMBS] = [
        7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    fn generator() -> (BigUint, BigUint) {
        let x = BigUint::from_str(
            "55066263022277343669578718895168534326250603453777594175500187360389116729240",
        )
        .unwrap();
        let y = BigUint::from_str(
            "32670510020758816978083085130507043184471273380659243275938904335757337482424",
        )
        .unwrap();
        (x, y)
    }

    fn prime_group_order() -> num::BigUint {
        BigUint::from_slice(&[
            0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ])
    }

    fn a_int() -> BigUint {
        BigUint::zero()
    }

    fn b_int() -> BigUint {
        BigUint::from(7u32)
    }
}

pub fn secp256k1_sqrt(n: &BigUint) -> BigUint {
    let be_bytes = n.to_be_bytes();
    let mut bytes = [0_u8; 32];
    bytes[32 - be_bytes.len()..].copy_from_slice(&be_bytes);
    let fe = FieldElement::from_bytes(&bytes.into()).unwrap();
    let result_bytes = fe.sqrt().unwrap().to_bytes();
    BigUint::from_be_bytes(&result_bytes as &[u8])
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils::ec::utils::biguint_from_limbs;
    use alloy_primitives::U256;
    use hex_literal::hex;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::RecoveryId;
    use k256::{
        ecdsa::{signature::Signer, Signature, SigningKey},
        SecretKey,
    };
    use k256::{
        ecdsa::{signature::Verifier, VerifyingKey},
        EncodedPoint,
    };
    use k256::{
        ecdsa::{Signature as K256Signature, VerifyingKey as K256VerifyingKey},
        PublicKey as K256PublicKey, Scalar,
    };
    use num::bigint::RandBigInt;
    use rand::thread_rng;
    use sha3::{Digest, Keccak256};

    #[test]
    fn test_weierstrass_biguint_scalar_mul() {
        assert_eq!(
            biguint_from_limbs(&Secp256k1BaseField::MODULUS),
            Secp256k1BaseField::modulus()
        );
    }

    #[test]
    fn test_secp256k_sqrt() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            // Check that sqrt(x^2)^2 == x^2
            // We use x^2 since not all field elements have a square root
            let x = rng.gen_biguint(256) % Secp256k1BaseField::modulus();
            let x_2 = (&x * &x) % Secp256k1BaseField::modulus();
            let sqrt = secp256k1_sqrt(&x_2);
            if sqrt > x_2 {
                println!("wtf");
            }

            let sqrt_2 = (&sqrt * &sqrt) % Secp256k1BaseField::modulus();

            assert_eq!(sqrt_2, x_2);
        }
    }

    #[test]
    fn test_secp256k1_signing() {
        let signing_key = SigningKey::from_bytes(
            &hex!("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").into(),
        )
        .unwrap();

        let msg = hex!(
            "e9808504e3b29200831e848094f0109fc8df283027b6285cc889f5aa624eac1f55843b9aca0080018080"
        );
        let digest = Keccak256::new_with_prefix(msg);

        println!("digest: {:?}", digest.clone().finalize().to_vec());

        let (sig, recid) = signing_key.sign_digest_recoverable(digest.clone()).unwrap();
        assert_eq!(
            sig.to_bytes().as_slice(),
            &hex!("c9cf86333bcb065d140032ecaab5d9281bde80f21b9687b3e94161de42d51895727a108a0b8d101465414033c3f705a9c7b826e596766046ee1183dbc8aeaa68")
        );
        println!("recid: {:?}", recid);
        assert_eq!(recid, RecoveryId::from_byte(0).unwrap());

        let verifying_key = VerifyingKey::recover_from_digest(digest.clone(), &sig, recid).unwrap();
        let pubkey_bytes = verifying_key.to_sec1_bytes();
        println!("pubkey: {:?}", pubkey_bytes);
        println!(
            "signature: {:?} {:?}",
            sig.r().to_bytes(),
            sig.s().to_bytes()
        );

        let pubkey_bytes = [
            2, 78, 59, 129, 175, 156, 34, 52, 202, 208, 157, 103, 156, 230, 3, 94, 209, 57, 35, 71,
            206, 100, 206, 64, 95, 93, 205, 54, 34, 138, 37, 222, 110,
        ];
        let r = U256::from_be_bytes([
            201, 207, 134, 51, 59, 203, 6, 93, 20, 0, 50, 236, 170, 181, 217, 40, 27, 222, 128,
            242, 27, 150, 135, 179, 233, 65, 97, 222, 66, 213, 24, 149,
        ]);
        let s = U256::from_be_bytes([
            114, 122, 16, 138, 11, 141, 16, 20, 101, 65, 64, 51, 195, 247, 5, 169, 199, 184, 38,
            229, 150, 118, 96, 70, 238, 17, 131, 219, 200, 174, 170, 104,
        ]);
        let message_hash = [
            136, 207, 189, 126, 81, 199, 164, 5, 64, 178, 51, 207, 104, 182, 42, 209, 223, 62, 146,
            70, 47, 28, 96, 24, 214, 214, 126, 174, 15, 59, 8, 245,
        ];

        // This is normal verification
        let public_key = K256PublicKey::from_sec1_bytes(&pubkey_bytes).expect("invalid pubkey");
        let signature =
            K256Signature::from_scalars(r.to_be_bytes(), s.to_be_bytes()).expect("r, s invalid");
        let verify_key = K256VerifyingKey::from(&public_key);
        verify_key
            .verify_prehash(&message_hash, &signature)
            .expect("invalid signature");

        println!("\n\n");

        println!("hi");
        let mut rng = thread_rng();
        let signing_key = SigningKey::random(&mut rng);
        let message =
            b"ECDSA proves knowledge of a secret number in the context of a single message";
        let signature: Signature = signing_key.sign(message);
        let verifying_key = VerifyingKey::from(&signing_key); // Serialize with `::to_encoded_point()`

        let pubkey_bytes = verifying_key.to_sec1_bytes();
        println!("pubkey: {:?}", pubkey_bytes);
        println!("signature: {:?}", signature);

        assert!(verifying_key.verify(message, &signature).is_ok());
    }
}
