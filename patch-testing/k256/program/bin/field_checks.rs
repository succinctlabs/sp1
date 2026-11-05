#![no_main]
sp1_zkvm::entrypoint!(main);

use k256::elliptic_curve::group::ff::{Field, PrimeField};

pub fn main() {
    let nine = k256::FieldElement::from_u64(9);
    let root = nine.sqrt().unwrap();
    assert_eq!(root, k256::FieldElement::from_u64(3));
    assert_eq!(root, nine.sqrt().unwrap());
    assert!(root.to_bytes() < (-root).to_bytes());
    assert!(bool::from(k256::FieldElement::from_u64(3).sqrt().is_none()));
    assert_eq!(k256::FieldElement::ZERO.sqrt().unwrap(), k256::FieldElement::ZERO);

    for n in 2..=10u64 {
        let square = k256::Scalar::from(n).square();
        let root = square.sqrt().unwrap();
        assert_eq!(root, square.sqrt().unwrap());
        assert!(root.to_bytes() < (-root).to_bytes());
    }
    assert!(bool::from(k256::Scalar::from(5u64).sqrt().is_none()));
    assert_eq!(k256::Scalar::ZERO.sqrt().unwrap(), k256::Scalar::ZERO);

    let mut modulus = (-k256::FieldElement::ONE).to_bytes();
    for byte in modulus.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    assert!(bool::from(k256::FieldElement::from_repr(modulus).is_none()));
    for byte in modulus.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    assert!(bool::from(k256::FieldElement::from_repr(modulus).is_none()));

    let mut modulus = (-k256::Scalar::ONE).to_bytes();
    for _ in 0..2 {
        for byte in modulus.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
        assert!(bool::from(k256::Scalar::from_repr(modulus).is_none()));
    }

    sp1_zkvm::io::commit(&true);
}
