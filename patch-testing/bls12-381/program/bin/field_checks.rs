#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    use bls12_381::{fp::Fp, fp2::Fp2};
    let four = Fp::one() + Fp::one();
    let four = four + four;
    let root = four.sqrt().unwrap();
    assert_eq!(root * root, four);
    assert_eq!(root, four.sqrt().unwrap());
    assert!(!bool::from(root.lexicographically_largest()));
    assert!(bool::from((Fp::one() + Fp::one()).sqrt().is_none()));
    assert_eq!(Fp::zero().sqrt().unwrap(), Fp::zero());

    let four2 = Fp2::from(four);
    let root2 = four2.sqrt().unwrap();
    assert_eq!(root2 * root2, four2);
    assert_eq!(root2, four2.sqrt().unwrap());
    assert!(!bool::from(root2.lexicographically_largest()));
    let y2 = Fp2 { c0: Fp::one(), c1: Fp::one() };
    let square2 = y2 * y2;
    let root2 = square2.sqrt().unwrap();
    assert_eq!(root2 * root2, square2);
    assert!(!bool::from(root2.lexicographically_largest()));
    assert!(bool::from(y2.sqrt().is_none()));
    assert_eq!(Fp2::zero().sqrt().unwrap(), Fp2::zero());

    let mut modulus = (-Fp::one()).to_bytes();
    for byte in modulus.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    assert!(bool::from(Fp::from_bytes(&modulus).is_none()));
    for byte in modulus.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    assert!(bool::from(Fp::from_bytes(&modulus).is_none()));
    sp1_zkvm::io::commit(&true);
}
