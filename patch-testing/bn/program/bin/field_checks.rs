#![no_main]
sp1_zkvm::entrypoint!(main);

macro_rules! check_fields {
    ($bn:ident) => {{
        let x = $bn::Fq::from_str("9").unwrap();
        let root = x.sqrt().unwrap();
        assert_eq!(root * root, x);
        assert_eq!(root, x.sqrt().unwrap());
        assert!(root < -root);
        assert!($bn::Fq::from_str("3").unwrap().sqrt().is_none());
        assert_eq!($bn::Fq::zero().sqrt().unwrap(), $bn::Fq::zero());

        let x2 = $bn::Fq2::new(x, $bn::Fq::zero());
        let root2 = x2.sqrt().unwrap();
        assert_eq!(root2 * root2, x2);
        assert_eq!(root2, x2.sqrt().unwrap());
        let neg_root2 = -root2;
        assert!((root2.imaginary(), root2.real()) < (neg_root2.imaginary(), neg_root2.real()));
        let y2 = $bn::Fq2::new($bn::Fq::from_str("2").unwrap(), $bn::Fq::one());
        let square2 = y2 * y2;
        let root2 = square2.sqrt().unwrap();
        assert_eq!(root2 * root2, square2);
        let neg_root2 = -root2;
        assert!((root2.imaginary(), root2.real()) < (neg_root2.imaginary(), neg_root2.real()));
        assert!(y2.sqrt().is_none());
        assert!($bn::Fq2::zero().sqrt().unwrap() == $bn::Fq2::zero());

        assert!($bn::Fq::from_u256($bn::Fq::modulus()).is_err());
        let mut modulus = [0u8; 32];
        $bn::Fq::modulus().to_big_endian(&mut modulus).unwrap();
        for byte in modulus.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
        assert!($bn::Fq::from_u256($bn::arith::U256::from_slice(&modulus).unwrap()).is_err());
    }};
}

pub fn main() {
    check_fields!(substrate_bn);
    check_fields!(substrate_bn_substrate);
    sp1_zkvm::io::commit(&true);
}
