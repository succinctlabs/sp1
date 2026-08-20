pub mod ed25519;

use generic_array::GenericArray;
use num::{BigUint, Zero};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

use ::curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};

use super::CurveType;
use crate::{
    params::{FieldParameters, NumLimbs},
    AffinePoint, EllipticCurve, EllipticCurveParameters,
};

use crate::{edwards::ed25519::Ed25519BaseField, params::NumWords};
use typenum::Unsigned;

pub type Limbs = <Ed25519BaseField as NumLimbs>::Limbs;
pub const NUM_LIMBS: usize = Limbs::USIZE;

pub type WordsFieldElement = <Ed25519BaseField as NumWords>::WordsFieldElement;
pub const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;

#[allow(unused)]
pub type WordsCurvePoint = <Ed25519BaseField as NumWords>::WordsCurvePoint;
pub const WORDS_CURVE_POINT: usize = WordsCurvePoint::USIZE;

pub trait EdwardsParameters: EllipticCurveParameters {
    const D: GenericArray<u8, <Self::BaseField as NumLimbs>::Limbs>;

    fn generator() -> (BigUint, BigUint);

    fn prime_group_order() -> BigUint;

    fn d_biguint() -> BigUint {
        let mut modulus = BigUint::zero();
        for (i, limb) in Self::D.iter().enumerate() {
            modulus += BigUint::from(*limb) << (8 * i);
        }
        modulus
    }

    fn neutral() -> (BigUint, BigUint) {
        (BigUint::from(0u32), BigUint::from(1u32))
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EdwardsCurve<E: EdwardsParameters>(pub E);

impl<E: EdwardsParameters> EdwardsParameters for EdwardsCurve<E> {
    const D: GenericArray<u8, <Self::BaseField as NumLimbs>::Limbs> = E::D;

    fn generator() -> (BigUint, BigUint) {
        E::generator()
    }

    fn prime_group_order() -> BigUint {
        E::prime_group_order()
    }

    fn d_biguint() -> BigUint {
        E::d_biguint()
    }

    fn neutral() -> (BigUint, BigUint) {
        E::neutral()
    }
}

impl<E: EdwardsParameters> EllipticCurveParameters for EdwardsCurve<E> {
    type BaseField = E::BaseField;
    const CURVE_TYPE: CurveType = E::CURVE_TYPE;
}

impl<E: EdwardsParameters> EdwardsCurve<E> {
    pub fn prime_group_order() -> BigUint {
        E::prime_group_order()
    }

    pub fn neutral() -> AffinePoint<Self> {
        let (x, y) = E::neutral();
        AffinePoint::new(x, y)
    }
}

impl<E: EdwardsParameters> EllipticCurve for EdwardsCurve<E> {
    fn ec_add(p: &AffinePoint<Self>, q: &AffinePoint<Self>) -> AffinePoint<Self> {
        p.ed_add(q)
    }

    fn ec_double(p: &AffinePoint<Self>) -> AffinePoint<Self> {
        p.ed_double()
    }

    fn ec_generator() -> AffinePoint<Self> {
        let (x, y) = E::generator();
        AffinePoint::new(x, y)
    }

    fn ec_neutral() -> Option<AffinePoint<Self>> {
        Some(Self::neutral())
    }

    fn ec_neg(p: &AffinePoint<Self>) -> AffinePoint<Self> {
        let modulus = E::BaseField::modulus();
        AffinePoint::new(&modulus - &p.x, p.y.clone())
    }
}

impl<E: EdwardsParameters> AffinePoint<EdwardsCurve<E>> {
    pub(crate) fn ed_add(
        &self,
        other: &AffinePoint<EdwardsCurve<E>>,
    ) -> AffinePoint<EdwardsCurve<E>> {
        let result = affine_to_dalek(self) + affine_to_dalek(other);
        dalek_to_affine(&result)
    }

    pub(crate) fn ed_double(&self) -> AffinePoint<EdwardsCurve<E>> {
        let point = affine_to_dalek(self);
        dalek_to_affine(&(point + point))
    }
}

fn affine_to_dalek<E: EdwardsParameters>(point: &AffinePoint<EdwardsCurve<E>>) -> EdwardsPoint {
    assert!(matches!(E::CURVE_TYPE, CurveType::Ed25519), "Dalek only supports Ed25519");

    let mut compressed = [0u8; 32];
    let y = point.y.to_bytes_le();
    compressed[..y.len()].copy_from_slice(&y);
    compressed[31] |= u8::from(point.x.bit(0)) << 7;

    CompressedEdwardsY(compressed).decompress().expect("edwards point must be valid")
}

fn dalek_to_affine<E: EdwardsParameters>(point: &EdwardsPoint) -> AffinePoint<EdwardsCurve<E>> {
    static SQRT_M1_TORSION_POINT: LazyLock<EdwardsPoint> = LazyLock::new(|| {
        CompressedEdwardsY([0u8; 32]).decompress().expect("(sqrt(-1), 0) must be valid")
    });

    const NEG_SQRT_M1: [u8; 32] = [
        61, 95, 241, 181, 216, 228, 17, 59, 135, 27, 208, 82, 249, 231, 188, 208, 88, 40, 4, 194,
        102, 255, 178, 212, 244, 32, 62, 176, 127, 219, 124, 84,
    ];

    let mut y_bytes = point.compress().to_bytes();
    y_bytes[31] &= 0x7f;

    // Adding (sqrt(-1), 0) maps (x, y) to (sqrt(-1) * y, sqrt(-1) * x).
    // This gives access to x through Dalek's compressed point interface.
    let mut x_times_sqrt_m1_bytes = (point + *SQRT_M1_TORSION_POINT).compress().to_bytes();
    x_times_sqrt_m1_bytes[31] &= 0x7f;

    let modulus = E::BaseField::modulus();
    let x = (BigUint::from_bytes_le(&x_times_sqrt_m1_bytes) * BigUint::from_bytes_le(&NEG_SQRT_M1))
        % modulus;
    let y = BigUint::from_bytes_le(&y_bytes);

    AffinePoint::new(x, y)
}

#[cfg(test)]
mod tests {

    use num::bigint::RandBigInt;
    use rand::thread_rng;

    use super::*;
    use crate::edwards::ed25519::{Ed25519, Ed25519Parameters};

    #[test]
    fn test_bigint_ed_add() {
        type E = Ed25519;
        let neutral = E::neutral();
        let base = E::ec_generator();

        assert_eq!(&base + &neutral, base);
        assert_eq!(&neutral + &base, base);
        assert_eq!(&neutral + &neutral, neutral);
    }

    #[test]
    fn test_biguint_scalar_mul() {
        type E = Ed25519;
        let base = E::ec_generator();

        let d = Ed25519Parameters::d_biguint();
        let p = <E as EllipticCurveParameters>::BaseField::modulus();
        assert_eq!((d * 121666u32) % &p, (&p - 121665u32) % &p);

        let mut rng = thread_rng();
        for _ in 0..10 {
            let x = rng.gen_biguint(24);
            let y = rng.gen_biguint(25);

            let x_base = &base * &x;
            let y_x_base = &x_base * &y;
            let xy = &x * &y;
            let xy_base = &base * &xy;
            assert_eq!(y_x_base, xy_base);
        }

        let order = BigUint::from(2u32).pow(252)
            + BigUint::from(27742317777372353535851937790883648493u128);
        assert_eq!(base, &base + &(&base * &order));
    }

    #[test]
    fn test_dalek_ed_add_matches_affine_formula() {
        type E = Ed25519;
        let base = E::ec_generator();
        let modulus = <E as EllipticCurveParameters>::BaseField::modulus();
        let d = Ed25519Parameters::d_biguint();
        let mut rng = thread_rng();

        for _ in 0..10 {
            let p = &base * &rng.gen_biguint(64);
            let q = &base * &rng.gen_biguint(64);
            let all_xy = (&p.x * &p.y * &q.x * &q.y) % &modulus;
            let dxy = (&d * all_xy) % &modulus;
            let den_x = ((1u32 + &dxy) % &modulus).modpow(&(&modulus - 2u32), &modulus);
            let den_y = ((1u32 + &modulus - dxy) % &modulus).modpow(&(&modulus - 2u32), &modulus);
            let expected_x = (&p.x * &q.y + &p.y * &q.x) * den_x % &modulus;
            let expected_y = (&p.y * &q.y + &p.x * &q.x) * den_y % &modulus;

            assert_eq!(&p + &q, AffinePoint::new(expected_x, expected_y));
            assert_eq!(E::ec_double(&p), &p + &p);
        }
    }
}
