pub mod ed25519;

use num::{BigUint, Zero};
use serde::{Deserialize, Serialize};

use crate::utils::ec::field::{FieldParameters, MAX_NB_LIMBS};
use crate::utils::ec::{AffinePoint, EllipticCurve, EllipticCurveParameters};

pub trait EdwardsParameters: EllipticCurveParameters {
    const D: [u16; MAX_NB_LIMBS];

    fn generator() -> (BigUint, BigUint);

    fn prime_group_order() -> BigUint;

    fn d_biguint() -> BigUint {
        let mut modulus = BigUint::zero();
        for (i, limb) in Self::D.iter().enumerate() {
            modulus += BigUint::from(*limb) << (16 * i);
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
    const D: [u16; MAX_NB_LIMBS] = E::D;

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
    const NAME: &'static str = E::NAME;
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
        let p = E::BaseField::modulus();
        let x_3n = (&self.x * &other.y + &self.y * &other.x) % &p;
        let y_3n = (&self.y * &other.y + &self.x * &other.x) % &p;

        let all_xy = (&self.x * &self.y * &other.x * &other.y) % &p;
        let d = E::d_biguint();
        let dxy = (d * &all_xy) % &p;
        let den_x = ((1u32 + &dxy) % &p).modpow(&(&p - 2u32), &p);
        let den_y = ((1u32 + &p - &dxy) % &p).modpow(&(&p - 2u32), &p);

        let x_3 = (&x_3n * &den_x) % &p;
        let y_3 = (&y_3n * &den_y) % &p;

        AffinePoint::new(x_3, y_3)
    }

    pub(crate) fn ed_double(&self) -> AffinePoint<EdwardsCurve<E>> {
        self.ed_add(self)
    }
}

#[cfg(test)]
mod tests {

    use num::bigint::RandBigInt;
    use num::BigUint;
    use rand::thread_rng;

    use super::{EdwardsParameters, *};
    use crate::utils::ec::edwards::ed25519::{Ed25519, Ed25519Parameters};
    use crate::utils::ec::{EllipticCurve, EllipticCurveParameters};

    #[test]
    fn test_bigint_ed_add() {
        type E = Ed25519;
        let netural = E::neutral();
        let base = E::ec_generator();

        assert_eq!(&base + &netural, base);
        assert_eq!(&netural + &base, base);
        assert_eq!(&netural + &netural, netural);
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
}
