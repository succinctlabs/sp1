use core::ops::Mul;

use num::{BigUint, One};

use super::{utils::biguint_to_bits_le, AffinePoint, EllipticCurve};

impl<E: EllipticCurve> AffinePoint<E> {
    pub fn scalar_mul(&self, scalar: &BigUint) -> Self {
        let power_two_modulus = BigUint::one() << E::nb_scalar_bits();
        let scalar = scalar % &power_two_modulus;
        let mut result = E::ec_neutral();
        let mut temp = self.clone();
        let bits = biguint_to_bits_le(&scalar, E::nb_scalar_bits());
        for bit in bits {
            if bit {
                result = result.map_or_else(|| Some(temp.clone()), |r| Some(&r + &temp));
            }
            temp = &temp + &temp;
        }
        result.expect("Scalar multiplication failed")
    }
}

impl<E: EllipticCurve> Mul<&BigUint> for &AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn mul(self, scalar: &BigUint) -> AffinePoint<E> {
        self.scalar_mul(scalar)
    }
}

impl<E: EllipticCurve> Mul<BigUint> for &AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn mul(self, scalar: BigUint) -> AffinePoint<E> {
        self.scalar_mul(&scalar)
    }
}

impl<E: EllipticCurve> Mul<BigUint> for AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn mul(self, scalar: BigUint) -> AffinePoint<E> {
        self.scalar_mul(&scalar)
    }
}
