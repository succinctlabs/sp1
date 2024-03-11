use core::ops::Mul;

use num::{BigUint, One};

use super::utils::biguint_to_bits_le;
use super::AffinePoint;
use super::EllipticCurve;

impl<E: EllipticCurve<N>, const N: usize> AffinePoint<E, N> {
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

impl<E: EllipticCurve<N>, const N: usize> Mul<&BigUint> for &AffinePoint<E, N> {
    type Output = AffinePoint<E, N>;

    fn mul(self, scalar: &BigUint) -> AffinePoint<E, N> {
        self.scalar_mul(scalar)
    }
}

impl<E: EllipticCurve<N>, const N: usize> Mul<BigUint> for &AffinePoint<E, N> {
    type Output = AffinePoint<E, N>;

    fn mul(self, scalar: BigUint) -> AffinePoint<E, N> {
        self.scalar_mul(&scalar)
    }
}

impl<E: EllipticCurve<N>, const N: usize> Mul<BigUint> for AffinePoint<E, N> {
    type Output = AffinePoint<E, N>;

    fn mul(self, scalar: BigUint) -> AffinePoint<E, N> {
        self.scalar_mul(&scalar)
    }
}
