use core::ops::{Add, Mul};
use itertools::Itertools;

use p3_field::{AbstractField, Field};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnivariatePolynomial<K> {
    pub coefficients: Vec<K>,
}

impl<K: Field> UnivariatePolynomial<K> {
    pub fn mul_by_x(&self) -> Self {
        let mut result = Vec::with_capacity(self.coefficients.len() + 1);
        result.push(K::zero());
        result.extend(&self.coefficients[..]);
        Self::new(result)
    }
}

/// Basic univariate polynomial operations.
impl<K: AbstractField> UnivariatePolynomial<K> {
    pub fn new(coefficients: Vec<K>) -> Self {
        Self { coefficients }
    }
    pub fn zero(degree: usize) -> Self {
        Self { coefficients: vec![K::zero(); degree + 1] }
    }

    pub fn one(degree: usize) -> Self {
        let zeros = vec![K::zero(); degree];
        let mut coefficients = vec![K::one()];
        coefficients.extend(zeros);
        Self { coefficients }
    }

    pub fn eval_at_point(&self, point: K) -> K {
        // Horner's method.
        self.coefficients.iter().rev().fold(K::zero(), |acc, x| acc * point.clone() + x.clone())
    }

    pub fn eval_one_plus_eval_zero(&self) -> K {
        if self.coefficients.is_empty() {
            K::zero()
        } else {
            self.coefficients[0].clone() + self.coefficients.iter().cloned().sum::<K>()
        }
    }
}

impl<K> IntoIterator for UnivariatePolynomial<K> {
    type Item = K;
    type IntoIter = std::vec::IntoIter<K>;

    fn into_iter(self) -> Self::IntoIter {
        self.coefficients.into_iter()
    }
}
/// Scalar multiplication for univariate polynomials.
impl<K: Field> Mul<K> for UnivariatePolynomial<K> {
    type Output = Self;

    fn mul(self, rhs: K) -> Self::Output {
        Self { coefficients: self.coefficients.into_iter().map(|x| x * rhs).collect() }
    }
}

/// Sum of two univariate polynomials.
impl<K: Field> Add for UnivariatePolynomial<K> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut new_coeffs = vec![K::zero(); self.coefficients.len().max(rhs.coefficients.len())];
        for (i, x) in new_coeffs.iter_mut().enumerate() {
            *x = *self.coefficients.get(i).unwrap_or(&K::zero())
                + *rhs.coefficients.get(i).unwrap_or(&K::zero());
        }
        UnivariatePolynomial::new(new_coeffs)
    }
}

/// Provide the polynomial that interpolates the given points `xs.zip_eq(ys)`.
///
/// Panics if `xs` contains duplicate points or if `xs.len() != ys.len()`.
pub fn interpolate_univariate_polynomial<K: Field>(xs: &[K], ys: &[K]) -> UnivariatePolynomial<K> {
    let mut result = UnivariatePolynomial::new(vec![K::zero()]);
    for (i, (x, y)) in xs.iter().zip_eq(ys).enumerate() {
        let (denominator, numerator) = xs.iter().enumerate().filter(|(j, _)| *j != i).fold(
            (K::one(), UnivariatePolynomial::new(vec![*y])),
            |(denominator, numerator), (_, xj)| {
                (denominator * (*x - *xj), numerator.mul_by_x() + numerator * (-*xj))
            },
        );
        result = result + numerator * denominator.inverse();
    }
    result
}

pub fn rlc_univariate_polynomials<K: Field>(
    polys: &[UnivariatePolynomial<K>],
    lambda: K,
) -> UnivariatePolynomial<K> {
    let mut result = UnivariatePolynomial::new(vec![K::zero()]);
    for poly in polys {
        result = result * lambda + poly.clone();
    }
    result
}

#[cfg(test)]
mod tests {
    use crate::{interpolate_univariate_polynomial, UnivariatePolynomial};
    use p3_field::AbstractField;
    use slop_baby_bear::BabyBear;

    type F = BabyBear;

    #[test]
    fn test_univariate_eval_at_point() {
        let poly = UnivariatePolynomial::new(vec![F::one(), F::one(), F::one()]);
        assert_eq!(poly.eval_at_point(F::two()), F::from_canonical_u16(7));
    }

    #[test]
    fn test_univariate_interpolate() {
        let xs = vec![F::zero(), F::one(), F::two()];
        let ys = vec![F::one(), F::two(), F::from_canonical_u16(7)];
        let poly = interpolate_univariate_polynomial(&xs, &ys);
        assert_eq!(poly.eval_at_point(F::zero()), F::one());
        assert_eq!(poly.eval_at_point(F::one()), F::two());
        assert_eq!(poly.eval_at_point(F::two()), F::from_canonical_u16(7));
    }
}
