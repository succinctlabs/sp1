use core::fmt::Debug;
use core::iter;
use core::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};

use itertools::Itertools;

use super::{get_powers, One};

/// A struct which implements helper methods for polynomial operations, such as addition and
/// multiplication.
#[derive(Debug, Clone, Copy)]
pub struct PolynomialOps;

impl PolynomialOps {
    /// Polynomial addition.
    pub fn add<T>(a: &[T], b: &[T]) -> Vec<T>
    where
        T: Add<Output = T> + Copy + Default,
    {
        a.iter()
            .zip_longest(b.iter())
            .map(|x| match x {
                itertools::EitherOrBoth::Both(a, b) => *a + *b,
                itertools::EitherOrBoth::Left(a) => *a,
                itertools::EitherOrBoth::Right(b) => *b,
            })
            .collect()
    }

    /// Polynomial addition with assignment. Assumes `a.len() >= b.len()`.
    pub fn add_assign<T>(a: &mut [T], b: &[T])
    where
        T: AddAssign + Copy,
    {
        debug_assert!(a.len() >= b.len(), "Expects a.len() >= b.len()");
        a.iter_mut().zip(b.iter()).for_each(|(a, b)| *a += *b);
    }

    /// Polynomial negation.
    pub fn neg<T>(a: &[T]) -> Vec<T>
    where
        T: Neg<Output = T> + Copy,
    {
        a.iter().map(|x| -*x).collect()
    }

    /// Polynomial subtraction.
    pub fn sub<T>(a: &[T], b: &[T]) -> Vec<T>
    where
        T: Sub<Output = T> + Copy + Neg<Output = T>,
    {
        a.iter()
            .zip_longest(b.iter())
            .map(|x| match x {
                itertools::EitherOrBoth::Both(a, b) => *a - *b,
                itertools::EitherOrBoth::Left(a) => *a,
                itertools::EitherOrBoth::Right(b) => -*b,
            })
            .collect()
    }

    /// Polynomial subtraction with assignment. Assumes `a.len() >= b.len()`.
    pub fn sub_assign<T>(a: &mut [T], b: &[T])
    where
        T: SubAssign + Copy,
    {
        debug_assert!(a.len() >= b.len());
        a.iter_mut().zip(b.iter()).for_each(|(a, b)| *a -= *b);
    }

    /// Polynomial multiplication.
    pub fn mul<T>(a: &[T], b: &[T]) -> Vec<T>
    where
        T: Add<Output = T> + Mul<Output = T> + Copy + Default + Add<Output = T>,
    {
        let mut result = vec![T::default(); a.len() + b.len() - 1];
        for i in 0..a.len() {
            for j in 0..b.len() {
                result[i + j] = result[i + j] + a[i] * b[j];
            }
        }
        result
    }

    /// Scalar polynomial addition.
    pub fn scalar_poly_add<T, S>(a: &[T], b: &[S]) -> Vec<T>
    where
        T: Add<S, Output = T> + Copy + Default,
        S: Copy,
    {
        debug_assert!(a.len() == b.len());
        a.iter().zip(b.iter()).map(|(a, b)| *a + *b).collect()
    }

    /// Scalar subtraction.
    pub fn scalar_sub<T, S>(a: &[T], b: &S) -> Vec<T>
    where
        T: Sub<S, Output = T> + Copy,
        S: Copy,
    {
        a.iter().map(|x| *x - *b).collect()
    }

    /// Scalar polynomial subtraction.
    pub fn scalar_poly_sub<T, S>(a: &[T], b: &[S]) -> Vec<T>
    where
        T: Sub<S, Output = T> + Copy + Default,
        S: Copy,
    {
        debug_assert!(a.len() == b.len());
        a.iter().zip(b.iter()).map(|(a, b)| *a - *b).collect()
    }

    /// Multiply a polynomial by a scalar.
    pub fn scalar_mul<T, S>(a: &[T], b: &S) -> Vec<T>
    where
        T: Mul<S, Output = T> + Copy,
        S: Copy,
    {
        a.iter().map(|x| *x * *b).collect()
    }

    /// Multiply a polynomial by a polynomial with a scalar coefficients.
    pub fn scalar_poly_mul<T, S>(a: &[T], b: &[S]) -> Vec<T>
    where
        T: Mul<S, Output = T> + Copy + Default + AddAssign,
        S: Copy,
    {
        let mut result = vec![T::default(); a.len() + b.len() - 1];
        for i in 0..a.len() {
            for j in 0..b.len() {
                result[i + j] += a[i] * b[j];
            }
        }
        result
    }

    /// Evaluate the polynomial at a point.
    pub fn eval<T, E, S>(a: &[T], x: &S) -> S
    where
        T: Copy,
        E: One<Output = S>,
        S: Add<Output = S> + MulAssign + Mul<T, Output = S> + Copy + iter::Sum,
    {
        let one = E::one();
        let powers = get_powers(*x, one);

        a.iter().zip(powers).map(|(a, x)| x.mul(*a)).sum()
    }

    /// Extract the quotient s(x) of a(x) such that (x-r)s(x) when r is a root of a(x). Panics if r = 0
    /// and does not check if r is a root of a(x)
    pub fn root_quotient<T>(a: &[T], r: &T) -> Vec<T>
    where
        T: Copy
            + Neg<Output = T>
            + Debug
            + MulAssign
            + Mul<Output = T>
            + Add<Output = T>
            + Sub<Output = T>
            + Div<Output = T>
            + PartialEq
            + Eq
            + iter::Sum,
    {
        let mut result = Vec::with_capacity(a.len() - 1);

        result.push(-a[0] / *r);
        for i in 1..a.len() - 1 {
            let element = result[i - 1] - a[i];
            result.push(element / *r);
        }
        result
    }
}
