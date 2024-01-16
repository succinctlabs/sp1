pub mod ops;
// pub mod parser;

use p3_field::Field;

use core::fmt::Debug;
use core::iter;
use core::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub};

use self::ops::PolynomialOps;
// use crate::utils::field::biguint_to_16_digits_field;

/// A wrapper around a vector of elements to represent a polynomial.
#[derive(Debug, Clone)]
pub struct Polynomial<T> {
    pub coefficients: Vec<T>,
}

impl<T: Clone> Polynomial<T> {
    pub fn from_coefficients(coefficients: Vec<T>) -> Self {
        Self { coefficients }
    }

    pub fn from_coefficients_slice(coefficients: &[T]) -> Self {
        Self {
            coefficients: coefficients.to_vec(),
        }
    }

    pub fn as_coefficients(self) -> Vec<T> {
        self.coefficients
    }

    #[inline]
    pub fn coefficients(&self) -> &[T] {
        &self.coefficients
    }

    // pub fn from_biguint_field(num: &BigUint, num_bits: usize, num_limbs: usize) -> Self
    // where
    //     T: Field,
    // {
    //     assert_eq!(num_bits, 16, "Only 16 bit numbers supported");
    //     Self::from_coefficients(biguint_to_16_digits_field(num, num_limbs))
    // }
}

impl<T> Polynomial<T> {
    pub fn degree(&self) -> usize {
        self.coefficients.len() - 1
    }

    pub fn eval<S>(&self, x: S) -> S
    where
        T: Copy,
        S: One<Output = S>,
        S: Add<Output = S> + MulAssign + Mul<T, Output = S> + Copy + iter::Sum,
    {
        PolynomialOps::eval::<T, S, S>(&self.coefficients, &x)
    }

    pub fn root_quotient(&self, r: T) -> Self
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
        Self::from_coefficients(PolynomialOps::root_quotient(&self.coefficients, &r))
    }
}

impl<T> FromIterator<T> for Polynomial<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self {
            coefficients: iter.into_iter().collect(),
        }
    }
}

impl<T: Add<Output = T> + Copy + Default> Add for Polynomial<T> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self::from_coefficients(PolynomialOps::add(
            self.coefficients(),
            other.coefficients(),
        ))
    }
}

impl<T: Add<Output = T> + Copy + Default> Add for &Polynomial<T> {
    type Output = Polynomial<T>;

    fn add(self, other: Self) -> Polynomial<T> {
        Polynomial::from_coefficients(PolynomialOps::add(
            self.coefficients(),
            other.coefficients(),
        ))
    }
}

impl<T: Add<Output = T> + Copy + Default> Add<&Polynomial<T>> for Polynomial<T> {
    type Output = Polynomial<T>;

    fn add(self, other: &Polynomial<T>) -> Polynomial<T> {
        Polynomial::from_coefficients(PolynomialOps::add(
            self.coefficients(),
            other.coefficients(),
        ))
    }
}

impl<T: Mul<Output = T> + Add<Output = T> + AddAssign + Copy + Default> Add<T> for Polynomial<T> {
    type Output = Polynomial<T>;

    fn add(self, other: T) -> Polynomial<T> {
        let mut coefficients = self.coefficients;
        coefficients[0] += other;
        Self::from_coefficients(coefficients)
    }
}

impl<T: Mul<Output = T> + Add<Output = T> + AddAssign + Copy + Default> Add<T> for &Polynomial<T> {
    type Output = Polynomial<T>;

    fn add(self, other: T) -> Polynomial<T> {
        let mut coefficients = self.coefficients.clone();
        coefficients[0] += other;
        Polynomial::from_coefficients(coefficients)
    }
}

impl<T: Neg<Output = T> + Copy> Neg for Polynomial<T> {
    type Output = Self;

    fn neg(self) -> Self {
        Self::from_coefficients(PolynomialOps::neg(self.coefficients()))
    }
}

impl<T: Sub<Output = T> + Neg<Output = T> + Copy + Default> Sub for Polynomial<T> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self::from_coefficients(PolynomialOps::sub(
            self.coefficients(),
            other.coefficients(),
        ))
    }
}

impl<T: Sub<Output = T> + Neg<Output = T> + Copy + Default> Sub<&Polynomial<T>> for Polynomial<T> {
    type Output = Polynomial<T>;

    fn sub(self, other: &Polynomial<T>) -> Polynomial<T> {
        Polynomial::from_coefficients(PolynomialOps::sub(
            self.coefficients(),
            other.coefficients(),
        ))
    }
}

impl<T: Sub<Output = T> + Neg<Output = T> + Copy + Default> Sub for &Polynomial<T> {
    type Output = Polynomial<T>;

    fn sub(self, other: Self) -> Polynomial<T> {
        Polynomial::from_coefficients(PolynomialOps::sub(
            self.coefficients(),
            other.coefficients(),
        ))
    }
}

impl<T: Mul<Output = T> + Add<Output = T> + Copy + Default> Mul for Polynomial<T> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self::from_coefficients(PolynomialOps::mul(
            self.coefficients(),
            other.coefficients(),
        ))
    }
}

impl<T: Mul<Output = T> + Add<Output = T> + Copy + Default> Mul for &Polynomial<T> {
    type Output = Polynomial<T>;

    fn mul(self, other: Self) -> Polynomial<T> {
        Polynomial::from_coefficients(PolynomialOps::mul(
            self.coefficients(),
            other.coefficients(),
        ))
    }
}

impl<T: Mul<Output = T> + Add<Output = T> + Copy + Default> Mul<T> for Polynomial<T> {
    type Output = Self;

    fn mul(self, other: T) -> Self {
        Self::from_coefficients(PolynomialOps::scalar_mul(self.coefficients(), &other))
    }
}

impl<T: Mul<Output = T> + Add<Output = T> + Copy + Default> Mul<T> for &Polynomial<T> {
    type Output = Polynomial<T>;

    fn mul(self, other: T) -> Polynomial<T> {
        Polynomial::from_coefficients(PolynomialOps::scalar_mul(self.coefficients(), &other))
    }
}

impl<T: Default + Clone> Default for Polynomial<T> {
    fn default() -> Self {
        Self::from_coefficients(vec![T::default()])
    }
}

impl Polynomial<u8> {
    pub fn as_field<F: Field>(self) -> Polynomial<F> {
        Polynomial {
            coefficients: self
                .coefficients
                .iter()
                .map(|x| F::from_canonical_u8(*x))
                .collect(),
        }
    }
}

pub struct Eval<T>(T);

impl<T> From<T> for Eval<T> {
    fn from(f: T) -> Self {
        Self(f)
    }
}

pub struct PowersIter<T> {
    base: T,
    current: T,
}

impl<T: MulAssign + Copy> Iterator for PowersIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        let result = self.current;
        self.current *= self.base;
        Some(result)
    }
}

pub trait One {
    type Output;
    fn one() -> Self::Output;
}

pub trait Zero {
    type Output;
    fn zero() -> Self::Output;
}

impl<F: Field> One for Eval<F> {
    type Output = F;

    fn one() -> Self::Output {
        F::one()
    }
}

impl<F: Field> Zero for Eval<F> {
    type Output = F;

    fn zero() -> Self::Output {
        F::zero()
    }
}

pub fn get_powers<T>(x: T, one: T) -> PowersIter<T> {
    PowersIter {
        base: x,
        current: one,
    }
}
