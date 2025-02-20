use core::fmt::Debug;
use core::ops::{Add, AddAssign, Mul, Neg, Sub};

use itertools::Itertools;
use p3_field::{AbstractExtensionField, AbstractField, Field};

/// A polynomial represented as a vector of coefficients.
#[derive(Debug, Clone)]
pub struct Polynomial<T> {
    coefficients: Vec<T>,
}

impl<T> Polynomial<T> {
    /// Create a new polynomial from a vector of coefficients.
    pub const fn new(coefficients: Vec<T>) -> Self {
        Self { coefficients }
    }

    /// Create a new polynomial from a slice of coefficients.
    pub fn from_coefficients(coefficients: &[T]) -> Self
    where
        T: Clone,
    {
        Self {
            coefficients: coefficients.to_vec(),
        }
    }

    /// Gets the coefficients of the polynomial.
    pub fn as_coefficients(self) -> Vec<T> {
        self.coefficients
    }

    /// Gets the coefficients of the polynomial.
    pub fn coefficients(&self) -> &[T] {
        &self.coefficients
    }

    /// Gets the degree of the polynomial.
    pub fn degree(&self) -> usize {
        self.coefficients.len().saturating_sub(1)
    }

    /// Evaluates the polynomial at a given point.
    pub fn eval<S: AbstractExtensionField<T>>(&self, x: S) -> S
    where
        T: AbstractField,
    {
        let mut result = S::zero();
        let mut power = S::one();
        for coeff in &self.coefficients {
            result += power.clone() * coeff.clone();
            power *= x.clone();
        }
        result
    }

    /// Computes the root quotient of the polynomial.
    pub fn root_quotient(&self, r: T) -> Self
    where
        T: Field,
    {
        let len = self.coefficients.len();
        if len == 0 {
            return Self::new(vec![]);
        }
        let mut result = Vec::with_capacity(len - 1);
        let r_inv = r.inverse();

        result.push(-self.coefficients[0].clone() * r_inv.clone());
        for i in 1..len - 1 {
            let element = result[i - 1].clone() - self.coefficients[i].clone();
            result.push(element * r_inv.clone());
        }
        Self {
            coefficients: result,
        }
    }

    /// Computes the derivative of the polynomial.
    pub fn derivative(&self) -> Self
    where
        T: AbstractField + From<u8>,
    {
        if self.coefficients.is_empty() {
            return Self::new(vec![]);
        }
        let mut result = Vec::with_capacity(self.degree());
        for (i, coeff) in self.coefficients.iter().enumerate().skip(1) {
            result.push(coeff.clone() * T::from(i as u8));
        }
        Self::new(result)
    }

    /// Computes the integral of the polynomial.
    pub fn integral(&self) -> Self
    where
        T: AbstractField + From<u8>,
    {
        let mut result = Vec::with_capacity(self.coefficients.len() + 1);
        result.push(T::zero());
        for (i, coeff) in self.coefficients.iter().enumerate() {
            result.push(coeff.clone() / T::from((i + 1) as u8));
        }
        Self::new(result)
    }

    /// Scales the polynomial by a scalar.
    pub fn scale(&self, scalar: T) -> Self
    where
        T: AbstractField,
    {
        Self::new(
            self.coefficients
                .iter()
                .map(|coeff| coeff.clone() * scalar.clone())
                .collect(),
        )
    }
}

impl<T> FromIterator<T> for Polynomial<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self {
            coefficients: iter.into_iter().collect(),
        }
    }
}

impl<T: Add<Output = T> + Clone> Add for Polynomial<T> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self + &other
    }
}

impl<T: Add<Output = T> + Clone> Add for &Polynomial<T> {
    type Output = Polynomial<T>;

    fn add(self, other: Self) -> Polynomial<T> {
        self.coefficients
            .iter()
            .zip_longest(other.coefficients.iter())
            .map(|x| match x {
                itertools::EitherOrBoth::Both(a, b) => a.clone() + b.clone(),
                itertools::EitherOrBoth::Left(a) => a.clone(),
                itertools::EitherOrBoth::Right(b) => b.clone(),
            })
            .collect()
    }
}

impl<T: Add<Output = T> + Clone> Add<&Polynomial<T>> for Polynomial<T> {
    type Output = Polynomial<T>;

    fn add(self, other: &Polynomial<T>) -> Polynomial<T> {
        self.coefficients
            .iter()
            .zip_longest(other.coefficients.iter())
            .map(|x| match x {
                itertools::EitherOrBoth::Both(a, b) => a.clone() + b.clone(),
                itertools::EitherOrBoth::Left(a) => a.clone(),
                itertools::EitherOrBoth::Right(b) => b.clone(),
            })
            .collect()
    }
}

impl<T: Mul<Output = T> + Add<Output = T> + AddAssign + Clone> Add<T> for Polynomial<T> {
    type Output = Polynomial<T>;

    fn add(self, other: T) -> Polynomial<T> {
        let mut coefficients = self.coefficients;
        coefficients[0] += other;
        Self::new(coefficients)
    }
}

impl<T: Mul<Output = T> + Add<Output = T> + Add + Clone> Add<T> for &Polynomial<T> {
    type Output = Polynomial<T>;

    fn add(self, other: T) -> Polynomial<T> {
        let mut coefficients = self.coefficients.clone();
        coefficients[0] = coefficients[0].clone() + other;
        Polynomial::new(coefficients)
    }
}

impl<T: Neg<Output = T>> Neg for Polynomial<T> {
    type Output = Self;

    fn neg(self) -> Self {
        Self::new(self.coefficients.into_iter().map(|x| -x).collect())
    }
}

impl<T: Sub<Output = T> + Neg<Output = T> + Clone> Sub for Polynomial<T> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self - &other
    }
}

impl<T: Sub<Output = T> + Neg<Output = T> + Clone> Sub<&Polynomial<T>> for Polynomial<T> {
    type Output = Polynomial<T>;

    fn sub(self, other: &Polynomial<T>) -> Polynomial<T> {
        Polynomial::new(
            self.coefficients
                .iter()
                .zip_longest(other.coefficients.iter())
                .map(|x| match x {
                    itertools::EitherOrBoth::Both(a, b) => a.clone() - b.clone(),
                    itertools::EitherOrBoth::Left(a) => a.clone(),
                    itertools::EitherOrBoth::Right(b) => -b.clone(),
                })
                .collect(),
        )
    }
}

impl<T: Sub<Output = T> + Neg<Output = T> + Clone> Sub for &Polynomial<T> {
    type Output = Polynomial<T>;

    fn sub(self, other: Self) -> Polynomial<T> {
        Polynomial::new(
            self.coefficients
                .iter()
                .zip_longest(other.coefficients.iter())
                .map(|x| match x {
                    itertools::EitherOrBoth::Both(a, b) => a.clone() - b.clone(),
                    itertools::EitherOrBoth::Left(a) => a.clone(),
                    itertools::EitherOrBoth::Right(b) => -b.clone(),
                })
                .collect(),
        )
    }
}

impl<T: AbstractField> Mul for Polynomial<T> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let mut result = vec![T::zero(); self.coefficients.len() + other.coefficients.len() - 1];
        for (i, a) in self.coefficients.into_iter().enumerate() {
            for (j, b) in other.coefficients.iter().enumerate() {
                result[i + j] = result[i + j].clone() + a.clone() * b.clone();
            }
        }
        Self::new(result)
    }
}

impl<T: AbstractField> Mul for &Polynomial<T> {
    type Output = Polynomial<T>;

    fn mul(self, other: Self) -> Polynomial<T> {
        let mut result = vec![T::zero(); self.coefficients.len() + other.coefficients.len() - 1];
        for (i, a) in self.coefficients.iter().enumerate() {
            for (j, b) in other.coefficients.iter().enumerate() {
                result[i + j] = result[i + j].clone() + a.clone() * b.clone();
            }
        }
        Polynomial::new(result)
    }
}

impl<T: AbstractField> Mul<T> for Polynomial<T> {
    type Output = Self;

    fn mul(self, other: T) -> Self {
        Self::new(
            self.coefficients
                .into_iter()
                .map(|x| x * other.clone())
                .collect(),
        )
    }
}

impl<T: AbstractField> Mul<T> for &Polynomial<T> {
    type Output = Polynomial<T>;

    fn mul(self, other: T) -> Polynomial<T> {
        Polynomial::new(
            self.coefficients
                .iter()
                .cloned()
                .map(|x| x * other.clone())
                .collect(),
        )
    }
}

impl<T: Eq + AbstractField> PartialEq<Polynomial<T>> for Polynomial<T> {
    fn eq(&self, other: &Polynomial<T>) -> bool {
        if self.coefficients.len() != other.coefficients.len() {
            let (shorter, longer) = if self.coefficients.len() < other.coefficients.len() {
                (self, other)
            } else {
                (other, self)
            };
            for i in 0..longer.coefficients.len() {
                if (i < shorter.coefficients.len()
                    && shorter.coefficients[i] != longer.coefficients[i])
                    || (i >= shorter.coefficients.len() && longer.coefficients[i] != T::zero())
                {
                    return false;
                }
            }
            return true;
        }
        self.coefficients == other.coefficients
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
