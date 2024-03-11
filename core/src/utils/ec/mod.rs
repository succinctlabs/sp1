pub mod edwards;
pub mod field;
pub mod scalar_mul;
pub mod utils;
// pub mod weierstrass;

use field::FieldParameters;
use num::BigUint;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use std::ops::{Add, Neg};

use crate::air::WORD_SIZE;

pub const NUM_WORDS_FIELD_ELEMENT: usize = 8;
pub const NUM_BYTES_FIELD_ELEMENT: usize = NUM_WORDS_FIELD_ELEMENT * WORD_SIZE;
pub const COMPRESSED_POINT_BYTES: usize = 32;

/// Number of words needed to represent a point on an elliptic curve. This is twice the number of
/// words needed to represent a field element as a point consists of the x and y coordinates.
pub const NUM_WORDS_EC_POINT: usize = 2 * NUM_WORDS_FIELD_ELEMENT;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffinePoint<E, const N: usize> {
    pub x: BigUint,
    pub y: BigUint,
    _marker: std::marker::PhantomData<E>,
}

impl<E, const N: usize> AffinePoint<E, N> {
    #[allow(dead_code)]
    pub fn new(x: BigUint, y: BigUint) -> Self {
        Self {
            x,
            y,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn from_words_le(words: &[u32]) -> Self {
        let x_bytes = words[0..words.len() / 2]
            .iter()
            .flat_map(|n| n.to_le_bytes())
            .collect::<Vec<_>>();
        let y_bytes = &words[words.len() / 2..]
            .iter()
            .flat_map(|n| n.to_le_bytes())
            .collect::<Vec<_>>();
        let x = BigUint::from_bytes_le(x_bytes.as_slice());
        let y = BigUint::from_bytes_le(y_bytes.as_slice());
        Self {
            x,
            y,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn to_words_le(&self) -> [u32; 16] {
        let mut x_bytes = self.x.to_bytes_le();
        x_bytes.resize(N, 0u8);
        let mut y_bytes = self.y.to_bytes_le();
        y_bytes.resize(N, 0u8);

        let mut words = [0u32; 16];
        for i in 0..8 {
            words[i] = u32::from_le_bytes([
                x_bytes[i * 4],
                x_bytes[i * 4 + 1],
                x_bytes[i * 4 + 2],
                x_bytes[i * 4 + 3],
            ]);
            words[i + 8] = u32::from_le_bytes([
                y_bytes[i * 4],
                y_bytes[i * 4 + 1],
                y_bytes[i * 4 + 2],
                y_bytes[i * 4 + 3],
            ]);
        }
        words
    }
}

pub trait EllipticCurveParameters<const N: usize>:
    Debug + Send + Sync + Copy + Serialize + DeserializeOwned + 'static
{
    type BaseField: FieldParameters<N>;
}

/// An interface for elliptic curve groups.
pub trait EllipticCurve<const N: usize>: EllipticCurveParameters<N> {
    /// Adds two different points on the curve.
    ///
    /// Warning: This method assumes that the two points are different.
    fn ec_add(p: &AffinePoint<Self, N>, q: &AffinePoint<Self, N>) -> AffinePoint<Self, N>;

    /// Doubles a point on the curve.
    fn ec_double(p: &AffinePoint<Self, N>) -> AffinePoint<Self, N>;

    /// Returns the generator of the curve group for a curve/subgroup of prime order.
    fn ec_generator() -> AffinePoint<Self, N>;

    /// Returns the neutral element of the curve group, if this element is affine (such as in the
    /// case of the Edwards curve group). Otherwise, returns `None`.
    fn ec_neutral() -> Option<AffinePoint<Self, N>>;

    /// Returns the negative of a point on the curve.
    fn ec_neg(p: &AffinePoint<Self, N>) -> AffinePoint<Self, N>;

    /// Returns the number of bits needed to represent a scalar in the group.
    fn nb_scalar_bits() -> usize {
        Self::BaseField::NB_LIMBS * Self::BaseField::NB_BITS_PER_LIMB
    }
}

impl<E: EllipticCurve<N>, const N: usize> Add<&AffinePoint<E, N>> for &AffinePoint<E, N> {
    type Output = AffinePoint<E, N>;

    fn add(self, other: &AffinePoint<E, N>) -> AffinePoint<E, N> {
        E::ec_add(self, other)
    }
}

impl<E: EllipticCurve<N>, const N: usize> Add<AffinePoint<E, N>> for AffinePoint<E, N> {
    type Output = AffinePoint<E, N>;

    fn add(self, other: AffinePoint<E, N>) -> AffinePoint<E, N> {
        &self + &other
    }
}

impl<E: EllipticCurve<N>, const N: usize> Add<&AffinePoint<E, N>> for AffinePoint<E, N> {
    type Output = AffinePoint<E, N>;

    fn add(self, other: &AffinePoint<E, N>) -> AffinePoint<E, N> {
        &self + other
    }
}

impl<E: EllipticCurve<N>, const N: usize> Neg for &AffinePoint<E, N> {
    type Output = AffinePoint<E, N>;

    fn neg(self) -> AffinePoint<E, N> {
        E::ec_neg(self)
    }
}

impl<E: EllipticCurve<N>, const N: usize> Neg for AffinePoint<E, N> {
    type Output = AffinePoint<E, N>;

    fn neg(self) -> AffinePoint<E, N> {
        -&self
    }
}
