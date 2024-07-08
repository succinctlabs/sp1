pub mod edwards;
pub mod scalar_mul;
pub mod uint;
pub mod utils;
pub mod weierstrass;

use std::fmt::{Debug, Display, Formatter, Result};
use std::ops::{Add, Neg};
use typenum::Unsigned;

use num::BigUint;
use serde::{de::DeserializeOwned, Serialize};

use crate::air::WORD_SIZE;
use crate::operations::field::params::{FieldParameters, NumWords};

pub const NUM_WORDS_FIELD_ELEMENT: usize = 8;
pub const NUM_BYTES_FIELD_ELEMENT: usize = NUM_WORDS_FIELD_ELEMENT * WORD_SIZE;
pub const COMPRESSED_POINT_BYTES: usize = 32;

/// Number of words needed to represent a point on an elliptic curve. This is twice the number of
/// words needed to represent a field element as a point consists of the x and y coordinates.
pub const NUM_WORDS_EC_POINT: usize = 2 * NUM_WORDS_FIELD_ELEMENT;

#[derive(Debug, PartialEq, Eq)]
pub enum CurveType {
    Secp256k1,
    Bn254,
    Ed25519,
    Bls12381,
}

impl Display for CurveType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            CurveType::Secp256k1 => write!(f, "Secp256k1"),
            CurveType::Bn254 => write!(f, "Bn254"),
            CurveType::Ed25519 => write!(f, "Ed25519"),
            CurveType::Bls12381 => write!(f, "Bls12381"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffinePoint<E> {
    pub x: BigUint,
    pub y: BigUint,
    _marker: std::marker::PhantomData<E>,
}

impl<E: EllipticCurveParameters> AffinePoint<E> {
    #[allow(dead_code)]
    pub const fn new(x: BigUint, y: BigUint) -> Self {
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

    pub fn to_words_le(&self) -> Vec<u32> {
        let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;
        let num_bytes = num_words * 4;
        let half_words = num_words / 2;

        let mut x_bytes = self.x.to_bytes_le();
        x_bytes.resize(num_bytes / 2, 0u8);
        let mut y_bytes = self.y.to_bytes_le();
        y_bytes.resize(num_bytes / 2, 0u8);

        let mut words = vec![0u32; num_words];

        for i in 0..half_words {
            let x = u32::from_le_bytes([
                x_bytes[4 * i],
                x_bytes[4 * i + 1],
                x_bytes[4 * i + 2],
                x_bytes[4 * i + 3],
            ]);
            let y = u32::from_le_bytes([
                y_bytes[4 * i],
                y_bytes[4 * i + 1],
                y_bytes[4 * i + 2],
                y_bytes[4 * i + 3],
            ]);

            words[i] = x;
            words[half_words + i] = y;
        }

        words
    }
}

pub trait EllipticCurveParameters:
    Debug + Send + Sync + Copy + Serialize + DeserializeOwned + 'static
{
    type BaseField: FieldParameters + NumWords;

    const CURVE_TYPE: CurveType;
}

/// An interface for elliptic curve groups.
pub trait EllipticCurve: EllipticCurveParameters {
    const NB_LIMBS: usize = Self::BaseField::NB_LIMBS;

    const NB_WITNESS_LIMBS: usize = Self::BaseField::NB_WITNESS_LIMBS;
    /// Adds two different points on the curve.
    ///
    /// Warning: This method assumes that the two points are different.
    fn ec_add(p: &AffinePoint<Self>, q: &AffinePoint<Self>) -> AffinePoint<Self>;

    /// Doubles a point on the curve.
    fn ec_double(p: &AffinePoint<Self>) -> AffinePoint<Self>;

    /// Returns the generator of the curve group for a curve/subgroup of prime order.
    fn ec_generator() -> AffinePoint<Self>;

    /// Returns the neutral element of the curve group, if this element is affine (such as in the
    /// case of the Edwards curve group). Otherwise, returns `None`.
    fn ec_neutral() -> Option<AffinePoint<Self>>;

    /// Returns the negative of a point on the curve.
    fn ec_neg(p: &AffinePoint<Self>) -> AffinePoint<Self>;

    /// Returns the number of bits needed to represent a scalar in the group.
    fn nb_scalar_bits() -> usize {
        Self::BaseField::NB_LIMBS * Self::BaseField::NB_BITS_PER_LIMB
    }
}

impl<E: EllipticCurve> Add<&AffinePoint<E>> for &AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn add(self, other: &AffinePoint<E>) -> AffinePoint<E> {
        E::ec_add(self, other)
    }
}

impl<E: EllipticCurve> Add<AffinePoint<E>> for AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn add(self, other: AffinePoint<E>) -> AffinePoint<E> {
        &self + &other
    }
}

impl<E: EllipticCurve> Add<&AffinePoint<E>> for AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn add(self, other: &AffinePoint<E>) -> AffinePoint<E> {
        &self + other
    }
}

impl<E: EllipticCurve> Neg for &AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn neg(self) -> AffinePoint<E> {
        E::ec_neg(self)
    }
}

impl<E: EllipticCurve> Neg for AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn neg(self) -> AffinePoint<E> {
        -&self
    }
}
