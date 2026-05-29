pub mod edwards;
pub mod params;
// pub mod polynomial;
pub mod scalar_mul;
pub mod uint256;
pub mod utils;
pub mod weierstrass;

pub mod curve25519_dalek {
    /// In "Edwards y" / "Ed25519" format, the curve point \\((x,y)\\) is
    /// determined by the \\(y\\)-coordinate and the sign of \\(x\\).
    ///
    /// The first 255 bits of a `CompressedEdwardsY` represent the
    /// \\(y\\)-coordinate.  The high bit of the 32nd byte gives the sign of \\(x\\).
    ///
    /// Note: This is taken from the `curve25519-dalek` crate.
    #[derive(Copy, Clone, Eq, PartialEq, Hash)]
    pub struct CompressedEdwardsY(pub [u8; 32]);

    impl CompressedEdwardsY {
        /// View this `CompressedEdwardsY` as a byte array.
        pub fn as_bytes(&self) -> &[u8; 32] {
            &self.0
        }

        /// Consume this `CompressedEdwardsY` and return the underlying byte array.
        pub fn to_bytes(&self) -> [u8; 32] {
            self.0
        }

        /// Construct a `CompressedEdwardsY` from a slice of bytes.
        ///
        /// # Errors
        ///
        /// Returns [`TryFromSliceError`] if the input `bytes` slice does not have
        /// a length of 32.
        pub fn from_slice(
            bytes: &[u8],
        ) -> Result<CompressedEdwardsY, core::array::TryFromSliceError> {
            bytes.try_into().map(CompressedEdwardsY)
        }
    }
}

pub use k256;
pub use p256;

use params::{FieldParameters, NumWords};
use sp1_primitives::consts::WORD_BYTE_SIZE;
use std::{
    fmt::{Debug, Display, Formatter, Result},
    ops::{Add, Neg},
};
use typenum::Unsigned;

pub use num::{BigUint, Integer, One, Zero};
use serde::{de::DeserializeOwned, Serialize};

pub const NUM_WORDS_FIELD_ELEMENT: usize = 4;
pub const NUM_BYTES_FIELD_ELEMENT: usize = NUM_WORDS_FIELD_ELEMENT * WORD_BYTE_SIZE;
pub const COMPRESSED_POINT_BYTES: usize = 32;

/// Number of words needed to represent a point on an elliptic curve. This is twice the number of
/// words needed to represent a field element as a point consists of the x and y coordinates.
pub const NUM_WORDS_EC_POINT: usize = 2 * NUM_WORDS_FIELD_ELEMENT;

#[derive(Debug, PartialEq, Eq)]
pub enum CurveType {
    Secp256k1,
    Secp256r1,
    Bn254,
    Ed25519,
    Bls12381,
}

impl Display for CurveType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            CurveType::Secp256k1 => write!(f, "Secp256k1"),
            CurveType::Secp256r1 => write!(f, "Secp256r1"),
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
        Self { x, y, _marker: std::marker::PhantomData }
    }

    pub fn to_sec1_uncompressed(&self) -> Vec<u8> {
        fn le_to_fixed_be<E: EllipticCurveParameters>(n: &BigUint) -> Vec<u8> {
            let le = n.to_bytes_le();

            // todo: make this const
            let mut buf = vec![0_u8; E::BaseField::NB_BYTES];
            buf[..le.len()].copy_from_slice(&le);
            buf.reverse();
            buf
        }

        let mut out = vec![0u8; E::BaseField::NB_BYTES * 2 + 1];
        out[0] = 0x04;
        out[1..E::BaseField::NB_BYTES + 1].copy_from_slice(&le_to_fixed_be::<E>(&self.x));
        out[E::BaseField::NB_BYTES + 1..].copy_from_slice(&le_to_fixed_be::<E>(&self.y));
        out
    }

    pub fn from_words_le<'a>(words: impl IntoIterator<Item = &'a u64>) -> Self {
        let words = words.into_iter().collect::<Vec<_>>();

        let x_bytes =
            words[0..words.len() / 2].iter().flat_map(|n| n.to_le_bytes()).collect::<Vec<_>>();

        let y_bytes =
            &words[words.len() / 2..].iter().flat_map(|n| n.to_le_bytes()).collect::<Vec<_>>();

        let x = BigUint::from_bytes_le(x_bytes.as_slice());
        let y = BigUint::from_bytes_le(y_bytes.as_slice());
        Self { x, y, _marker: std::marker::PhantomData }
    }

    pub fn to_words_le(&self) -> Vec<u64> {
        let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;
        let num_bytes = num_words * 8;
        let half_words = num_words / 2;

        let mut x_bytes = self.x.to_bytes_le();
        x_bytes.resize(num_bytes / 2, 0u8);
        let mut y_bytes = self.y.to_bytes_le();
        y_bytes.resize(num_bytes / 2, 0u8);

        let mut words = vec![0u64; num_words];

        for i in 0..half_words {
            let x = u64::from_le_bytes([
                x_bytes[8 * i],
                x_bytes[8 * i + 1],
                x_bytes[8 * i + 2],
                x_bytes[8 * i + 3],
                x_bytes[8 * i + 4],
                x_bytes[8 * i + 5],
                x_bytes[8 * i + 6],
                x_bytes[8 * i + 7],
            ]);
            let y = u64::from_le_bytes([
                y_bytes[8 * i],
                y_bytes[8 * i + 1],
                y_bytes[8 * i + 2],
                y_bytes[8 * i + 3],
                y_bytes[8 * i + 4],
                y_bytes[8 * i + 5],
                y_bytes[8 * i + 6],
                y_bytes[8 * i + 7],
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
